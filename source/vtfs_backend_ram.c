#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "vtfs.h"
#include "vtfs_backend.h"

#define VTFS_ROOT_INO 1

struct vtfs_inode_payload {
  struct vtfs_node_meta meta;
  char* data;
  size_t capacity;
  struct vtfs_inode_payload* next;
};

struct vtfs_ram_node {
  vtfs_ino_t parent_ino;
  char name[NAME_MAX + 1];
  struct vtfs_inode_payload* inode;
  struct vtfs_ram_node* next;
};

static struct vtfs_ram_node* vtfs_nodes_head = NULL;
static struct vtfs_inode_payload* vtfs_inodes_head = NULL;
static vtfs_ino_t vtfs_next_ino = VTFS_ROOT_INO + 1;

static struct vtfs_inode_payload* vtfs_find_inode(vtfs_ino_t ino) {
  struct vtfs_inode_payload* cur = vtfs_inodes_head;
  while (cur) {
    if (cur->meta.ino == ino)
      return cur;
    cur = cur->next;
  }
  return NULL;
}

static struct vtfs_ram_node* vtfs_find_dentry(vtfs_ino_t parent, const char* name) {
  struct vtfs_ram_node* cur = vtfs_nodes_head;
  while (cur) {
    if (cur->parent_ino == parent && !strcmp(cur->name, name))
      return cur;
    cur = cur->next;
  }
  return NULL;
}

static struct vtfs_ram_node* vtfs_alloc_node(void) {
  struct vtfs_ram_node* node = kzalloc(sizeof(*node), GFP_KERNEL);
  if (!node)
    return NULL;
  node->next = vtfs_nodes_head;
  vtfs_nodes_head = node;
  return node;
}

static struct vtfs_inode_payload* vtfs_alloc_payload(enum vtfs_node_type type, umode_t mode) {
  struct vtfs_inode_payload* payload = kzalloc(sizeof(*payload), GFP_KERNEL);
  if (!payload)
    return NULL;
  payload->meta.type = type;
  payload->meta.mode = mode;
  payload->meta.size = 0;
  payload->meta.nlink = (type == VTFS_NODE_DIR) ? 2 : 1;
  payload->data = NULL;
  payload->capacity = 0;
  payload->next = vtfs_inodes_head;
  vtfs_inodes_head = payload;
  return payload;
}

static void vtfs_free_payload(struct vtfs_inode_payload* payload) {
  struct vtfs_inode_payload** cur = &vtfs_inodes_head;
  while (*cur) {
    if (*cur == payload) {
      *cur = payload->next;
      kfree(payload->data);
      kfree(payload);
      return;
    }
    cur = &(*cur)->next;
  }
}

static void vtfs_free_all_nodes(void) {
  struct vtfs_ram_node* cur = vtfs_nodes_head;
  while (cur) {
    struct vtfs_ram_node* next = cur->next;
    kfree(cur);
    cur = next;
  }
  vtfs_nodes_head = NULL;

  struct vtfs_inode_payload* ip = vtfs_inodes_head;
  while (ip) {
    struct vtfs_inode_payload* next = ip->next;
    kfree(ip->data);
    kfree(ip);
    ip = next;
  }
  vtfs_inodes_head = NULL;

  vtfs_next_ino = VTFS_ROOT_INO + 1;
}

int vtfs_storage_init(void) {
  vtfs_free_all_nodes();

  struct vtfs_inode_payload* root_inode = vtfs_alloc_payload(VTFS_NODE_DIR, S_IFDIR | 0777);
  if (!root_inode)
    return -ENOMEM;

  root_inode->meta.ino = VTFS_ROOT_INO;
  root_inode->meta.nlink = 2;

  struct vtfs_ram_node* root = vtfs_alloc_node();
  if (!root)
    return -ENOMEM;

  root->parent_ino = VTFS_ROOT_INO;
  root->name[0] = '\0';
  root->inode = root_inode;

  LOG("vtfs_storage_init: root created (ino=%lu)\n", (unsigned long)root_inode->meta.ino);
  return 0;
}

void vtfs_storage_shutdown(void) {
  vtfs_free_all_nodes();
  LOG("vtfs_storage_shutdown: all nodes freed\n");
}

static void vtfs_fill_meta(struct vtfs_node_meta* out, struct vtfs_ram_node* dentry) {
  out->ino = dentry->inode->meta.ino;
  out->parent_ino = dentry->parent_ino;
  out->type = dentry->inode->meta.type;
  out->mode = dentry->inode->meta.mode;
  out->size = dentry->inode->meta.size;
  out->nlink = dentry->inode->meta.nlink;
}

int vtfs_storage_get_root(struct vtfs_node_meta* out) {
  struct vtfs_ram_node* root = vtfs_nodes_head;
  if (!root || root->inode->meta.ino != VTFS_ROOT_INO)
    return -ENOENT;
  vtfs_fill_meta(out, root);
  return 0;
}

int vtfs_storage_lookup(vtfs_ino_t parent, const char* name, struct vtfs_node_meta* out) {
  struct vtfs_ram_node* node = vtfs_find_dentry(parent, name);
  if (!node)
    return -ENOENT;
  vtfs_fill_meta(out, node);
  return 0;
}

int vtfs_storage_iterate_dir(vtfs_ino_t dir_ino, unsigned long* offset, struct vtfs_dirent* out) {
  unsigned long count = 0;
  struct vtfs_ram_node* cur = vtfs_nodes_head;

  while (cur) {
    if (cur->parent_ino == dir_ino && cur->name[0] != '\0') {
      if (count == *offset) {
        strncpy(out->name, cur->name, NAME_MAX);
        out->name[NAME_MAX] = '\0';
        out->ino = cur->inode->meta.ino;
        out->type = cur->inode->meta.type;
        (*offset)++;
        return 0;
      }
      count++;
    }
    cur = cur->next;
  }

  return -ENOENT;
}

int vtfs_storage_create_file(
    vtfs_ino_t parent, const char* name, umode_t mode, struct vtfs_node_meta* out
) {
  if (vtfs_find_dentry(parent, name))
    return -EEXIST;

  struct vtfs_inode_payload* parent_payload = vtfs_find_inode(parent);
  if (!parent_payload || parent_payload->meta.type != VTFS_NODE_DIR)
    return -ENOTDIR;

  struct vtfs_inode_payload* payload = vtfs_alloc_payload(VTFS_NODE_FILE, S_IFREG | (mode & 0777));
  if (!payload)
    return -ENOMEM;

  payload->meta.ino = vtfs_next_ino++;

  struct vtfs_ram_node* node = vtfs_alloc_node();
  if (!node) {
    vtfs_free_payload(payload);
    return -ENOMEM;
  }

  node->parent_ino = parent;
  strncpy(node->name, name, NAME_MAX);
  node->name[NAME_MAX] = '\0';
  node->inode = payload;

  vtfs_fill_meta(out, node);
  return 0;
}

int vtfs_storage_mkdir(
    vtfs_ino_t parent, const char* name, umode_t mode, struct vtfs_node_meta* out
) {
  if (vtfs_find_dentry(parent, name))
    return -EEXIST;

  struct vtfs_inode_payload* parent_payload = vtfs_find_inode(parent);
  if (!parent_payload || parent_payload->meta.type != VTFS_NODE_DIR)
    return -ENOTDIR;

  struct vtfs_inode_payload* payload = vtfs_alloc_payload(VTFS_NODE_DIR, S_IFDIR | (mode & 0777));
  if (!payload)
    return -ENOMEM;

  payload->meta.ino = vtfs_next_ino++;
  payload->meta.nlink = 2;
  parent_payload->meta.nlink++;

  struct vtfs_ram_node* node = vtfs_alloc_node();
  if (!node) {
    vtfs_free_payload(payload);
    parent_payload->meta.nlink--;
    return -ENOMEM;
  }

  node->parent_ino = parent;
  strncpy(node->name, name, NAME_MAX);
  node->name[NAME_MAX] = '\0';
  node->inode = payload;

  vtfs_fill_meta(out, node);
  return 0;
}

int vtfs_storage_unlink(vtfs_ino_t parent, const char* name) {
  struct vtfs_ram_node** cur = &vtfs_nodes_head;

  while (*cur) {
    if ((*cur)->parent_ino == parent && !strcmp((*cur)->name, name)) {
      if ((*cur)->inode->meta.type != VTFS_NODE_FILE)
        return -EPERM;

      struct vtfs_ram_node* victim = *cur;
      *cur = victim->next;

      victim->inode->meta.nlink--;
      if (victim->inode->meta.nlink == 0)
        vtfs_free_payload(victim->inode);

      kfree(victim);
      return 0;
    }
    cur = &(*cur)->next;
  }

  return -ENOENT;
}

int vtfs_storage_rmdir(vtfs_ino_t parent, const char* name) {
  struct vtfs_ram_node** cur = &vtfs_nodes_head;

  while (*cur) {
    if ((*cur)->parent_ino == parent && !strcmp((*cur)->name, name)) {
      if ((*cur)->inode->meta.type != VTFS_NODE_DIR)
        return -ENOTDIR;

      struct vtfs_ram_node* scan = vtfs_nodes_head;
      while (scan) {
        if (scan->parent_ino == (*cur)->inode->meta.ino)
          return -ENOTEMPTY;
        scan = scan->next;
      }

      struct vtfs_ram_node* victim = *cur;
      *cur = victim->next;

      vtfs_ino_t parent_ino = victim->parent_ino;
      struct vtfs_inode_payload* parent_payload = vtfs_find_inode(parent_ino);
      if (parent_payload && parent_payload->meta.nlink > 0)
        parent_payload->meta.nlink--;

      victim->inode->meta.nlink -= 2;
      if (victim->inode->meta.nlink <= 0)
        vtfs_free_payload(victim->inode);

      kfree(victim);
      return 0;
    }
    cur = &(*cur)->next;
  }

  return -ENOENT;
}

int vtfs_storage_link(
    vtfs_ino_t parent, const char* name, vtfs_ino_t target_ino, struct vtfs_node_meta* out
) {
  if (vtfs_find_dentry(parent, name))
    return -EEXIST;

  struct vtfs_inode_payload* parent_payload = vtfs_find_inode(parent);
  if (!parent_payload || parent_payload->meta.type != VTFS_NODE_DIR)
    return -ENOTDIR;

  struct vtfs_inode_payload* target = vtfs_find_inode(target_ino);
  if (!target)
    return -ENOENT;
  if (target->meta.type != VTFS_NODE_FILE)
    return -EPERM;

  struct vtfs_ram_node* node = vtfs_alloc_node();
  if (!node)
    return -ENOMEM;

  node->parent_ino = parent;
  strncpy(node->name, name, NAME_MAX);
  node->name[NAME_MAX] = '\0';
  node->inode = target;

  target->meta.nlink++;

  vtfs_fill_meta(out, node);
  return 0;
}

static int vtfs_reserve_data(struct vtfs_inode_payload* inode, size_t needed) {
  size_t new_cap = max_t(size_t, 2 * inode->capacity, needed);
  char* new_data = krealloc(inode->data, new_cap, GFP_KERNEL);
  if (!new_data)
    return -ENOMEM;

  if (new_cap > inode->capacity)
    memset(new_data + inode->capacity, 0, new_cap - inode->capacity);

  inode->data = new_data;
  inode->capacity = new_cap;

  return 0;
}

ssize_t vtfs_storage_read_file(vtfs_ino_t ino, loff_t offset, size_t len, char* dst) {
  struct vtfs_inode_payload* inode = vtfs_find_inode(ino);
  if (!inode)
    return -ENOENT;

  if (inode->meta.type != VTFS_NODE_FILE)
    return -EISDIR;

  if (offset >= inode->meta.size)
    return 0;

  size_t to_copy = min_t(size_t, len, inode->meta.size - offset);
  memcpy(dst, inode->data + offset, to_copy);

  return to_copy;
}

ssize_t vtfs_storage_write_file(
    vtfs_ino_t ino, loff_t offset, const char* src, size_t len, loff_t* new_size
) {
  struct vtfs_inode_payload* inode = vtfs_find_inode(ino);
  if (!inode)
    return -ENOENT;

  if (inode->meta.type != VTFS_NODE_FILE)
    return -EISDIR;

  size_t end = offset + len;
  if (end > inode->capacity) {
    int err = vtfs_reserve_data(inode, end);
    if (err)
      return err;
  }

  if (offset > inode->meta.size)
    memset(inode->data + inode->meta.size, 0, offset - inode->meta.size);

  memcpy(inode->data + offset, src, len);
  inode->meta.size = max_t(loff_t, inode->meta.size, end);

  if (new_size)
    *new_size = inode->meta.size;

  return len;
}