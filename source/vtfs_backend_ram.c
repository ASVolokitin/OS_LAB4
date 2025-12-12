#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "vtfs.h"
#include "vtfs_backend.h"

#define VTFS_ROOT_INO 1

struct vtfs_ram_node {
  struct vtfs_node_meta meta;
  char name[NAME_MAX + 1];
  char* data;
  size_t capacity;
  struct vtfs_ram_node* next;
};

static struct vtfs_ram_node* vtfs_nodes_head = NULL;
static vtfs_ino_t vtfs_next_ino = VTFS_ROOT_INO + 1;

static struct vtfs_ram_node* vtfs_find_node_by_ino(vtfs_ino_t ino) {
  struct vtfs_ram_node* cur = vtfs_nodes_head;

  while (cur) {
    if (cur->meta.ino == ino)
      return cur;
    cur = cur->next;
  }

  return NULL;
}

static struct vtfs_ram_node* vtfs_find_child(vtfs_ino_t parent, const char* name) {
  struct vtfs_ram_node* cur = vtfs_nodes_head;

  while (cur) {
    if (cur->meta.parent_ino == parent && !strcmp(cur->name, name))
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

static void vtfs_free_all_nodes(void) {
  struct vtfs_ram_node* cur = vtfs_nodes_head;
  while (cur) {
    struct vtfs_ram_node* next = cur->next;
    kfree(cur);
    cur = next;
  }
  vtfs_nodes_head = NULL;
  vtfs_next_ino = VTFS_ROOT_INO + 1;
}

int vtfs_storage_init(void) {
  vtfs_free_all_nodes();

  struct vtfs_ram_node* root = vtfs_alloc_node();
  if (!root)
    return -ENOMEM;

  root->meta.ino = VTFS_ROOT_INO;
  root->meta.parent_ino = 0;
  root->meta.type = VTFS_NODE_DIR;
  root->meta.mode = S_IFDIR | 0777;
  root->meta.size = 0;
  root->name[0] = '\0';

  LOG("vtfs_storage_init: root created (ino=%lu)\n", (unsigned long)root->meta.ino);
  return 0;
}

void vtfs_storage_shutdown(void) {
  vtfs_free_all_nodes();
  LOG("vtfs_storage_shutdown: all nodes freed\n");
}

int vtfs_storage_get_root(struct vtfs_node_meta* out) {
  struct vtfs_ram_node* root = vtfs_find_node_by_ino(VTFS_ROOT_INO);
  if (!root)
    return -ENOENT;

  *out = root->meta;
  return 0;
}

int vtfs_storage_lookup(vtfs_ino_t parent, const char* name, struct vtfs_node_meta* out) {
  struct vtfs_ram_node* node = vtfs_find_child(parent, name);
  if (!node)
    return -ENOENT;

  *out = node->meta;
  return 0;
}

int vtfs_storage_iterate_dir(vtfs_ino_t dir_ino, unsigned long* offset, struct vtfs_dirent* out) {
  unsigned long count = 0;
  struct vtfs_ram_node* cur = vtfs_nodes_head;

  while (cur) {
    if (cur->meta.parent_ino == dir_ino) {
      if (count == *offset) {
        strncpy(out->name, cur->name, NAME_MAX);
        out->name[NAME_MAX] = '\0';
        out->ino = cur->meta.ino;
        out->type = cur->meta.type;

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
  if (vtfs_find_child(parent, name))
    return -EEXIST;

  struct vtfs_ram_node* parent_node = vtfs_find_node_by_ino(parent);
  if (!parent_node || parent_node->meta.type != VTFS_NODE_DIR)
    return -ENOTDIR;

  struct vtfs_ram_node* node = vtfs_alloc_node();
  if (!node)
    return -ENOMEM;

  node->meta.ino = vtfs_next_ino++;
  node->meta.parent_ino = parent;
  node->meta.type = VTFS_NODE_FILE;
  node->meta.mode = S_IFREG | (mode & 0777);
  node->meta.size = 0;

  strncpy(node->name, name, NAME_MAX);
  node->name[NAME_MAX] = '\0';

  *out = node->meta;
  return 0;
}

int vtfs_storage_mkdir(
    vtfs_ino_t parent, const char* name, umode_t mode, struct vtfs_node_meta* out
) {
  if (vtfs_find_child(parent, name))
    return -EEXIST;

  struct vtfs_ram_node* parent_node = vtfs_find_node_by_ino(parent);
  if (!parent_node || parent_node->meta.type != VTFS_NODE_DIR)
    return -ENOTDIR;

  struct vtfs_ram_node* node = vtfs_alloc_node();
  if (!node)
    return -ENOMEM;

  node->meta.ino = vtfs_next_ino++;
  node->meta.parent_ino = parent;
  node->meta.type = VTFS_NODE_DIR;
  node->meta.mode = S_IFDIR | (mode & 0777);
  node->meta.size = 0;

  strncpy(node->name, name, NAME_MAX);
  node->name[NAME_MAX] = '\0';

  *out = node->meta;
  return 0;
}

int vtfs_storage_unlink(vtfs_ino_t parent, const char* name) {
  struct vtfs_ram_node* prev = NULL;
  struct vtfs_ram_node* cur = vtfs_nodes_head;

  while (cur) {
    if (cur->meta.parent_ino == parent && !strcmp(cur->name, name)) {
      if (cur->meta.type != VTFS_NODE_FILE)
        return -EPERM;

      if (prev)
        prev->next = cur->next;
      else
        vtfs_nodes_head = cur->next;

      kfree(cur);
      return 0;
    }
    prev = cur;
    cur = cur->next;
  }

  return -ENOENT;
}

int vtfs_storage_rmdir(vtfs_ino_t parent, const char* name) {
  struct vtfs_ram_node* prev = NULL;
  struct vtfs_ram_node* cur = vtfs_nodes_head;

  while (cur) {
    if (cur->meta.parent_ino == parent && !strcmp(cur->name, name)) {
      if (cur->meta.type != VTFS_NODE_DIR)
        return -ENOTDIR;

      struct vtfs_ram_node* scan = vtfs_nodes_head;
      while (scan) {
        if (scan->meta.parent_ino == cur->meta.ino)
          return -ENOTEMPTY;
        scan = scan->next;
      }

      if (prev)
        prev->next = cur->next;
      else
        vtfs_nodes_head = cur->next;

      kfree(cur);
      return 0;
    }
    prev = cur;
    cur = cur->next;
  }

  return -ENOENT;
}

static int vtfs_reserve_data(struct vtfs_ram_node* node, size_t needed) {
  size_t new_cap = max_t(size_t, 2 * node->capacity, needed);
  char* new_data = krealloc(node->data, new_cap, GFP_KERNEL);
  if (!new_data)
    return -ENOMEM;

  if (new_cap > node->capacity)
    memset(new_data + node->capacity, 0, new_cap - node->capacity);

  node->data = new_data;
  node->capacity = new_cap;

  return 0;
}

ssize_t vtfs_storage_read_file(vtfs_ino_t ino, loff_t offset, size_t len, char* dst) {
  struct vtfs_ram_node* node = vtfs_find_node_by_ino(ino);
  if (!node)
    return -ENOENT;

  if (node->meta.type != VTFS_NODE_FILE)
    return -EPERM;

  if (offset >= node->meta.size)
    return 0;

  size_t to_copy = min_t(size_t, len, node->meta.size - offset);
  memcpy(dst, node->data + offset, to_copy);

  return to_copy;
}

ssize_t vtfs_storage_write_file(
    vtfs_ino_t ino, loff_t offset, const char* src, size_t len, loff_t* new_size
) {
  struct vtfs_ram_node* node = vtfs_find_node_by_ino(ino);
  if (!node)
    return -ENOENT;

  if (node->meta.type != VTFS_NODE_FILE)
    return -EPERM;

  size_t end = offset + len;
  if (end > node->capacity) {
    int err = vtfs_reserve_data(node, end);
    if (err)
      return err;
  }

  if (offset > node->meta.size)
    memset(node->data + node->meta.size, 0, offset - node->meta.size);

  memcpy(node->data + offset, src, len);
  node->meta.size = max_t(loff_t, node->meta.size, end);

  if (new_size)
    *new_size = node->meta.size;

  return len;
}