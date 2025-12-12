#include "vtfs.h"

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mnt_idmapping.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "vtfs_backend.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sashka");
MODULE_DESCRIPTION("A simple FS kernel module");

struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
    .mkdir = vtfs_mkdir,
    .rmdir = vtfs_rmdir,
    .link = vtfs_link,
};

struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

struct file_operations vtfs_file_ops = {
    .open = vtfs_open,
    .read = vtfs_read,
    .write = vtfs_write,
};

static int __init vtfs_init(void) {
  int ret;

  ret = vtfs_storage_init();
  if (ret) {
    LOG("vtfs_storage_init failed: %d\n", ret);
    return ret;
  }

  LOG("VTFS joined the kernel\n");
  ret = register_filesystem(&vtfs_fs_type);
  if (ret) {
    LOG("Failed to register filesystem: %d\n", ret);
    vtfs_storage_shutdown();
  }
  return ret;
}

static void __exit vtfs_exit(void) {
  unregister_filesystem(&vtfs_fs_type);
  vtfs_storage_shutdown();
  LOG("VTFS left the kernel\n");
}

struct file_system_type vtfs_fs_type = {
    .name = "vtfs", .mount = vtfs_mount, .kill_sb = vtfs_kill_sb
};

struct dentry* vtfs_mount(
    struct file_system_type* fs_type, int flags, const char* token, void* data
) {
  struct dentry* ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
  if (ret == NULL) {
    printk(KERN_ERR "Can't mount file system");
  } else {
    LOG("Mounted successfully\n");
  }
  return ret;
}

int vtfs_fill_super(struct super_block* sb, void* data, int silent) {
  struct vtfs_node_meta meta;
  int err = vtfs_storage_get_root(&meta);
  if (err)
    return err;

  struct inode* inode = vtfs_get_inode(sb, NULL, meta.mode, meta.ino);
  if (!inode)
    return -ENOMEM;

  inode->i_op = &vtfs_inode_ops;
  inode->i_fop = &vtfs_dir_ops;
  inode->i_size = meta.size;
  set_nlink(inode, meta.nlink);

  sb->s_root = d_make_root(inode);
  if (sb->s_root == NULL) {
    iput(inode);
    return -ENOMEM;
  }

  printk(KERN_INFO "return 0\n");
  return 0;
}

struct inode* vtfs_get_inode(
    struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino
) {
  struct inode* inode = new_inode(sb);
  if (inode != NULL) {
    inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
    inode->i_mode = mode;
    inode->i_op = &vtfs_inode_ops;

    if (S_ISDIR(mode))
      inode->i_fop = &vtfs_dir_ops;
    else if (S_ISREG(mode)) {
      inode->i_fop = &vtfs_file_ops;
    }

    inode->i_mode = mode | 0777;
  }
  inode->i_ino = i_ino;
  return inode;
}

void vtfs_kill_sb(struct super_block* sb) {
  printk(KERN_INFO "vtfs super block is destroyed. Unmount successfully.\n");
}

struct dentry* vtfs_lookup(
    struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag
) {
  const char* name = child_dentry->d_name.name;
  struct vtfs_node_meta meta;
  int err = vtfs_storage_lookup(parent_inode->i_ino, name, &meta);

  if (err)
    return NULL;

  struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, meta.mode, meta.ino);
  if (!inode)
    return ERR_PTR(-ENOMEM);

  inode->i_size = meta.size;
  set_nlink(inode, meta.nlink);
  d_add(child_dentry, inode);
  return NULL;
}

int vtfs_iterate(struct file* filp, struct dir_context* ctx) {
  struct dentry* dentry = filp->f_path.dentry;
  struct inode* inode = dentry->d_inode;
  vtfs_ino_t ino = inode->i_ino;
  unsigned long pos = filp->f_pos;

  if (pos == 0) {
    if (!dir_emit(ctx, ".", 1, ino, DT_DIR))
      return 0;
    ctx->pos = ++pos;
    filp->f_pos = pos;
  }

  if (pos == 1) {
    ino_t parent_ino = dentry->d_parent->d_inode->i_ino;
    if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR))
      return 0;
    ctx->pos = ++pos;
    filp->f_pos = pos;
  }

  if (pos >= 2) {
    unsigned long off = pos - 2;
    while (1) {
      struct vtfs_dirent ent;
      int err = vtfs_storage_iterate_dir(ino, &off, &ent);
      if (err)
        break;

      unsigned char dtype = (ent.type == VTFS_NODE_DIR) ? DT_DIR : DT_REG;

      if (!dir_emit(ctx, ent.name, strlen(ent.name), ent.ino, dtype))
        break;

      ctx->pos = filp->f_pos = off + 2;
    }
  }

  return 0;
}

int vtfs_open(struct inode* inode, struct file* filp) {
  LOG("vtfs_open called for inode %lu\n", inode->i_ino);
  return 0;
}

int vtfs_create(
    struct mnt_idmap* idmap,
    struct inode* parent_inode,
    struct dentry* child_dentry,
    umode_t mode,
    bool b
) {
  const char* name = child_dentry->d_name.name;
  struct vtfs_node_meta meta;
  int err;

  err = vtfs_storage_create_file(parent_inode->i_ino, name, mode, &meta);
  if (err)
    return err;

  struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, meta.mode, meta.ino);
  if (!inode)
    return -ENOMEM;

  inode->i_size = meta.size;
  set_nlink(inode, meta.nlink);
  d_add(child_dentry, inode);
  return 0;
}

struct dentry* vtfs_mkdir(
    struct mnt_idmap* idmap, struct inode* parent_inode, struct dentry* child_dentry, umode_t mode
) {
  const char* name = child_dentry->d_name.name;
  struct vtfs_node_meta meta;
  int err;

  err = vtfs_storage_mkdir(parent_inode->i_ino, name, mode, &meta);
  if (err)
    return ERR_PTR(err);

  struct inode* inode = vtfs_get_inode(parent_inode->i_sb, parent_inode, meta.mode, meta.ino);
  if (!inode)
    return ERR_PTR(-ENOMEM);

  inode->i_size = meta.size;
  set_nlink(inode, meta.nlink);
  d_add(child_dentry, inode);
  inc_nlink(parent_inode);
  return NULL;
}

int vtfs_unlink(struct inode* parent_inode, struct dentry* child_dentry) {
  const char* name = child_dentry->d_name.name;
  return vtfs_storage_unlink(parent_inode->i_ino, name);
}

int vtfs_rmdir(struct inode* parent_inode, struct dentry* child_dentry) {
  const char* name = child_dentry->d_name.name;
  return vtfs_storage_rmdir(parent_inode->i_ino, name);
}

ssize_t vtfs_read(struct file* filp, char __user* buffer, size_t len, loff_t* offset) {
  if (!len)
    return 0;

  char* kbuf = kmalloc(len, GFP_KERNEL);
  if (!kbuf)
    return -ENOMEM;

  ssize_t copied = vtfs_storage_read_file(filp->f_inode->i_ino, *offset, len, kbuf);
  if (copied < 0) {
    kfree(kbuf);
    return copied;
  }

  if (copy_to_user(buffer, kbuf, copied)) {
    kfree(kbuf);
    return -EFAULT;
  }

  *offset += copied;
  kfree(kbuf);
  return copied;
}

ssize_t vtfs_write(struct file* filp, const char __user* buffer, size_t len, loff_t* offset) {
  if (!len)
    return 0;

  if (filp->f_flags & O_APPEND)
    *offset = filp->f_inode->i_size;

  char* kbuf = memdup_user(buffer, len);
  if (IS_ERR(kbuf))
    return PTR_ERR(kbuf);

  loff_t new_size;
  ssize_t written = vtfs_storage_write_file(filp->f_inode->i_ino, *offset, kbuf, len, &new_size);
  kfree(kbuf);

  if (written < 0)
    return written;

  *offset += written;
  filp->f_inode->i_size = new_size;
  return written;
}

int vtfs_link(struct dentry* old_dentry, struct inode* parent_inode, struct dentry* new_dentry) {
  struct inode* old_inode = d_inode(old_dentry);
  struct vtfs_node_meta meta;
  int err =
      vtfs_storage_link(parent_inode->i_ino, new_dentry->d_name.name, old_inode->i_ino, &meta);
  if (err)
    return err;

  ihold(old_inode);
  d_instantiate(new_dentry, old_inode);
  old_inode->i_size = meta.size;
  set_nlink(old_inode, meta.nlink);
  return 0;
}

module_init(vtfs_init);
module_exit(vtfs_exit);