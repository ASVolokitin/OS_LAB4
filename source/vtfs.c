#include "vtfs.h"

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mnt_idmapping.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sashka");
MODULE_DESCRIPTION("A simple FS kernel module");

static int mask = 0;

struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
};

struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

struct file_operations vtfs_file_ops = {
    .open = vtfs_open,
};

static int __init vtfs_init(void) {
  LOG("VTFS joined the kernel\n");
  int ret = register_filesystem(&vtfs_fs_type);
  if (ret) {
    LOG("Failed to register filesystem: %d\n", ret);
  }
  return ret;
}

static void __exit vtfs_exit(void) {
  unregister_filesystem(&vtfs_fs_type);
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
  struct inode* inode = vtfs_get_inode(sb, NULL, S_IFDIR, 1000);

  if (!inode)
    return -ENOMEM;

  inode->i_op = &vtfs_inode_ops;
  inode->i_fop = &vtfs_dir_ops;

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
      inode->i_size = 0;
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
  ino_t root = parent_inode->i_ino;
  const char* name = child_dentry->d_name.name;
  if (root == 1000 && !strcmp(name, "test.txt")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFREG, 1001);
    d_add(child_dentry, inode);
  } else if (root == 1000 && !strcmp(name, "new_file.txt")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFREG, 1002);
    d_add(child_dentry, inode);
  } else if (root == 1000 && !strcmp(name, "dir")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFDIR, 2000);
    d_add(child_dentry, inode);
  }
  return NULL;
}

int vtfs_iterate(struct file* filp, struct dir_context* ctx) {
  struct dentry* dentry = filp->f_path.dentry;
  struct inode* inode = dentry->d_inode;
  unsigned long offset = filp->f_pos;
  int ino = inode->i_ino;

  if (ino != 1000)
    return 0;

  if (offset == 0) {
    if (!dir_emit(ctx, ".", 1, ino, DT_DIR))
      return 0;
    ctx->pos++;
    filp->f_pos = ctx->pos;
    return 0;
  }

  if (offset == 1) {
    if (!dir_emit(ctx, "..", 2, dentry->d_parent->d_inode->i_ino, DT_DIR))
      return 0;
    ctx->pos++;
    filp->f_pos = ctx->pos;
    return 0;
  }

  if (offset == 2) {
    if (!dir_emit(ctx, "test.txt", 8, 1001, DT_REG))
      return 0;
    ctx->pos++;
    filp->f_pos = ctx->pos;
    return 0;
  }

  if (offset == 3) {
    if (!dir_emit(ctx, "new_file.txt", 12, 1002, DT_REG))
      return 0;
    ctx->pos++;
    filp->f_pos = ctx->pos;
    return 0;
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
  LOG("vtfs_create called! parent_inode=%lu, name=%s\n",
      parent_inode->i_ino,
      child_dentry->d_name.name);
  ino_t root = parent_inode->i_ino;
  const char* name = child_dentry->d_name.name;

  if (root == 1000 && !strcmp(name, "test.txt")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFREG | S_IRWXUGO, 1001);
    d_add(child_dentry, inode);
    mask |= 1;

  } else if (root == 1000 && !strcmp(name, "new_file.txt")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFREG | S_IRWXUGO, 1002);
    d_add(child_dentry, inode);
    mask |= 2;
  }
  return 0;
}

int vtfs_unlink(struct inode* parent_inode, struct dentry* child_dentry) {
  const char* name = child_dentry->d_name.name;
  ino_t root = parent_inode->i_ino;
  if (root == 1000 && !strcmp(name, "test.txt")) {
    mask &= ~1;
  } else if (root == 1000 && !strcmp(name, "new_file.txt")) {
    mask &= ~2;
  }
  return 0;
}

module_init(vtfs_init);
module_exit(vtfs_exit);