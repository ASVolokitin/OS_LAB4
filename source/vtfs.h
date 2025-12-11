#ifndef _VTFS_H
#define _VTFS_H

#include <linux/fs.h>

#define MODULE_NAME "vtfs"
#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

extern struct file_system_type vtfs_fs_type;
extern struct inode_operations vtfs_inode_ops;
extern struct file_operations vtfs_dir_ops;

struct dentry* vtfs_lookup(
    struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag
);

int vtfs_iterate(struct file* filp, struct dir_context* ctx);

struct dentry* vtfs_mount(
    struct file_system_type* fs_type, int flags, const char* token, void* data
);

int vtfs_fill_super(struct super_block* sb, void* data, int silent);

void vtfs_kill_sb(struct super_block* sb);

struct inode* vtfs_get_inode(
    struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino
);

#endif