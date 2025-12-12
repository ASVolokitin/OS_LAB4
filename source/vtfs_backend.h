#ifndef _VTFS_BACKEND_H
#define _VTFS_BACKEND_H

#include <linux/fs.h>

typedef ino_t vtfs_ino_t;

enum vtfs_node_type {
  VTFS_NODE_DIR,
  VTFS_NODE_FILE,
};

struct vtfs_node_meta {
  vtfs_ino_t ino;
  vtfs_ino_t parent_ino;
  enum vtfs_node_type type;
  umode_t mode;
  loff_t size;
};

struct vtfs_dirent {
  char name[NAME_MAX + 1];
  vtfs_ino_t ino;
  enum vtfs_node_type type;
};

int vtfs_storage_init(void);

void vtfs_storage_shutdown(void);

int vtfs_storage_get_root(struct vtfs_node_meta* out);

int vtfs_storage_lookup(vtfs_ino_t parent, const char* name, struct vtfs_node_meta* out);

int vtfs_storage_iterate_dir(vtfs_ino_t dir_ino, unsigned long* offset, struct vtfs_dirent* out);

int vtfs_storage_create_file(
    vtfs_ino_t parent, const char* name, umode_t mode, struct vtfs_node_meta* out
);

int vtfs_storage_unlink(vtfs_ino_t parent, const char* name);

#endif