// async_uring.c
#define _GNU_SOURCE
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
  int fd = open("/mnt/vt/test", O_RDWR | O_CREAT, 0644);
  char buf[64];
  memset(buf, 0, sizeof(buf));
  strcpy(buf, "Hello from io_uring!\n");
  struct io_uring ring;

  io_uring_queue_init(8, &ring, 0);

  struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
  io_uring_prep_write(sqe, fd, buf, strlen(buf), 0);
  io_uring_submit(&ring);

  printf("Write submitted.\n");

  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_read(sqe, fd, buf, 64, 0);
  io_uring_submit(&ring);

  printf("Read submitted.\n");

  struct io_uring_cqe* cqe;
  for (int i = 0; i < 2; i++) {
    io_uring_wait_cqe(&ring, &cqe);
    printf("CQE %d: res=%d\n", i, cqe->res);
    io_uring_cqe_seen(&ring, cqe);
  }

  close(fd);
  io_uring_queue_exit(&ring);
  return 0;
}