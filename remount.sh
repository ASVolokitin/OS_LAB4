sudo umount /mnt/vt
sudo rmmod vtfs
sudo make
sudo insmod vtfs.ko
sudo mount -t vtfs "REMOUNT" /mnt/vt