bash compile.sh
mkdir /home/jjy/mnt
sudo modprobe nbd
sudo qemu-nbd --connect=/dev/nbd0 /home/jjy/qemu_vms/overlay_0.qcow2
sleep 1
sudo ntfsfix /dev/nbd0p2
sleep 1
sudo mount /dev/nbd0p2 /home/jjy/mnt
sleep 1
cp /home/jjy/targets/kafl.targets/windows_x86_64/bin/fuzzer/vuln_test.exe /home/jjy/mnt/fuzzer.exe
sleep 1
sudo umount /home/jjy/mnt
sudo qemu-nbd --disconnect /dev/nbd0
rmdir /home/jjy/mnt
