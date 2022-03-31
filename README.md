# kAFL/Nyx Target Components

Example code for targeting different kernels and firmware in kAFL/Nyx.

# Fuzzing with Nyx

## Requirements

IntelPT capable processor

## Install Nyx kernel

As per kAFL install the KVM-Nyx host kernel.
Note upon installation and booting, you may need to hit `advanced boot options` or similar to load the kafl kernel instead of your normal linux kernel.

## Install kAFL

Build and install kAFL as per the README (using kafl/install.sh)

## Build kafl.qemu

Clone kafl.qemu repo (ensure its kafl_stable branch) and compile by running `./compile_qemu_nyx.sh static` or similar.

## Running the example Windows target

The example windows target is a driver included in windows_x86_64\src\vuln_driver, you can compile and install this driver onto your target.
Your target must eventually be a QEMU qcow2 image, but I recommend starting with a HyperV (vhdx/vhd) or VMWare (vmdk) target you can run on your host and perform setup on this target (install the Driver, install your fuzzer harness in the target (windows_x86_64\src\fuzzer\vuln_test.c)), you will also need to set the target driver to start on boot (sc create vuln_driver binPath= c:\tmp\vuln_driver.sys type= kernel start= auto), then set your vuln_test.exe harness to auto-start afterwards (sc create vuln_test binPath= c:\tmp\vuln_test.exe start= delayed-auto). Once completed, convert your vhdx/vhd/vmdk to a qcow2 image.

Once converted, you can create the overlay image for it ("qemu-img create -f qcow2 -b windows.qcow2 overlay_0.qcow2).

Now you can fuzz the target by going into kAFL, running `make env` as documented on kAFL's readme, and running `python3 kafl_fuzz.py -w ../output_fuzz --image ../disks/overlay_0.qcow2 -m 3000 --radamsa-path=../../Source/radamsa/bin/radamsa --qemu-path ~/Source/kafl.qemu/x86_64-softmmu/qemu-system-x86_64 --purge --seed-dir=../inputs --append ""`

You may need to modify kafl.qemu/kafl/kafl_fuzzer/worker/qemu.py to not have the `-append` line when launching QEMU this way.

Nyx will launch the qcow2 and run it until the handshake and snapshot hypercalls are encountered, then it will automatically enter fuzz-mode and you should see it fuzzing as per below 

![kafl_nyx](https://user-images.githubusercontent.com/16039802/160758127-6d195e9a-b08c-4317-aeb1-2f356f44ff52.png)
