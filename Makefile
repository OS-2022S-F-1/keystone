user_img := zCore/zCore/riscv64.img
sm_wrkdir := build/sm.build
#bootrom_wrkdir := build/bootrom.build
core_build_path := zCore/target/riscv64/release
#bootrom_img := ${bootrom_wrkdir}/bootrom.bin
fw_jump_img := ${sm_wrkdir}/platform/generic/firmware/fw_jump.bin
#fw_payload_elf := ${sm_wrkdir}/platform/generic/firmware/fw_payload.elf
#fw_payload_img := ${sm_wrkdir}/platform/generic/firmware/fw_payload.bin
kernel_img := zCore/target/riscv64/release/zcore.bin
qemu_disk := $(core_build_path)/disk.qcow2

export USER_IMG=$(realpath $(user_img))

qemu_opts := -smp 1 \
	-machine virt \
	-bios $(fw_jump_img) \
	-m 1024M \
	-no-reboot \
	-serial mon:stdio \
	-serial file:/tmp/serial.out \
	-kernel $(kernel_img) \
	-initrd $(USER_IMG) \
	-append "LOG=debug" \
	-display none -nographic

image:
	@cd zCore && make riscv-image

core:
	@cd zCore/zCore && make build MODE=release LINUX=1

sm: CMakeLists.txt
	@cd build && cmake .. && make bootrom && make sm

run:
	qemu-system-riscv64 $(qemu_opts)

debugrun:
	qemu-system-riscv64 $(qemu_opts) -s -S &
	@sleep 1
	riscv64-unknown-elf-gdb  $(kernel_elf) -x gdbinit -ex "target remote :1234"
