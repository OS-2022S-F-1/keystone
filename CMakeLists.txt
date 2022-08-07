cmake_minimum_required(VERSION 3.5)
project(keystone C)
include(ProcessorCount)
set(CMAKE_VERBOSE_MAKEFILE ON)

###############################################################################
## MACROS
###############################################################################

# add patch macro
macro(add_patch submodule patch working_directory patch_list)
  add_custom_command(OUTPUT ${patch}.applied
    WORKING_DIRECTORY ${working_directory}
    COMMAND patch --forward -p0 < ${patchdir}/${submodule}/${patch} || true
    COMMAND touch ${CMAKE_BINARY_DIR}/${patch}.applied
    COMMENT "Applying ${patch}")
  list(APPEND ${patch_list} ${patch}.applied)
endmacro()

macro(mkdir name dir)
  add_custom_command(OUTPUT ${dir}/.exists
    COMMAND mkdir -p ${dir}
    COMMAND touch ${dir}/.exists
  )
  set(${name} ${dir})
  set(${name}_exists ${dir}/.exists)
endmacro()


###############################################################################
## CONFIGURATION/VARIABLES
###############################################################################

if(NOT DEFINED ENV{RISCV})
	message(FATAL_ERROR "set RISCV environment variable. \n Try `cd ${CMAKE_SOURCE_DIR}; source source.sh`")
endif()

set(USE_RUST_SM FALSE CACHE BOOL "Use Rust version of the security monitor.")
set(SM_CONFIGURE_ARGS --enable-opt=2 CACHE STRING "Security Monitor configure script arguments")
set(SM_PLATFORM "generic" CACHE STRING "Board name for SM hardware-specific functions")
set(platform ${SM_PLATFORM})
message(STATUS "platform=${platform}")

set(LINUX_SIFIVE FALSE CACHE BOOL "Build linux for sifive")
set(sifive ${LINUX_SIFIVE})
message(STATUS "sifive=${sifive}")

if((CMAKE_BUILD_TYPE MATCHES "Debug") OR (CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo"))
  message(STATUS "Using debug symbols")
  set(CFLAGS -g)
endif()

set(RISCV32 OFF CACHE BOOL "Build in 32-bit mode")
if(RISCV32)
  message(STATUS "riscv32")
  set(BITS 32)
  set(ABI ilp32d)
else()
  message(STATUS "riscv64")
  set(BITS 64)
  set(ABI lp64d)
endif()

set(ISA rv${BITS}imafdc)
set(confdir ${CMAKE_SOURCE_DIR}/conf)
set(patchdir ${CMAKE_SOURCE_DIR}/patches)
set(cross_compile riscv${BITS}-unknown-linux-gnu-)

set(bootrom_srcdir ${CMAKE_SOURCE_DIR}/bootrom)
set(bootrom_wrkdir ${CMAKE_BINARY_DIR}/bootrom.build)
#set(qemu_wrkdir ${CMAKE_SOURCE_DIR}/qemu)
#set(qemu_srcdir ${CMAKE_SOURCE_DIR}/qemu)
set(sm_srcdir ${CMAKE_SOURCE_DIR}/sm)
mkdir(sm_wrkdir ${CMAKE_BINARY_DIR}/sm.build)
#set(buildroot_srcdir ${CMAKE_SOURCE_DIR}/buildroot)
#set(buildroot_wrkdir ${CMAKE_BINARY_DIR}/buildroot.build)
#set(buildroot_config ${confdir}/qemu_riscv${BITS}_virt_defconfig)
set(overlay_dir ${CMAKE_BINARY_DIR}/overlay)
set(overlay_root ${overlay_dir}/root)

if(firesim)
  message(STATUS "Using Linux defconfig: ${linux_defconfig}")
	set(initramfs true)
elseif(sifive)
  message(STATUS "SiFive Unleashed configs and patches. Forcing initramfs=y")
	set(linux_defconfig ${confdir}/linux64-sifive-defconfig)
  message(STATUS "Using Linux defconfig: ${linux_defconfig}")
	set(initramfs true)
endif()

if(NOT DEFINED linux_defconfig)
	set(linux_defconfig ${confdir}/linux${BITS}-defconfig)
endif()

#set(linux_srcdir ${CMAKE_SOURCE_DIR}/linux)
#mkdir(linux_wrkdir ${CMAKE_BINARY_DIR}/linux.build)
#set(linux_symvers ${linux_wrkdir}/Modules.symvers)
#set(linux_image ${linux_wrkdir}/arch/riscv/boot/Image)
set(driver_srcdir ${CMAKE_SOURCE_DIR}/linux-keystone-driver)
set(driver_wrkdir ${CMAKE_BINARY_DIR}/linux-keystone-driver.build)
set(fw_elf ${sm_wrkdir}/platform/${platform}/firmware/fw_payload.elf)
set(fw_bin ${sm_wrkdir}/platform/${platform}/firmware/fw_payload.bin)
set(final_image ${CMAKE_BINARY_DIR}/firmware.bin)
set(initramfs_sysroot ${CMAKE_BINARY_DIR}/initramfs-sysroot)


###############################################################################
## COMPONENT: security monitor (sm)
###############################################################################

add_patch("sm/opensbi" "opensbi-firmware-secure-boot.patch" ${sm_srcdir}/opensbi sm_patches)
add_custom_target("sm" DEPENDS ${sm_wrkdir_exists} ${sm_patches} WORKING_DIRECTORY ${sm_wrkdir}
  COMMAND $(MAKE) -C ${sm_srcdir}/opensbi O=${sm_wrkdir} PLATFORM_DIR=${sm_srcdir}/plat/${platform}
    CROSS_COMPILE=riscv${BITS}-unknown-elf-
        FW_PAYLOAD_PATH=/mnt/d/Personal/Study/2022_Spring/OS/keystone/zCore/target/riscv64/release/zcore.bin
        FW_PAYLOAD=y PLATFORM_RISCV_XLEN=${BITS}
    PLATFORM_RISCV_ISA=${ISA} PLATFORM_RISCV_ABI=${ABI}
  COMMENT "Building sm"
)

###############################################################################
## PATCH
###############################################################################
add_custom_target("patch" DEPENDS ${qemu_patches} ${linux_patches} ${sm_patches})

