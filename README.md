# Rust-Keystone: A Rust-based Secure Enclave Framework

## Introduction
Rust-Keystone attempts to build a secure framework in Rust language. We follow the design in [Keystone](https://github.com/keystone-enclave/keystone). Due to the time limitation, some parts of the framework are not replaced to a Rust version(Secure Manager and Enclave Runtime).
Instead of running in Linux, our framework is running in [zCore](https://github.com/rcore-os/zCore), which is also implemented in Rust. In the future, we will make the whole system in Rust.

## Toolchain
The system is built in riscv64-unknown-elf. Before running the following step, first install riscv64-unknown-elf toolchain and add the binary to PATH.

## Build Secure Component
- Build keystone-sdk in ./zCore/keystone-sdk and export KEYSTONE_SDK_DIR, which will be used in building sercuity monitor and runtime;
- Build keytone-runtime in ./zCore/keystone-runtime;
- Build security monitor with cmake. If the cmake directory is ./build, run the following command:
```shell
cd builid
make
make sm
```


## Build image and core
After building the essential components, we are ready to build the final part.
```shell
make image && make core
```
The user program in ./zCore/linux_user/[app | host] will be installed in /home/bin.

## Run the framework in QEMU
The environment setting is set in Makefile. Run the following command to enter zCore:
```shell
make run
```