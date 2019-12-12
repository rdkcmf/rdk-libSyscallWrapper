#SETTING TOOLCHAIN AND RAMDISK PATH
export PLATFORM_SDK=${RDK_DIR}/sdk/toolchain/arm-linux-gnueabihf
export RDK_TOOLCHAIN_PATH=$RDK_PROJECT_ROOT_PATH/sdk/toolchain/arm-linux-gnueabihf
export ROOTFS=${RDK_DIR}/sdk/fsroot/ramdisk
export RDK_FSROOT_PATH=$RDK_PROJECT_ROOT_PATH/sdk/fsroot/ramdisk
#SETTING CROSS COMPILER
export CROSS_COMPILE=${PLATFORM_SDK}/bin/arm-linux-gnueabihf-
export CC=${CROSS_COMPILE}gcc
export CXX=${CROSS_COMPILE}g++
export DEFAULT_HOST=arm-linux
export PKG_CONFIG_PATH="$RDK_PROJECT_ROOT_PATH/opensource/lib/pkgconfig/:$RDK_FSROOT_PATH/img/fs/shadow_root/usr/local/lib/pkgconfig/:$RDK_TOOLCHAIN_PATH/lib/pkgconfig/:$PKG_CONFIG_PATH"
