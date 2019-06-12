#!/bin/sh
# ----------------------------------------------------------------------------
# Copyright 2016-2017 ARM Ltd.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

set -x
# Write a partition image file to a partition and set the boot flags.

# Parse command line
#
# HEADER
# FIRMWARE
# LOCATION
# OFFSET
# SIZE
#
. /opt/arm/arm_update_cmdline.sh

# Return the number of the partition with the given label (in $1)
# Exit with error if the partition can't be found
getpart() {
    res=$(readlink -f "/dev/disk/by-label/$1")
    if [ "$(echo "${res}" | cut -c1-13)x"  = "/dev/mmcblk0px" ]; then
        echo "$(echo $res | cut -d'p' -f2)"
    fi
}

# Detect root partitions
root1=$(getpart "rootfs1")
if [ "${root1}"x = "x" ]; then
    echo "Unable to find partition with label 'rootfs1'"
    exit 9
fi
root2=$(getpart "rootfs2")
if [ "${root2}"x = "x" ]; then
    echo "Unable to find partition with label 'rootfs2'"
    exit 9
fi
ROOTS="$root1 $root2"

# Flag partition
FLAGS=$(getpart "bootflags")
if [ "${FLAGS}"x = "x" ]; then
    echo "Unable to find partition with label 'bootflags'"
    exit 9
fi

# Find the partition that is currently mounted to /
activePartition=$(lsblk -nro NAME,MOUNTPOINT | grep -e ".* /$" | cut -d ' ' -f1)
# Find the disk that contains the current root
activeDisk=$(lsblk -nro pkname "/dev/${activePartition}")
# Get the format of the partition name
partitionPrefix=$(echo ${activePartition} | sed -e "s|^\([a-z0-9]*[a-z]\)[0-9]$|\1|")

nextPartition=""
nextPartitionLabel=""
nextRoot=""
# Find the other root partition by listing both root partitions and filtering out the active partition
for pNum in ${ROOTS} ; do
    if [ "${partitionPrefix}${pNum}" != "$activePartition" ]; then
        nextPartition="${partitionPrefix}${pNum}"
        nextRoot=${pNum}
        break
    fi
done

if [ -z "${nextPartition}" ]; then
    exit 1
fi

# Make sure that nextPartition exists in the disk
if ! lsblk -nr "/dev/${nextPartition}" > /dev/null ; then
    exit 2
fi

# Make sure the next partition isn't mounted.
umount "/dev/${nextPartition}" > /dev/null
# Set next partition label based on whether it is first or second root
if [ "${nextRoot}" = "5" ]; then
    nextPartitionLabel="rootfs1"
fi
if [ "${nextRoot}" = "6" ]; then
    nextPartitionLabel="rootfs2"
fi


# Create the file system on the next partition
# if ! mkfs -t ext4 -L ${nextPartitionLabel} -F "/dev/${nextPartition}"; then
#    echo "mkfs failed on the new root partition"
#    exit 3
#fi
# Mount the next partition
if ! mount "/dev/${nextPartition}" /mnt/root; then
    echo "Unable to mount the new root partition"
    exit 4
fi

# empty the next partition so we can temporarily make an .tar
# -copy of active partition files there
if ! rm -rf /mnt/root/*; then
    echo "Unable to remove files from new partition!"
    exit 5
fi

# Try to create an original binary out of the current root fs contents
# exclude run/lock and var/lib because yocto build produces content there but
# tmpfs is mounted in device into those
# tar --exclude='run/lock' --exclude='var/lib' --exclude='var/volatile' --exclude='lost+found' --sort=name --format=ustar --mtime="2019-01-01 00:00Z" --owner=0 --group=0 --numeric-owner --one-file-system -cvpf /mnt/root/original_image.bin *;then

cd /
# Temp fix to avoid difference to original image:
chmod 755 /sys /proc
if ! tar --exclude='run/*' --exclude='var/lib' --exclude='var/volatile' --exclude='lost+found' --exclude='dev/*' --exclude='proc/*' --exclude='sys/*' --exclude='boot/*' --sort=name --format=ustar --mtime="2019-01-01 00:00Z" --owner=0 --group=0 --numeric-owner --one-file-system -cvpf /mnt/root/original_image.bin *;then
    echo "prepare original tar failed for the delta!"
    exit 6
fi
chmod 555 /sys /proc

sync

exit 0

