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
if ! mkfs -t ext4 -L ${nextPartitionLabel} -F "/dev/${nextPartition}"; then
    echo "mkfs failed on the new root partition"
    exit 3
fi
# Mount the next partition
if ! mount "/dev/${nextPartition}" /mnt/root; then
    echo "Unable to mount the new root partition"
    exit 4
fi
# Uncompress the image
if ! tar xvjf $FIRMWARE -C /mnt/root; then
    echo "Image copy failed"
    exit 5
fi
umount /mnt/root

if ! mkdir -p /mnt/flags ; then
    exit 6
fi

# Make sure flags partition isn't mounted.
umount "/dev/${partitionPrefix}${FLAGS}" > /dev/null
if ! mount "/dev/${partitionPrefix}${FLAGS}" /mnt/flags ; then
    exit 7
fi

# Boot Flags
if [ "${nextRoot}" = "5" ]; then
    cp $HEADER /mnt/flags/five
    sync
    rm -f /mnt/flags/six
    sync
elif [ "${nextRoot}" = "6" ]; then
    cp $HEADER /mnt/flags/six
    sync
    rm -f /mnt/flags/five
    sync
fi

if ! umount /mnt/flags ; then
    exit 8
fi

exit 0
