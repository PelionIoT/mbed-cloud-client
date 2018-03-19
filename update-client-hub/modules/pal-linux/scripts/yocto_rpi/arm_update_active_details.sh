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

# Parse command line
#
# HEADER
# FIRMWARE
# LOCATION
# OFFSET
# SIZE
#
. /opt/arm/arm_update_cmdline.sh

# header directory
HEADER_DIR=$(dirname ${HEADER})

# header name (not prefix)
HEADER_NAME="header"

# location where the update client will find the header
HEADER_PATH=${HEADER_DIR}"/"${HEADER_NAME}".bin"

# header size
HEADER_SIZE=112

set -x
# Return the number of the partition with the given label (in $1)
# Exit with error if the partition can't be found
getpart() {
    res=`readlink -f /dev/disk/by-label/$1`
    if [[ ${res:0:13}x == "/dev/mmcblk0px" ]]; then
        echo `echo $res | cut -d'p' -f2`
    fi
}

# Flag partition
FLAGS=`getpart "bootflags"`
if [ "${FLAGS}"x == "x" ]; then
    echo "Unable to find partition with label 'bootflags'"
    exit 9
fi

# Find the partition that is currently mounted to /
activePartition=`lsblk -nro NAME,MOUNTPOINT | grep -e ".* /$" | cut -d ' ' -f1`
activePartitionNum=`echo ${activePartition} | grep -Eo '[0-9]+$'`

# Get the format of the partition name
partitionPrefix=`echo ${activePartition} | sed -e "s|^\([a-z0-9]*[a-z]\)[0-9]$|\1|"`

# Make sure flags partition isn't mounted.
umount /dev/${partitionPrefix}${FLAGS} > /dev/null

# mount flags partition
if ! mount /dev/${partitionPrefix}${FLAGS} /mnt/flags ; then
    exit 7
fi

# Boot Flags
if [ "${activePartitionNum}" == "5" ] && [ -e "/mnt/flags/five" ]; then
    cp /mnt/flags/five $HEADER_PATH
    sync
elif [ "${activePartitionNum}" == "6" ] && [ -e "/mnt/flags/six" ]; then
    cp /mnt/flags/six $HEADER_PATH
    sync
else
    echo "Warning: No active firmware header found!"
    exit 9
fi

exit 0
