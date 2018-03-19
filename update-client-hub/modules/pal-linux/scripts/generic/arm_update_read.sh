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
. ../../../arm_update_cmdline.sh

# copy fragment from stored firmware to temporary file
VALUE=$(dd if=/tmp/extended/firmware_${LOCATION}.bin of=/tmp/firmware_fragment.bin count=$SIZE ibs=1 skip=$OFFSET 2>/dev/null)

# indicate to Update client where to read fragment from
echo "/tmp/firmware_fragment.bin"

exit $VALUE
