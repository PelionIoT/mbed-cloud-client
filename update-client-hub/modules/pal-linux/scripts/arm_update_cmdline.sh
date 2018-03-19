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

# default values
LOCATION=0
OFFSET=0
SIZE=0

# parse command line arguments
while [ $# -gt 1 ]
do
key="$1"
case $key in
    -h|--header)
    HEADER="$2"
    shift # past argument=value
    ;;
    -f|--firmware)
    FIRMWARE="$2"
    shift # past argument=value
    ;;
    -l|--location)
    LOCATION="$2"
    shift # past argument=value
    ;;
    -o|--offset)
    OFFSET="$2"
    shift # past argument=value
    ;;
    -s|--size)
    SIZE="$2"
    shift # past argument=value
    ;;
    *)
            # unknown option
    ;;
esac
shift
done

# echo "header:   ${HEADER}"
# echo "firmware: ${FIRMWARE}"
# echo "location: ${LOCATION}"
# echo "offset:   ${OFFSET}"
# echo "size:     ${SIZE}"
