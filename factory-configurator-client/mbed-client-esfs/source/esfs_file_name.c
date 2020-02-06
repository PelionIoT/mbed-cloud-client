/*
* Copyright (c) 2017 ARM Limited. All rights reserved.
* SPDX-License-Identifier: Apache-2.0
* Licensed under the Apache License, Version 2.0 (the License); you may
* not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an AS IS BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "pal.h"
#include <string.h>
#include "esfs.h"


static char IntToBase64Char(uint8_t intVal)
{
    const char* base64Digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#_";
    return base64Digits[intVal & 0x3F];
}
esfs_result_e esfs_EncodeBase64(const void* buffer, uint32_t bufferSize, char* string, uint32_t stringSize)
{
    uint32_t bitOffset = 0;

    const uint8_t* readPtr = (const uint8_t*)buffer;
    const uint8_t* bufferEnd = (const uint8_t*)buffer + bufferSize;

    char* writePtr = string;
    char* stringEnd = string + stringSize - 1;

    if ((NULL == string) || (NULL == buffer) || (stringSize == 0))
        return ESFS_INVALID_PARAMETER;

    stringSize--;
    while(readPtr < bufferEnd && writePtr < stringEnd)
    {
        uint8_t tempVal = 0;
        switch (bitOffset)
        {
            case 0:
                *writePtr++ = IntToBase64Char(*readPtr >> 2);                 // take upper 6 bits
                break;
            case 6:
                tempVal = (uint8_t)(*readPtr++ << 4);
                if (readPtr < bufferEnd)
                    tempVal |= *readPtr >> 4;
                *writePtr++ = IntToBase64Char(tempVal);
                break;
            case 4:
                tempVal = (uint8_t)(*readPtr++ << 2);
                if (readPtr < bufferEnd)
                    tempVal |= *readPtr >> 6;
                *writePtr++ = IntToBase64Char(tempVal);
                break;
            case 2:
                *writePtr++ = IntToBase64Char(*readPtr++);
                break;
            default:
                return ESFS_INTERNAL_ERROR; // we should never reach this code.
        }
        bitOffset = (bitOffset + 6) & 0x7;
    }
    while (bitOffset > 0 && writePtr < stringEnd)
    {
        *writePtr++ = '!';
        bitOffset = (bitOffset + 6) & 0x7;
    }
    *writePtr = 0;

    if ((readPtr < bufferEnd) || (bitOffset != 0))
        return (ESFS_BUFFER_TOO_SMALL);

    return(ESFS_SUCCESS);
}

/* size_of_file_name should should include the null at the end of the string. In our case 9*/
esfs_result_e esfs_get_name_from_blob(const uint8_t *blob, uint32_t blob_length,char *file_name, uint32_t size_of_file_name)
{
unsigned char output[32] = {0};
    palStatus_t pal_result;
    esfs_result_e esfs_result;
    pal_result = pal_sha256(blob, blob_length, output);
    if (PAL_SUCCESS != pal_result)
        return ESFS_INTERNAL_ERROR;
    esfs_result = esfs_EncodeBase64(output, (size_of_file_name - 1)*6/8, file_name, size_of_file_name);
    return (esfs_result);


}


