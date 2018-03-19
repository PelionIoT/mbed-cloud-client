/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

#include "mbed.h"
#include "EthernetInterface.h"

bool dhcpDone = true;
static EthernetInterface* netInterface = NULL;
extern "C" {
    void* palTestGetNetWorkInterfaceContext(void)
    {
        nsapi_error_t status = NSAPI_ERROR_OK;
        if (NULL == netInterface)
        {
            netInterface = new EthernetInterface();
            printf("new interface created\r\n");
            status = netInterface->connect();
            if (NSAPI_ERROR_OK == status)
            {
                printf("interface registered : OK \r\n");
            }
            else //connect failed
            {
                printf("interface registered : FAILED! \r\n");
                delete netInterface;
                netInterface = NULL;
            }
        }
        return netInterface;
    }
}
