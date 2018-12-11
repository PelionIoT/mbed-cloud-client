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
#ifndef __PAL_SOCKET_TEST_ADDRESS_H__
#define __PAL_SOCKET_TEST_ADDRESS_H__

// test server contact details, typically overridden on CI and/or local development setup

// address of a server which is running the KeepAliveServer/KeepAliveServer.py
#ifndef PAL_TEST_KEEPALIVE_SERVER_ADDRESS
#define PAL_TEST_KEEPALIVE_SERVER_ADDRESS "127.0.0.1"
#endif

// listening port of the server
#ifndef PAL_TEST_SERVER_KEEPALIVE_PORT
#define PAL_TEST_SERVER_KEEPALIVE_PORT 5533
#endif

// magic number of keepalive messages (or TCP ACKs..) which serves as pivot on deciding if
// the keepalive did work or not.
#ifndef PAL_TEST_KEEPALIVE_NUM_OF_ACK
#define PAL_TEST_KEEPALIVE_NUM_OF_ACK 4
#endif

#endif // !__PAL_SOCKET_TEST_ADDRESS_H__
