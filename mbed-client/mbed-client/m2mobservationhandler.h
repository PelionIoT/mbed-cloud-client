/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
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
#ifndef M2M_OBSERVATION_HANDLER_H
#define M2M_OBSERVATION_HANDLER_H

// Needed for M2MBase::Operation
#include "m2mbase.h"
#include "mbed-client/coap_response.h"
//FORWARD DECLARATION
class M2MResourceInstance;

/** \file m2mobservationhandler.h \brief header for M2MObservationHandler */

/** An interface for handling observation
 *  callbacks from different objects.
 */
class M2MObservationHandler
{
  public:

    /**
     * \brief The observation callback to be sent to the
     * server due to a change in a parameter under observation.
     * \param object The observed object whose information needs to be sent.
     * \param obs_number The observation number.
     * \param changed_instance_ids A list of changed object instance IDs.
     * \param send_object Indicates whether the whole object will be sent or not.
     *
     * \return True if the message was send, False if there is already ongoing notification.
     */
    virtual bool observation_to_be_sent(M2MBase *object,
                                        uint16_t obs_number,
                                        const m2m::Vector<uint16_t> &changed_instance_ids,
                                        bool send_object = false) = 0;

    /**
     * \brief A callback for removing an NSDL resource from the data structures.
     * \param The M2MBase derived observed object whose information
     * needs to be removed.
     */
    virtual void resource_to_be_deleted(M2MBase *base) = 0;

    /**
     * \brief A callback indicating that the value of the resource object is updated by server.
     * \param base The object whose value is updated.
     * \param object_name The name of the updated resource, default is empty.
     */
    virtual void value_updated(M2MBase *base) = 0;

    /**
     * \brief A callback for removing an object from the list.
     * \param object The M2MObject to be removed.
     */
    virtual void remove_object(M2MBase *object) = 0;

#ifndef DISABLE_DELAYED_RESPONSE
    /**
     * \brief Sends a delayed post response to the server with 'COAP_MSG_CODE_RESPONSE_CHANGED' response code.
     * \param base The resource sending the response.
     * \param code Response code to be sent.
     */
    virtual void send_delayed_response(M2MBase *base, sn_coap_msg_code_e code = COAP_MSG_CODE_RESPONSE_CHANGED) = 0;
#endif

#ifdef ENABLE_ASYNC_REST_RESPONSE
    /**
     * \brief Sends async response to the server for the given operation with the given response code.
     * \param base The resource sending the response.
     * \param payload Payload for the resource.
     * \param payload_len Length of the payload.
     * \param token Token for the incoming CoAP request.
     * \param token_len Token length for the incoming CoAP request.
     * \param code The response code for the operation, for example: COAP_MSG_CODE_RESPONSE_CHANGED.
     */
    virtual void send_asynchronous_response(M2MBase *base,
                                            const uint8_t *payload,
                                            size_t payload_len,
                                            const uint8_t* token,
                                            const uint8_t token_len,
                                            coap_response_code_e code) = 0;
#endif
};


#endif // M2M_OBSERVATION_HANDLER_H
