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
#ifndef M2MREPORTHANDLER_H
#define M2MREPORTHANDLER_H

// Support for std args
#include <stdint.h>
#include "mbed-client/m2mconfig.h"
#include "mbed-client/m2mbase.h"
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
#include "mbed-client/m2mtimerobserver.h"
#endif
#include "mbed-client/m2mresourceinstance.h"
#include "mbed-client/m2mvector.h"
#include "mbed-client/m2mtimer.h"

//FORWARD DECLARATION
class M2MReportObserver;
class M2MTimer;
class M2MResourceInstance;

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
typedef union current_value_u {
    float   float_value;
    int64_t int_value;
} current_value_t;

typedef union last_value_u {
    float   float_value;
    int64_t int_value;
} last_value_t;

typedef union high_step_u {
    float   float_value;
    int64_t int_value;
} high_step_t;

typedef union low_step_u {
    float   float_value;
    int64_t int_value;
} low_step_t;
#endif
/**
 *  @brief M2MReportHandler.
 *  This class is handles all the observation related operations.
 */
class M2MReportHandler
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
        : public M2MTimerObserver
#endif
{
private:
    // Prevents the use of assignment operator by accident.
    M2MReportHandler& operator=( const M2MReportHandler& /*other*/ );

public:

    M2MReportHandler(M2MReportObserver &observer, M2MBase::DataType type);

public:

    /**
     * Enum defining which write attributes are set.
    */
    enum {
        Cancel = 1,
        Pmin = 2,
        Pmax = 4,
        Lt = 8,
        Gt = 16,
        St = 32
    };

    /**
     * Destructor
     */
    virtual ~M2MReportHandler();

    /**
     * @brief Sets that object is under observation.
     * @param Value for the observation.
     * @param handler, Handler object for sending
     * observation callbacks.
     */
    void set_under_observation(bool observed);

    /**
     * @brief Sets the float value of the given resource.
     * @param value, Value of the observed resource.
     */
    void set_value_float(float value);

    /**
     * @brief Sets the integer value of the given resource.
     * @param value, Value of the observed resource.
     */
    void set_value_int(int64_t value);

    /**
     * @brief Sets notification trigger.
     * @param obj_instance_id, Object instance id that has changed
     */
    void set_notification_trigger(uint16_t obj_instance_id = 0);

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    /**
     * @brief Parses the received query for notification
     * attribute.
     * @param query Query to be parsed for attributes.
     * @param type Type of the Base Object.
     * @param resource_type Type of the Resource.
     * @return true if required attributes are present else false.
     */
    bool parse_notification_attribute(const char *query,
                                              M2MBase::BaseType type,
                                              M2MResourceInstance::ResourceType resource_type = M2MResourceInstance::OPAQUE);
#endif

    /**
    * @brief Set back to default values.
    */
    void set_default_values();

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    /**
     * @brief Return write attribute flags.
     */
    uint8_t attribute_flags() const;
#endif

    /**
     * \brief Sets the observation token value.
     * \param token A pointer to the token of the resource.
     * \param length The length of the token pointer.
     */
    void set_observation_token(const uint8_t *token, const uint8_t length);

    /**
     * \brief Provides a copy of the observation token of the object.
     * \param value[OUT] A pointer to the value of the token.
     * \param value_length[OUT] The length of the token pointer.
     */
    void get_observation_token(uint8_t *token, uint8_t &token_length) const;

    /**
     * \brief Returns the observation number.
     * \return The observation number of the object.
     */
    uint16_t observation_number() const;

    /**
     * \brief Adds the observation level for the object.
     * \param observation_level The level of observation.
     */
    void add_observation_level(M2MBase::Observation obs_level);

    /**
     * \brief Removes the observation level for the object.
     * \param observation_level The level of observation.
     */
    void remove_observation_level(M2MBase::Observation obs_level);

    /**
     * \brief Returns the observation level of the object.
     * \return The observation level of the object.
     */
    M2MBase::Observation observation_level() const;

    /**
     * @brief Returns whether this resource is under observation or not.
     * @return True if the resource is under observation, else false,
     */
    bool is_under_observation() const;

    /**
     * @brief Schedule a report, if the pmin is exceeded
     * report immediately, otherwise store the state to be
     * reported once the time fires.
     *
     * @param in_queue If the message is queued message then it must be send even if
     * current and last values are the same.
     */
    void schedule_report(bool in_queue = false);

    /**
     * @brief Set flag that new notification needs to be send.
     *
     * @param to_queue If True then notification is marked to be send
     */
    void set_notification_in_queue(bool to_queue);

    /**
     * @brief Returns whether notification needs to be send or not.
     *
     * @return Is notification sending needed or not.
     */
    bool notification_in_queue() const;

    /**
     * @brief Set flag that new notification needs to be send.
     *
     * @param to_queue If True then notification is marked to be send
     */
    void set_notification_send_in_progress(bool progress);

    /**
     * @brief Returns whether notification send is in progress or not.
     *
     * @return Is notification sending ongoing or not.
     */
    bool notification_send_in_progress() const;

    /**
     * @brief Sets whether notification will be sent using blockwise or not.
     *
     * @param blockwise_notify If True then notification is sent using blockwise.
     */
    void set_blockwise_notify(bool blockwise_notify);

    /**
     * @brief Returns whether notification is sent using blockwise or not.
     *
     * @return Is notification sent using blockwise.
     */
    bool blockwise_notify() const;

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
protected : // from M2MTimerObserver

    virtual void timer_expired(M2MTimerObserver::Type type =
                               M2MTimerObserver::Notdefined);
#endif

private:

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    bool set_notification_attribute(const char* option,
            M2MBase::BaseType type,
            M2MResourceInstance::ResourceType resource_type);
#endif

    /**
    * @brief Reports a sample that satisfies the reporting criteria.
    *
    * @param in_queue If the message is queued message then it must be send even
    * current and last values are the same.
    */
    void report(bool in_queue = false);

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    /**
    * @brief Manage timers for pmin and pmax.
    */
    void handle_timers();

    /**
    * @brief Check whether notification params can be accepted.
    */
    bool check_attribute_validity() const;

    /**
    * @brief Stop pmin & pmax timers.
    */
    void stop_timers();

    /**
     * @brief Check if current value match threshold values.
     * @return True if notify can be send otherwise false.
     */
    bool check_threshold_values() const;

    /**
     * @brief Check whether current value matches with GT & LT.
     * @return True if current value match with GT or LT values.
     */
    bool check_gt_lt_params() const;
#endif

    /**
     * \brief Allocate size amount of memory, copy size bytes into it
     * \param source The source data to copy, may not be NULL.
     * \param size The size of memory to be reserved.
    */
    static uint8_t* alloc_copy(const uint8_t* source, uint32_t size);

    /**
     * \brief New value is ready to be sent.
    */
    void send_value();

private:
    M2MReportObserver           &_observer;
    bool                        _is_under_observation : 1;
    M2MBase::Observation        _observation_level : 3;
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    uint8_t                     _attribute_state;
#endif
    unsigned                    _token_length : 8;
    M2MBase::DataType           _resource_type : 3;
    bool                        _notify : 1;
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    bool                        _pmin_exceeded : 1;
    bool                        _pmax_exceeded : 1;
#endif
    unsigned                    _observation_number : 24;
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    M2MTimer                    _pmin_timer;
    M2MTimer                    _pmax_timer;    
    int32_t                     _pmax;
    int32_t                     _pmin;
    high_step_t                 _high_step;
    low_step_t                  _low_step;
    last_value_t                _last_value;
    float                       _gt;
    float                       _lt;
    float                       _st;
#endif
    uint8_t                     *_token;
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    current_value_t             _current_value;
#endif
    m2m::Vector<uint16_t>       _changed_instance_ids;
    bool                        _notification_send_in_progress : 1;
    bool                        _notification_in_queue : 1;
    bool                        _blockwise_notify : 1;
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    bool                        _pmin_quiet_period : 1;
#endif
friend class Test_M2MReportHandler;

};

#endif // M2MREPORTHANDLER_H
