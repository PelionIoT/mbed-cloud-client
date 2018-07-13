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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef URIQUERYPARSER_H_
#define URIQUERYPARSER_H_


/**
 * @brief Parse query parameter from uri and return size of parameter value and pointer to value within
 *        uri.
 *
 * Example usage:
 * char *value_ptr = NULL;
 * ssize_t value_len = parse_query_parameter_value_from_uri("http://www.myquery.com?someparameter=value", "someparameter", &value_ptr);
 * will result in value_len = 5 and value_ptr = "value"
 *
 * @param uri uri to parse.
 * @param parameter_name, parameter name to parse from query.
 * @param parameter_value[OUT], pointer to parameter value, NULL if parameter does not exist.
 * @return size of parameter value, -1 if parameter does not exist in uri
 */
int parse_query_parameter_value_from_uri(const char *uri, const char *parameter_name, const char **parameter_value);

/**
 * @brief Parse query parameter from query and return size of parameter value and pointer to value within
 *        query.
 *
 * Example usage:
 * char *value_ptr = NULL;
 * ssize_t value_len = parse_query_parameter_value("someparameter=value&param2=second", "param2", &value_ptr);
 * will result in value_len = 6 and value_ptr = "second"
 *
 * @param query query to parse.
 * @param parameter_name, parameter name to parse from query.
 * @param parameter_value[OUT], pointer to parameter value, NULL if parameter does not exist.
 * @return size of parameter value, -1 if parameter does not exist in query
 */
int parse_query_parameter_value_from_query(const char *uri, const char *parameter_name, const char **parameter_value);


#endif /* URIQUERYPARSER_H_ */

#ifdef __cplusplus
}
#endif
