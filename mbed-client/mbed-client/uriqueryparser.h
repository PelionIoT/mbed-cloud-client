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

/** \file uriqueryparser.h
 *  \brief Helper functions for parsing URI query parameters.
 */

/**
 * @brief Parse a query parameter from URI and return the size of the parameter value and a pointer to the value within
 *        the URI.
 *
 * **Example usage:**
 * @code{.cpp}
 * char *value_ptr = NULL;
 * ssize_t value_len = parse_query_parameter_value_from_uri("http://www.myquery.com?someparameter=value", "someparameter", &value_ptr);
 * @endcode
 * will result in value_len = 5 and value_ptr = "value"
 *
 * @param uri The URI to parse.
 * @param parameter_name The parameter name to parse from query.
 * @param[out] parameter_value A pointer to the parameter value, NULL if parameter does not exist.
 * @return The size of the parameter value, -1 if parameter does not exist in the URI.
 */
int parse_query_parameter_value_from_uri(const char *uri, const char *parameter_name, const char **parameter_value);

/**
 * @brief Parse a query parameter from a query and return the size of the parameter value and a pointer to the value within
 *        the query.
 *
 * **Example usage:**
 * @code{.cpp}
 * char *value_ptr = NULL;
 * ssize_t value_len = parse_query_parameter_value("someparameter=value&param2=second", "param2", &value_ptr);
 * @endcode
 * will result in value_len = 6 and value_ptr = "second"
 *
 * @param query The query to parse.
 * @param parameter_name The parameter name to parse from the query.
 * @param[out] parameter_value A pointer to the parameter value, NULL if parameter does not exist.
 * @return The size of the parameter value, -1 if parameter does not exist in the query.
 */
int parse_query_parameter_value_from_query(const char *query, const char *parameter_name, const char **parameter_value);


#endif /* URIQUERYPARSER_H_ */

#ifdef __cplusplus
}
#endif
