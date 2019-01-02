// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//  
//     http://www.apache.org/licenses/LICENSE-2.0
//  
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef __PV_ERROR_HANDLING_H__
#define __PV_ERROR_HANDLING_H__


#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdbool.h>

#include "pv_log.h"


/** The following are macros to enable different error handling in development
 *    environment and production environment:
 *    On development environment, in oredr to speed up bug fixing we might want
 *    to assert or disable CK services. On production we shall not halt since
 *    we might get the whole device stuck.
 *    The errors are devided into 2 categories:
 *    1. recoverable errors - like invalid parameter to API function
 *    2. non-recoverable errors - like allocation failures
 *    default values for production is to not halt in any case,
 *    for development the default is to halt in non-recovrable error only
 *    since recoverable error may occure in negative tests
 */
#ifdef DEVELOPMENT_ENV
#define HALT_ON_RECOVERABLE_ERRORS()  	0
#define HALT_ON_UNRECOVERABLE_ERRORS()  0
#else //if PRODUCTION_ENV
#define HALT_ON_RECOVERABLE_ERRORS()  	0
#define HALT_ON_UNRECOVERABLE_ERRORS()  0
#endif

/**  Set this to 1 to immediately assert when an unrecoverable error is
 *    detected in PC environment.
 *    While it can be nice to get an immediate assert, often seeing the
 *    call trace is more useful - so the default is NOT to assert.
 */
#define ASSERT_IN_PC_ENV() 0

// Currently, this flag is defined in makefile errors.mk
// Set this to 1 in order to completely ignore unrecoverable errors -
// condition won't be checked, nothing would be printed.
// This should only be used in situations where memory is very tight,
// and would render debugging very complicated!
//#define IGNORE_UNRECOVERABLE_ERRORS 0


void pv_error_occured(void);
bool pv_error_is_error_occured(void);

#if  ((HALT_ON_RECOVERABLE_ERRORS()) || (HALT_ON_UNRECOVERABLE_ERRORS()))
#define SA_PV_IS_PREV_ERROR_OCCURED() (pv_error_is_error_occured())
#else
#define SA_PV_IS_PREV_ERROR_OCCURED() (false)
#endif



#define _SA_PV_ERR_ASSERT_UPON_ERROR(cond, return_code, args...) {\
	if (cond) { \
		SA_PV_LOG_ERR_FUNC_EXIT(__VA_ARGS__);\
		assert(!(cond));\
		(void)return_code;  /* Mention explicitly to fail compilation if return_code is not compilable. */ \
		abort();\
	}\
}

#define _SA_PV_ERR_ASSERT_UPON_ERROR_GOTO(cond, return_code_assignment, goto_label, args...) {\
	if (cond) {\
		SA_PV_LOG_ERR(__VA_ARGS__);\
		assert(!(cond));\
		abort();\
		return_code_assignment;  /* Mention explicitly to fail compilation if return_code_assignment is not compilable. */ \
		goto goto_label;\
	}\
}

#define _SA_PV_ERR_OCCURED_AND_RETURN_UPON_ERROR(cond, return_code, args...) {\
	if (cond) {\
		SA_PV_LOG_ERR_FUNC_EXIT(__VA_ARGS__); \
		pv_error_occured();\
		return return_code;\
	}\
}

#define _SA_PV_RETURN_UPON_ERROR(level, cond, return_code, args...) {\
	if (cond) {\
		SA_PV_LOG_ ## level ## _FUNC_EXIT(__VA_ARGS__);\
		return return_code;\
	}\
}
#define _SA_PV_ERR_OCCURED_AND_GOTO_UPON_ERROR(cond, return_code_assignment, goto_label, args...) {\
	if (cond) {\
		SA_PV_LOG_ERR(__VA_ARGS__);\
		pv_error_occured();\
		return_code_assignment;\
		goto goto_label;\
	}\
}

#define _SA_PV_GOTO_UPON_ERROR(level, cond, return_code_assignment, goto_label, args...) {\
	if (cond) {\
		SA_PV_LOG_ ## level(__VA_ARGS__); \
		return_code_assignment;\
		goto goto_label;\
	}\
}


/**  For non-recoverable errors, if condition fails:
 *    log error message
 *    if in development and running on PC - assert
 *    if in development but not PC - disable further processing with CK and return error code
 *    if in case in production (default  behavior), just return error code
 */
#if HALT_ON_UNRECOVERABLE_ERRORS()
#if defined(SA_PV_PC_ENV) && ASSERT_IN_PC_ENV()
#ifndef IGNORE_UNRECOVERABLE_ERRORS
#define SA_PV_ERR_UNRECOVERABLE_RETURN_IF(cond, return_code, args...) \
				_SA_PV_ERR_ASSERT_UPON_ERROR((cond), (return_code), ##__VA_ARGS__)
#else
#define SA_PV_ERR_UNRECOVERABLE_RETURN_IF(cond, return_code, args...) \
				if (false && (cond)) {}  /* Dummy use of the condition to avoid compiler warnings */
#endif
#else
#ifndef IGNORE_UNRECOVERABLE_ERRORS
#define SA_PV_ERR_UNRECOVERABLE_RETURN_IF(cond, return_code, args...) \
				_SA_PV_ERR_OCCURED_AND_RETURN_UPON_ERROR((cond), (return_code), ##__VA_ARGS__)
#else
#define SA_PV_ERR_UNRECOVERABLE_RETURN_IF(cond, return_code, args...) \
				if (false && (cond)) {}  /* Dummy use of the condition to avoid compiler warnings */
#endif
#endif
#else   // HALT_ON_UNRECOVERABLE_ERRORS  
#ifndef IGNORE_UNRECOVERABLE_ERRORS
#define SA_PV_ERR_UNRECOVERABLE_RETURN_IF(cond, return_code, args...) \
			_SA_PV_RETURN_UPON_ERROR(ERR, (cond), (return_code), ##__VA_ARGS__)
#else
#define SA_PV_ERR_UNRECOVERABLE_RETURN_IF(cond, return_code, args...) \
			if (false && (cond)) {}  /* Dummy use of the condition to avoid compiler warnings */
#endif
#endif // HALT_ON_UNRECOVERABLE_ERRORS

/**  For non-recoverable errors, if condition fails:
 *     log error message
 *     if in development and running on PC - assert
 *     if in development but not PC - disable further processing with CK and assign error code and goto label
 *     if in case in production (default  behavior), just  assign error code and goto label
 */
#if HALT_ON_UNRECOVERABLE_ERRORS()
#if defined(SA_PV_PC_ENV) && ASSERT_IN_PC_ENV()
#ifndef IGNORE_UNRECOVERABLE_ERRORS
#define SA_PV_ERR_UNRECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
				_SA_PV_ERR_ASSERT_UPON_ERROR_GOTO((cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
#else
#define SA_PV_ERR_UNRECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
				if (false && (cond)) {  /* Dummy use of the condition to avoid compiler warnings */ \
					return_code_assignment;  /* Dummy use of the assignment to avoid compiler warnings */ \
					goto goto_label;  /* Dummy use of the goto label to avoid compiler warnings. */ \
				}
#endif
#else
#ifndef IGNORE_UNRECOVERABLE_ERRORS
#define SA_PV_ERR_UNRECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
				_SA_PV_ERR_OCCURED_AND_GOTO_UPON_ERROR((cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
#else
#define SA_PV_ERR_UNRECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
				if (false && (cond)) {  /* Dummy use of the condition to avoid compiler warnings */ \
					return_code_assignment;  /* Dummy use of the assignment to avoid compiler warnings */ \
					goto goto_label;  /* Dummy use of the goto label to avoid compiler warnings. */ \
				}
#endif
#endif
#else // HALT_ON_UNRECOVERABLE_ERRORS  
#ifndef IGNORE_UNRECOVERABLE_ERRORS
#define SA_PV_ERR_UNRECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
			_SA_PV_GOTO_UPON_ERROR(ERR, (cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
#else
#define SA_PV_ERR_UNRECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
			if (false && (cond)) {  /* Dummy use of the condition to avoid compiler warnings */ \
				return_code_assignment;  /* Dummy use of the assignment to avoid compiler warnings */ \
				goto goto_label;  /* Dummy use of the goto label to avoid compiler warnings. */ \
			}
#endif
#endif // HALT_ON_UNRECOVERABLE_ERRORS


/** Recoverable errors handling
 *    For recoverable errors, if condition fails:
 *    log error message
 *    if in development and running on PC - assert
 *    if in development but not PC - disable further processing with CK and return error code
 *    if in case in production (default  behavior), just log and return error code
 *    this is all only regarding errors. INFO, TRACE, etc. will not cause halt, will just log and return error code
 */
#if HALT_ON_RECOVERABLE_ERRORS()
#if defined(SA_PV_PC_ENV) && ASSERT_IN_PC_ENV()
#define SA_PV_ERR_RECOVERABLE_RETURN_IF(cond, return_code, args...) \
			_SA_PV_ERR_ASSERT_UPON_ERROR((cond), return_code, ##__VA_ARGS__)
#else
#define SA_PV_ERR_RECOVERABLE_RETURN_IF(cond, return_code, args...) \
			_SA_PV_ERR_OCCURED_AND_RETURN_UPON_ERROR((cond), (return_code), ##__VA_ARGS__)
#endif
#else // HALT_ON_RECOVERABLE_ERRORS
#define SA_PV_ERR_RECOVERABLE_RETURN_IF(cond, return_code, args...) \
		_SA_PV_RETURN_UPON_ERROR(ERR, (cond), (return_code), ##__VA_ARGS__)

#define SA_PV_ERR_RECOVERABLE_RETURN(return_code, args...) \
        SA_PV_LOG_ERR_FUNC_EXIT(__VA_ARGS__); \
        return return_code;
#endif // HALT_ON_RECOVERABLE_ERRORS

// if the condition is true:
// Theses macros return with return_code and perform the exit function log (if the log level is appropriate).

// FIXME: This is partial solution, for critical level, also unrecoverable return should be treated and
// the macros for different  flags should be implemented (HALT_ON_RECOVERABLE_ERRORS etc.)
#define SA_PV_CRITICAL_RECOVERABLE_RETURN_IF(cond, return_code, args...) \
	_SA_PV_RETURN_UPON_ERROR(CRITICAL, (cond), (return_code), ##__VA_ARGS__)
//	used in errors that are not critical (such as failure to read data from a socket - a retry is scheduled)
#define SA_PV_WARN_RECOVERABLE_RETURN_IF(cond, return_code, args...) \
	_SA_PV_RETURN_UPON_ERROR(WARN, (cond), (return_code), ##__VA_ARGS__)
//	used in external APIs
#define SA_PV_INFO_RECOVERABLE_RETURN_IF(cond, return_code, args...) \
	_SA_PV_RETURN_UPON_ERROR(INFO, (cond), (return_code), ##__VA_ARGS__)
//	used in internal APIs
#define SA_PV_TRACE_RECOVERABLE_RETURN_IF(cond, return_code, args...) \
	_SA_PV_RETURN_UPON_ERROR(TRACE, (cond), (return_code), ##__VA_ARGS__)
#define SA_PV_DATA_RECOVERABLE_RETURN_IF(cond, return_code, args...) \
	_SA_PV_RETURN_UPON_ERROR(DATA, (cond), (return_code), ##__VA_ARGS__)

/** For recoverable errors, if condition fails:
 *    log error message
 *    if in development and running on PC - assert
 *    if in development but not PC - disable further processing with CK and assign error code and goto label
 *    if in case in production (default  behavior), just log, assign error code and goto label
 *    this is all only regarding errors. INFO, TRACE, etc. will not cause halt, will just log, assign error code and goto label
 */
#if HALT_ON_RECOVERABLE_ERRORS()
#if defined(SA_PV_PC_ENV) && ASSERT_IN_PC_ENV()
#define SA_PV_ERR_RECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
			_SA_PV_ERR_ASSERT_UPON_ERROR_GOTO((cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
#else
#define SA_PV_ERR_RECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
			_SA_PV_ERR_OCCURED_AND_GOTO_UPON_ERROR((cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
#endif
#else // HALT_ON_RECOVERABLE_ERRORS
#define SA_PV_ERR_RECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
		_SA_PV_GOTO_UPON_ERROR(ERR, (cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
#endif // HALT_ON_RECOVERABLE_ERRORS

// if the condition is true:
// Theses macros jump to goto_label with return_code and perform log (if the log level is appropriate).

// FIXME: This is partial solution, for critical level, also unrecoverable goto should be treated and
// the macros for differnet  flags should be implemented (HALT_ON_RECOVERABLE_ERRORS etc.)
#define SA_PV_CRITICAL_RECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
	_SA_PV_GOTO_UPON_ERROR(CRITICAL, (cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
//	used in errors that are not critical (such as failure to read data from a socket - a retry is scheduled)
#define SA_PV_WARN_RECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
	_SA_PV_GOTO_UPON_ERROR(WARN, (cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
//	used in external APIs
#define SA_PV_INFO_RECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
	_SA_PV_GOTO_UPON_ERROR(INFO, (cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
//	used in internal APIs
#define SA_PV_TRACE_RECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
	_SA_PV_GOTO_UPON_ERROR(TRACE, (cond), (return_code_assignment), goto_label, ##__VA_ARGS__)
//	used in functions that are called many times and we don't necessary want to see all its logging even in TRACE mode
#define SA_PV_DATA_RECOVERABLE_GOTO_IF(cond, return_code_assignment, goto_label, args...) \
	_SA_PV_GOTO_UPON_ERROR(DATA, (cond), (return_code_assignment), goto_label, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif  // __PV_ERROR_HANDLING_H__

