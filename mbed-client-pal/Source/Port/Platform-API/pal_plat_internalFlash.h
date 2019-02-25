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
#ifndef PAL_PLAT_FLASH_H_
#define PAL_PLAT_FLASH_H_

#include "pal_internalFlash.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief This function initialized the flash API module,
 * 			And should be called prior to flash API calls.
 *
 * \return   PAL_SUCCESS upon successful operation.
 * \return   PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
 *
 * \note Should be called only once unless \c pal_InternalFlashDeInit function is called.
 * \note This function is Blocking till completion!!
 *
 */
palStatus_t pal_plat_internalFlashInit(void);

/*! \brief This function deinitializes the flash module.
 *
 * \return PAL_SUCCESS upon successful operation.
 * \return PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
 *
 * \note Should be called only after \c pal_InternalFlashinit() is called.
 * \note Flash APIs will not work after calling this function.
 * \note This function is \b Blocking till completion.
 *
 */
palStatus_t pal_plat_internalFlashDeInit(void);

/*! \brief This function writes to the internal flash
*
* @param[in]	buffer - pointer to the buffer to be written
* @param[in]	size - the size of the buffer in bytes, must be aligned to minimum writing unit (page size).
* @param[in]	address - the address of the internal flash.
*
* \return PAL_SUCCESS upon successful operation.
* \return PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
*
* \note This function is \b Blocking till completion.
* \note This function is Thread Safe.
*/
palStatus_t pal_plat_internalFlashWrite(const size_t size, const uint32_t address, const uint32_t * buffer);

/*! \brief This function copies the memory data into the user given buffer
*
* @param[in]	size - the size of the buffer in bytes.
* @param[in]	address - the address of the internal flash.
* @param[out]	buffer - pointer to the buffer to write to
*
* \return PAL_SUCCESS upon successful operation.
* \return PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
* \note This function is \b Blocking till completion.
* \note This function is Thread Safe.
*
*/
palStatus_t pal_plat_internalFlashRead(const size_t size, const uint32_t address, uint32_t * buffer);

/*! \brief This function erases a sector
*
* @param[in]	size - the size to be erased, must match sector size.
* @param[in]	address - start address for the sector to be erased.
*
* \return PAL_SUCCESS upon successful operation.
* \return PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
*
* \note \e ALL sectors can be erased. There is no protection for bootloader, program or other sectors.
* \note This function is \b Blocking till completion.
* \note Only one sector can be erased with each function call.
* \note This function is Thread Safe.
*/
palStatus_t pal_plat_internalFlashErase(uint32_t address, size_t size);

/*! \brief This function returns the minimum size of the writing unit when writing to the flash
*
* \return the minimum size of the writing unit.
*/
size_t pal_plat_internalFlashGetPageSize(void);


/*! \brief This function returns the sector size
 *
* @param[in]	address - the starting address of the sector in question
*
* \return size of sector, `0` in case of error
*/
size_t pal_plat_internalFlashGetSectorSize(uint32_t address);



///////////////////////////////////////////////////////////////
////-------------------SOTP functions------------------------//
///////////////////////////////////////////////////////////////
/*! \brief This function return the SOTP section data
*
* @param[in]	section - the section number (0 or 1)
* @param[out]	data - the information about the section
*
* \return PAL_SUCCESS upon successful operation.
* \return PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
*
*/
palStatus_t pal_plat_internalFlashGetAreaInfo(uint8_t section, palSotpAreaData_t *data);


#ifdef __cplusplus
}
#endif

#endif /* PAL_PLAT_FLASH_H_ */
