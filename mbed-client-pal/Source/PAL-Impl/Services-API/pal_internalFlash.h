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
#ifndef PAL_FLASH_H
#define PAL_FLASH_H

#ifdef __cplusplus
extern "C" {
#endif


#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif



#define PAL_INT_FLASH_BLANK_VAL 0xFF


/*! \brief This function initialized the flash API module,
 * 			And should be called prior flash APIs calls
 *
 * \return   PAL_SUCCESS upon successful operation. \n
 *           PAL_FILE_SYSTEM_ERROR - see error code \c palError_t.
 *
 * \note should be called only once unless \c pal_internalFlashDeinit function is called
 * \note This function is Blocking till completion!!
 *
 */
palStatus_t pal_internalFlashInit(void);

/*! \brief This function destroy the flash module
 *
 * \return PAL_SUCCESS upon successful operation. \n
 *         PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
 *
 * \note Should be called only after \c pal_internalFlashinit() is called.
 * \note Flash APIs will not work after calling this function
 * \note This function is Blocking till completion!!
 *
 */
palStatus_t pal_internalFlashDeInit(void);

/*! \brief This function writes to the internal flash
*
* @param[in]	buffer - pointer to the buffer to be written
* @param[in]	size - the size of the buffer in bytes.
* @param[in]	address - the address of the internal flash, must be aligned to minimum writing unit (page size).
*
* \return PAL_SUCCESS upon successful operation. \n
*         PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
*
* \note ALL address can be written to!! No protection to boot loader, program or other...
* \note This function is Blocking till completion!!
* \note This function is Thread Safe!!
*/
palStatus_t pal_internalFlashWrite(const size_t size, const uint32_t address, const uint32_t * buffer);

/*! \brief This function copies the memory data into the user given buffer
*
* @param[in]	size - the size of the buffer in bytes.
* @param[in]	address - the address of the internal flash.
* @param[out]	buffer - pointer to the buffer to write to
*
* \return PAL_SUCCESS upon successful operation. \n
*         PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
* \note This function is Blocking till completion!!
* \note This function is Thread Safe!!
*
*/
palStatus_t pal_internalFlashRead(const size_t size, const uint32_t address, uint32_t * buffer);

/*! \brief This function Erase the sector
*
* @param[in]	size - the size to be erased
* @param[in]	address - sector start address to be erased, must be align to sector.
*
* \return PAL_SUCCESS upon successful operation. \n
*         PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
*
* \note ALL sectors can be erased!! No protection to bootloader, program or other...
* \note This function is Blocking till completion!!
* \note Only one sector can be erased in each function call
* \note This function is Thread Safe!!
*/
palStatus_t pal_internalFlashErase(uint32_t address, size_t size);


/*! \brief This function returns the minimum writing unit to the flash
*
* \return size_t the 2, 4, 8....
*/
size_t pal_internalFlashGetPageSize(void);


/*! \brief This function returns the sector size for the given address
 *
* @param[in]	the starting address of the sector is question
*
* \return size of sector, 0 if error
*/
size_t pal_internalFlashGetSectorSize(uint32_t address);


///////////////////////////////////////////////////////////////
////-------------------SOTP functions------------------------//
///////////////////////////////////////////////////////////////

/*! \brief This function return the SOTP section data
*
* @param[in]	section - the section number (0 or 1)
* @param[out]	data - the information about the section
*
* \return PAL_SUCCESS upon successful operation. \n
*         PAL_ERR_INTERNAL_FLASH_ERROR - see error code \c palError_t.
*
*/
palStatus_t pal_internalFlashGetAreaInfo(uint8_t section, palSotpAreaData_t *data);

#ifdef __cplusplus
}
#endif
#endif //PAL_FLASH_H
