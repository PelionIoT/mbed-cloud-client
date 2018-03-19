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

/*\brief  Starting Address for section 1 Minimum requirement size is 1KB and section must be consecutive sectors*/
#ifndef PAL_INTERNAL_FLASH_SECTION_1_ADDRESS
#define PAL_INTERNAL_FLASH_SECTION_1_ADDRESS    0x080C0000
#endif

/*\brief  Starting Address for section 2 Minimum requirement size is 1KB and section must be consecutive sectors*/
#ifndef PAL_INTERNAL_FLASH_SECTION_2_ADDRESS
#define PAL_INTERNAL_FLASH_SECTION_2_ADDRESS    0x080E0000
#endif

/*\brief  Size for section 1*/
#ifndef PAL_INTERNAL_FLASH_SECTION_1_SIZE
#define PAL_INTERNAL_FLASH_SECTION_1_SIZE       0x20000
#endif

/*\brief  Size for section 2*/
#ifndef PAL_INTERNAL_FLASH_SECTION_2_SIZE
#define PAL_INTERNAL_FLASH_SECTION_2_SIZE       0x20000
#endif

#ifndef PAL_INT_FLASH_NUM_SECTIONS
#define PAL_INT_FLASH_NUM_SECTIONS 2
#endif

#ifndef PAL_USE_INTERNAL_FLASH 
#define PAL_USE_INTERNAL_FLASH  1
#endif

#ifndef PAL_USE_HW_ROT 
#define PAL_USE_HW_ROT     0
#endif

#ifndef PAL_USE_HW_RTC
#define PAL_USE_HW_RTC    0
#endif
