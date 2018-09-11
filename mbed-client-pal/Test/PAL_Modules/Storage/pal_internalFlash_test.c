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

#include "pal.h"
#include "unity.h"
#include "unity_fixture.h"

#define TRACE_GROUP "PAL"

#if PAL_USE_INTERNAL_FLASH

TEST_GROUP(pal_internalFlash);
#define LITTLE_BUFFER_SIZE					120
#define PRIME_NUMBER_FOR_TESTING			11 //must be 4 times lower then LITTLE_BUFFER_SIZE
#define MAX_BUFFER_SIZE                     0x1000

palSotpAreaData_t areaOneData;
palSotpAreaData_t areaTwoData;
uint32_t *ReadBuffer = NULL;
uint32_t *compareBuffer = NULL;
uint32_t biggestSectorSize = 0;


palStatus_t InternalFlashWriteTest(uint32_t address_offset);
palStatus_t InternalFlashReadTest(uint32_t address_offset);

TEST_SETUP(pal_internalFlash)
{
	palStatus_t status = PAL_SUCCESS;
	status = pal_internalFlashGetAreaInfo(0, &areaOneData);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	status = pal_internalFlashGetAreaInfo(1, &areaTwoData);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	biggestSectorSize = (PAL_MAX(areaTwoData.size, areaOneData.size));
	biggestSectorSize = (PAL_MIN(biggestSectorSize, MAX_BUFFER_SIZE)); //there are sector size 128KB so this limit the buffer to 4KB
	ReadBuffer = (uint32_t *)malloc(biggestSectorSize);
	TEST_ASSERT_NOT_NULL(ReadBuffer);
	compareBuffer = (uint32_t *)malloc(biggestSectorSize);
	TEST_ASSERT_NOT_NULL(compareBuffer);
    pal_init();
}

TEST_TEAR_DOWN(pal_internalFlash)
{
	if (compareBuffer != NULL)
	{
		free(compareBuffer);
		compareBuffer = NULL;
	}

	if (ReadBuffer != NULL)
	{
		free(ReadBuffer);
		ReadBuffer = NULL;
	}
    pal_destroy();
}

/*! \brief This function checks if the flash needed to be deleted by checking if all bytes in sector are 0xFF */
void SectorDeleteValidity(uint32_t address, size_t size)
{
	palStatus_t status = PAL_SUCCESS;
	uint32_t index = 0;
	memset(ReadBuffer, 0, biggestSectorSize);

	status = pal_internalFlashRead(biggestSectorSize, address, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	for(index = 0; index < biggestSectorSize; index++)
	{
		if(*((uint8_t*)ReadBuffer + index) != 0xFF)
		{
		    status = pal_internalFlashErase(address, size);
		    TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
		    break;
		}

	}
}

/*! \brief Basic read write & erase tests
 *
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Check if Sector A and B are erased                               | 			   |
* | 2 | Read sector A & B and compare them to 0xFF (erased sector)       | PAL_SUCCESS |
* | 3 | Run Write tests See function for more details                    | PAL_SUCCESS |
* | 4 | Run Read tests See function for more details                     | PAL_SUCCESS |
* | 5 | fill sector B with provided Data (full sector write)             | PAL_SUCCESS |
* | 6 | Read full sector and compare                                     | PAL_SUCCESS |
* | 7 | Delete Sector one                                                | PAL_SUCCESS |
* | 8 | Read and verify that sector two in not changed                   | PAL_SUCCESS |
* | 9 | Delete Sector two                                                | PAL_SUCCESS |
* | 10 | read compare both sectors to 0xff (verify erased)               | PAL_SUCCESS |
*/
TEST(pal_internalFlash, BasicTest)
{
	palStatus_t status = PAL_SUCCESS;
	/*1*/
    SectorDeleteValidity(areaOneData.address, areaOneData.size);
    SectorDeleteValidity(areaTwoData.address, areaTwoData.size);

	memset(compareBuffer, 0xFF, biggestSectorSize);
	memset(ReadBuffer, 0, biggestSectorSize);

	/*2*/
    DEBUG_PRINT("Read both sectors and compare to 0xFF \n\r");
	status = pal_internalFlashRead(biggestSectorSize, areaOneData.address, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	TEST_ASSERT_EQUAL_UINT8_ARRAY((uint8_t *)ReadBuffer, (uint8_t *)compareBuffer, biggestSectorSize);

	status = pal_internalFlashRead(biggestSectorSize, areaTwoData.address, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	TEST_ASSERT_EQUAL_UINT8_ARRAY((uint8_t *)ReadBuffer, (uint8_t *)compareBuffer, biggestSectorSize);

	/*3*/
	status = InternalFlashWriteTest(areaOneData.address);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	/*4*/
	status = InternalFlashReadTest(areaOneData.address + 2 * LITTLE_BUFFER_SIZE);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);


	DEBUG_PRINT("---------FULL SECTOR TEST---------\n\r");
    for (uint32_t i = 0; i < biggestSectorSize; i++)
    {
    	((uint8_t *)compareBuffer)[biggestSectorSize - i - 1] = (uint8_t)(i % 256);
    }
    DEBUG_PRINT("Write data to second sector\n\r");
    /*5*/
	status = pal_internalFlashWrite(biggestSectorSize, areaTwoData.address, compareBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);

	/*6*/
	memset(ReadBuffer, 0, biggestSectorSize);
	DEBUG_PRINT("Read and compare from second sector\n\r");
	status = pal_internalFlashRead(biggestSectorSize, areaTwoData.address, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	TEST_ASSERT_EQUAL_UINT8_ARRAY((uint8_t *)ReadBuffer, (uint8_t *)compareBuffer, biggestSectorSize);

	/*7*/
	DEBUG_PRINT("Delete sector one\n\r");
   status = pal_internalFlashErase(areaOneData.address, areaOneData.size);
   TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);

   /*8*/
	DEBUG_PRINT("Verify that sector 2 was not changed in sector one erasing\n\r");
	status = pal_internalFlashRead(biggestSectorSize, areaTwoData.address, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	TEST_ASSERT_EQUAL_UINT8_ARRAY((uint8_t *)ReadBuffer, (uint8_t *)compareBuffer, biggestSectorSize);

	/*9*/
	DEBUG_PRINT("Delete sector two\n\r");
   status = pal_internalFlashErase(areaTwoData.address, areaTwoData.size);
   TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);

   /*10*/
   memset(compareBuffer, 0xFF, biggestSectorSize);
   DEBUG_PRINT("Read both sectors and compare to 0xFF (verify that erase is done)\n\r");
	status = pal_internalFlashRead(biggestSectorSize, areaOneData.address, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	TEST_ASSERT_EQUAL_UINT8_ARRAY((uint8_t *)ReadBuffer, (uint8_t *)compareBuffer, biggestSectorSize);

	status = pal_internalFlashRead(biggestSectorSize, areaTwoData.address, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	TEST_ASSERT_EQUAL_UINT8_ARRAY((uint8_t *)ReadBuffer, (uint8_t *)compareBuffer, biggestSectorSize);
}



/*! \brief Write tests to internal Flash with different sizes
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Write Data to sector from align address and up to prime number, prime number will never divide in page size     | PAL_SUCCESS |
* | 2 | Read & compare Data up to prime number												       						| PAL_SUCCESS |
* | 3 | Write Data from  next align address from the prime number up to buffer size                  					| PAL_SUCCESS |
* | 4 | Read & compare Data from prime number and up to end of buffer						       						| PAL_SUCCESS |
*/


palStatus_t InternalFlashWriteTest(uint32_t address_offset)
{
	palStatus_t status = PAL_SUCCESS;
	uint32_t alignPage = pal_internalFlashGetPageSize();

	TEST_ASSERT_NOT_EQUAL(alignPage, 0);

	DEBUG_PRINT("---------WRITE TEST---------r\n\r");
	memset(compareBuffer, 0xFF, biggestSectorSize);
	memset(ReadBuffer, 0, biggestSectorSize);

    for (uint32_t i = 0; i < PRIME_NUMBER_FOR_TESTING; i++)
    {
    	compareBuffer[i] = (uint8_t)(i % 256);
    }
    /*1*/
    DEBUG_PRINT("Write data to First Sector up to PRIME_NUMBER_FOR_TESTINGr\n\r");
	status = pal_internalFlashWrite(PRIME_NUMBER_FOR_TESTING, address_offset, compareBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);

	/*2*/
	DEBUG_PRINT("Read and compare from first sector\n\r");
	status = pal_internalFlashRead(PRIME_NUMBER_FOR_TESTING, address_offset, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	TEST_ASSERT_EQUAL_UINT8_ARRAY((uint8_t *)ReadBuffer, (uint8_t *)compareBuffer, PRIME_NUMBER_FOR_TESTING);

    for (uint32_t i = PRIME_NUMBER_FOR_TESTING; i < LITTLE_BUFFER_SIZE / 4 ; i++)
    {
    	compareBuffer[i] = (uint32_t)(i % 256);
    }

    /*3*/
    uint32_t offset = PRIME_NUMBER_FOR_TESTING - (PRIME_NUMBER_FOR_TESTING % alignPage) + alignPage;
    DEBUG_PRINT("Write data to First Sector from PRIME_NUMBER_FOR_TESTING up to LITTLE_BUFFER_SIZE\n\r");
	status = pal_internalFlashWrite(LITTLE_BUFFER_SIZE - offset, address_offset + offset, compareBuffer + offset / 4);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);

	/*4*/
	DEBUG_PRINT("Read and compare from first sector\n\r");
	status = pal_internalFlashRead(LITTLE_BUFFER_SIZE - offset, address_offset + offset, ReadBuffer + offset / 4);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
	TEST_ASSERT_EQUAL_UINT8_ARRAY((uint8_t *)ReadBuffer + offset, (uint8_t *)compareBuffer + offset, LITTLE_BUFFER_SIZE - offset);
	return PAL_SUCCESS;
}


/*! \brief read tests with different sizes
 * *
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Write data to sector                                | PAL_SUCCESS |
* | 2 | Read data in chunks of bytes and compare            | PAL_SUCCESS |
*/

palStatus_t InternalFlashReadTest(uint32_t address_offset)
{
	palStatus_t status = PAL_SUCCESS;
	DEBUG_PRINT("---------READ TEST---------r\n\r");
	memset(compareBuffer, 0xFF, biggestSectorSize);
	memset(ReadBuffer, 0, biggestSectorSize);
    for (uint32_t i = 0; i < LITTLE_BUFFER_SIZE / 4; i++)
    {
    	ReadBuffer[i] = (uint32_t)(i % 256);
    }
    /*1*/
    DEBUG_PRINT("Write data to Sector up to LITTLE_BUFFER_SIZE\n\r");
	status = pal_internalFlashWrite(LITTLE_BUFFER_SIZE, address_offset, ReadBuffer);
	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);

	/*2*/
	DEBUG_PRINT("Read and compare\n\r");
    for (uint32_t i = 0; i < LITTLE_BUFFER_SIZE / 4; i++)
    {
    	uint32_t value = 0;
    	status = pal_internalFlashRead(1, address_offset + i, &value);
    	TEST_ASSERT_EQUAL_HEX(status, PAL_SUCCESS);
    	TEST_ASSERT_EQUAL_HEX(*((uint8_t *)ReadBuffer + i), (uint8_t)value);
    }
    return PAL_SUCCESS;
}

/*! \brief Negative tests to verify validations and errors
 *
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Delete sector with unaligned address                                | PAL_ERR_INTERNAL_FLASH_SECTOR_NOT_ALIGNED |
* | 2 | Write with null ptr has buffer					                    | PAL_ERR_INTERNAL_FLASH_CROSSING_SECTORS |
* | 3 | write with address not align to page size               		    | PAL_ERR_INTERNAL_FLASH_ADDRESS_NOT_ALIGNED |
* | 4 | write to unaligned buffer  								            | PAL_ERR_INTERNAL_FLASH_BUFFER_ADDRESS_NOT_ALIGNED |
*/

TEST(pal_internalFlash, NegativeTest)
{
#ifdef DEBUG
	palStatus_t status = PAL_SUCCESS;
	uint8_t alignPage = pal_internalFlashGetPageSize();
	uint32_t * ReadBuffer1 = NULL;
	TEST_ASSERT_NOT_EQUAL(alignPage, 0);

	/*1*/
    status = pal_internalFlashErase(areaOneData.address + 4, areaOneData.size);
    TEST_ASSERT_EQUAL_HEX(status, PAL_ERR_INTERNAL_FLASH_SECTOR_NOT_ALIGNED);

	/*2*/
	status = pal_internalFlashWrite(areaOneData.size * 2, areaOneData.address, ReadBuffer1);
	TEST_ASSERT_EQUAL_HEX(status, PAL_ERR_INTERNAL_FLASH_NULL_PTR_RECEIVED);

	/*3*/
	if( pal_internalFlashGetPageSize() > 1)
	{//This test only valid if page size is bigger then 1
	    status = pal_internalFlashWrite(8, (uint32_t)4, (uint32_t*)&ReadBuffer1);
	    TEST_ASSERT_EQUAL_HEX(status, PAL_ERR_INTERNAL_FLASH_ADDRESS_NOT_ALIGNED);
	}

	/*4*/
	status = pal_internalFlashWrite(8 , areaOneData.address + alignPage + 1, (uint32_t*)0x11);
	TEST_ASSERT_EQUAL_HEX(status, PAL_ERR_INTERNAL_FLASH_BUFFER_ADDRESS_NOT_ALIGNED);
#endif
}

#endif //PAL_USE_INTERNAL_FLASH
