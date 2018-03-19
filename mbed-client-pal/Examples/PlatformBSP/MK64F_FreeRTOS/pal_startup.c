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
#include "PlatIncludes.h"
#include "fsl_debug_console.h"
#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sys.h"
#include "pal_BSP.h"

#ifndef TEST_MAIN_THREAD_STACK_SIZE
#define TEST_MAIN_THREAD_STACK_SIZE (1024*8)
#endif

#ifndef TEST_FS_INIT_THREAD_STACK_SIZE
#define TEST_FS_INIT_THREAD_STACK_SIZE (1024*4)
#endif

#ifndef BSP_MAX_INIT_ITERATIONS 
#define BSP_MAX_INIT_ITERATIONS 600
#endif

#ifndef BSP_INIT_INTERATION_TIME_MS 
#define BSP_INIT_INTERATION_TIME_MS 1000
#endif




extern bool dhcpDone;
extern bool FileSystemInit;
int main(int argc, char * argv[]);


void freeRTOScallMain(void * arg)
{
    main(0,NULL);
}


//returns the network context
 bspStatus_t initPlatform(void** outputContext)
{
    bspStatus_t status = BSP_SUCCESS;
    static uint8_t initState = 0;
    BaseType_t rtosStatus = pdPASS;
    //1st time in init the system is required
    if (0 == initState) 
    {
        //set for next initState
        initState = 1;

    	//Init Board
    	boardInit();

    	//Init FileSystem
    	rtosStatus = xTaskCreate((TaskFunction_t)fileSystemMountDrive, "FileSystemInit", TEST_FS_INIT_THREAD_STACK_SIZE, NULL, tskIDLE_PRIORITY + 3, NULL);
        if (pdPASS != rtosStatus)
        {
            PRINTF("BSP ERROR: failed to create task with error %x \r\n", rtosStatus);
            status = BSP_THREAD_CREATION_FAILURE;
            goto end;
        }

    	//Init DHCP thread - note: according to LWIP docs this funciton can't fail (states that porting code must asset in case of failure) 
        sys_thread_new("networkInit", networkInit, NULL, 1024, tskIDLE_PRIORITY + 2);

        //Init Unit testing thread
        rtosStatus = xTaskCreate(freeRTOScallMain, "main", (uint16_t)PAL_TEST_THREAD_STACK_SIZE, NULL, tskIDLE_PRIORITY + 1, NULL);
        if (pdPASS != rtosStatus)
        {
            PRINTF("BSP ERROR: failed to create task with error %x \r\n", rtosStatus);
            status = BSP_THREAD_CREATION_FAILURE;
            goto end;
        }

    	//Start OS
    	vTaskStartScheduler();
        // taks scheduler shouldn't exit unless an error has occured
        PRINTF("BSP ERROR: failed to run scheduler \r\n");
        status = BSP_THREAD_CREATION_FAILURE;
        goto end;
    }  
    if (1 == initState) 
    {
        uint32_t counter = 0; // limit waiting for FileSystemInit and dhcpDone to 
        while (((!FileSystemInit) || (!dhcpDone))  && (counter < BSP_MAX_INIT_ITERATIONS))
        {
            vTaskDelay(BSP_INIT_INTERATION_TIME_MS);
            PRINTF("waiting to file system % network to init\r\n");
            counter++;
        }

        if ((!dhcpDone) || (!FileSystemInit))
        {
            if (!FileSystemInit)
            {
                status = BSP_FILE_SYSTEM_TIMEOUT;
                PRINTF("BSP ERROR: timeout while waiting for file system init\r\n");
                
            }
            if (!dhcpDone)
            {
                status = BSP_NETWORK_TIMEOUT;
                PRINTF("BSP ERROR: timeout while waiting for dhcp \r\n");
            }
            goto end;
        }

    }
     
    if (NULL != outputContext)
    {
        *outputContext = palTestGetNetWorkInterfaceContext();
    }

end:
   return status;

}


bool runProgram(testMain_t func, pal_args_t * args)
{
    func(args);
    return true;
}

#ifndef __CC_ARM          /* ARM Compiler */
/*This is a Hardfault handler to use in debug for more info please read -
 * http://www.freertos.org/Debugging-Hard-Faults-On-Cortex-M-Microcontrollers.html */
/* The prototype shows it is a naked function - in effect this is just an
assembly function. */
void HardFault_Handler( void ) __attribute__( ( naked ) );

/* The fault handler implementation calls a function called
prvGetRegistersFromStack(). */
void HardFault_Handler(void)
{
    __asm volatile
    (
        " tst lr, #4                                                \n"
        " ite eq                                                    \n"
        " mrseq r0, msp                                             \n"
        " mrsne r0, psp                                             \n"
        " ldr r1, [r0, #24]                                         \n"
        " ldr r2, handler2_address_const                            \n"
        " bx r2                                                     \n"
        " handler2_address_const: .word prvGetRegistersFromStack    \n"
    );
}


void prvGetRegistersFromStack( uint32_t *pulFaultStackAddress )
{
/* These are volatile to try and prevent the compiler/linker optimising them
away as the variables never actually get used.  If the debugger won't show the
values of the variables, make them global my moving their declaration outside
of this function. */
volatile uint32_t r0;
volatile uint32_t r1;
volatile uint32_t r2;
volatile uint32_t r3;
volatile uint32_t r12;
volatile uint32_t lr; /* Link register. */
volatile uint32_t pc; /* Program counter. */
volatile uint32_t psr;/* Program status register. */

    r0 = pulFaultStackAddress[ 0 ];
    r1 = pulFaultStackAddress[ 1 ];
    r2 = pulFaultStackAddress[ 2 ];
    r3 = pulFaultStackAddress[ 3 ];

    r12 = pulFaultStackAddress[ 4 ];
    lr = pulFaultStackAddress[ 5 ];
    pc = pulFaultStackAddress[ 6 ];
    psr = pulFaultStackAddress[ 7 ];

    /* When the following line is hit, the variables contain the register values. */
    PRINTF("r0 = %d\r\n"
           "r1 = %d\r\n"
           "r2 = %d\r\n"
           "r3 = %d\r\n"
           "r12 = %d\r\n"
           "lr = %d\r\n"
           "pc = %d\r\n"
           "psr = %d\r\n",
           r0,r1,r2,r3,r12,lr,pc,psr);
    for( ;; );
}

#endif
// This is used by unity for output. The make file must pass a definition of the following form
// -DUNITY_OUTPUT_CHAR=unity_output_char
void unity_output_char(int c)
{
	PUTCHAR(c);
}


