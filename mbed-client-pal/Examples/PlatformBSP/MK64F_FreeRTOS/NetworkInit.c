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
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/arch.h"
#include "lwip/api.h"
#include "lwip/tcpip.h"
#include "netif/etharp.h"
#include "lwip/dhcp.h"
#include "ethernetif.h"
#include "lwip/inet.h"


struct netif fsl_netif0;
ip_addr_t fsl_netif0_ipaddr, fsl_netif0_netmask, fsl_netif0_gw;

#ifndef NETWORK_BRINGUP
#define NETWORK_BRINGUP 1
#endif

bool dhcpDone = false;

#define configIP_ADDR0 0
#define configIP_ADDR1 0
#define configIP_ADDR2 0
#define configIP_ADDR3 0

/* Netmask configuration. */
#define configNET_MASK0 0
#define configNET_MASK1 0
#define configNET_MASK2 0
#define configNET_MASK3 0

/* Default gateway address configuration */
#define configGW_ADDR0 0
#define configGW_ADDR1 0
#define configGW_ADDR2 0
#define configGW_ADDR3 0

#ifndef HTTPD_STACKSIZE
#define HTTPD_STACKSIZE 3000
#endif

#ifndef HTTPD_DEBUG
#define HTTPD_DEBUG LWIP_DBG_ON
#endif


void networkInit(void *arg)
{
	PRINTF("%s : Starting HTTP thread! \r\n", __FUNCTION__);
	if (NETWORK_BRINGUP)
	{
		err_t err = 0;
		LWIP_UNUSED_ARG(arg);

		///// MAC
		fsl_netif0.hwaddr_len = 6;

		// Fetch word 0
		uint32_t word0 = *(uint32_t *)0x40048060;
		// Fetch word 1
		// we only want bottom 16 bits of word1 (MAC bits 32-47)
		// and bit 9 forced to 1, bit 8 forced to 0
		// Locally administered MAC, reduced conflicts
		// http://en.wikipedia.org/wiki/MAC_address
		uint32_t word1 = *(uint32_t *)0x4004805C;
		word1 |= 0x00000200;
		word1 &= 0x0000FEFF;

		fsl_netif0.hwaddr[0] = (word1 & 0x000000ff);
		fsl_netif0.hwaddr[1] = (word1 & 0x0000ff00) >> 8;
		fsl_netif0.hwaddr[2] = (word0 & 0xff000000) >> 24;
		fsl_netif0.hwaddr[3] = (word0 & 0x00ff0000) >> 16;
		fsl_netif0.hwaddr[4] = (word0 & 0x0000ff00) >> 8;
		fsl_netif0.hwaddr[5] = (word0 & 0x000000ff);
		////

		tcpip_init(NULL, NULL);
		LWIP_DEBUGF(HTTPD_DEBUG, ("TCP/IP initialized.\r\n"));
		IP4_ADDR(&fsl_netif0_ipaddr, configIP_ADDR0, configIP_ADDR1, configIP_ADDR2, configIP_ADDR3);
		IP4_ADDR(&fsl_netif0_netmask, configNET_MASK0, configNET_MASK1, configNET_MASK2, configNET_MASK3);
		IP4_ADDR(&fsl_netif0_gw, configGW_ADDR0, configGW_ADDR1, configGW_ADDR2, configGW_ADDR3);

		netif_add(&fsl_netif0, &fsl_netif0_ipaddr, &fsl_netif0_netmask, &fsl_netif0_gw, NULL, ethernetif_init, tcpip_input);
		netif_set_default(&fsl_netif0);

		PRINTF("%s : Starting DCHP request\r\n", __FUNCTION__);
		/* obtain the IP address, default gateway and subnet mask by using DHCP*/
		err = dhcp_start(&fsl_netif0);
		PRINTF("%s : Started DCHP request (%s)\r\n", __FUNCTION__, lwip_strerr(err));
		for(int i=0; i < 40 && fsl_netif0.dhcp->state != DHCP_BOUND; i++)
		{
			PRINTF("%s : Current DHCP State : %d\r\n", __FUNCTION__, fsl_netif0.dhcp->state);
			vTaskDelay(1000/portTICK_PERIOD_MS);
		}

		/**/
		PRINTF("%s : DHCP state, activating interface (%d)\r\n", __FUNCTION__,fsl_netif0.dhcp->state);
		if (fsl_netif0.dhcp->state != DHCP_BOUND)
		{
			PRINTF("%s : DHCP state, TIMEOUT (%d)\r\n", __FUNCTION__,fsl_netif0.dhcp->state);
		}

		LWIP_DEBUGF(HTTPD_DEBUG, ("http_server_netconn_thread: init interface START!"));
		netif_set_up(&fsl_netif0);
		LWIP_DEBUGF(HTTPD_DEBUG, ("http_server_netconn_thread: init interface END!"));

		PRINTF("%s : Interface is up : %d\r\n", __FUNCTION__, fsl_netif0.dhcp->state);
		PRINTF("%s : IP %s\r\n", __FUNCTION__, ipaddr_ntoa(&fsl_netif0.ip_addr));
		PRINTF("%s : NM %s\r\n", __FUNCTION__, ipaddr_ntoa(&fsl_netif0.netmask));
		PRINTF("%s : GW %s\r\n", __FUNCTION__, ipaddr_ntoa(&fsl_netif0.gw));
	}
	PRINTF("before run tests: \r\n");
	dhcpDone = true;

	vTaskDelete( NULL );

}

// Currently we support only one interface
void* palTestGetNetWorkInterfaceContext()
{
	return (void *)&fsl_netif0;
}






