/* Copyright (c) 2021 Pelion
 * Copyright (c) 2022 Izuma Networks
 * SPDX-License-Identifier: Apache-2.0
 */

 #include "FlashIAP.h"
 #include "FlashMap.h"
 
 /* Zephyr 3.6 headers for devicetree + flash map */
 #include <zephyr/devicetree.h>
 #include <zephyr/storage/flash_map.h>
 
 /*******************************************************************************
  * Implementation
  ******************************************************************************/
 
 namespace mbed {
 
 /*
  * Prefer a node *label* (DT_NODELABEL) you control in the overlay.
  * Example overlay nodes:
  *
  *   izuma_partition: partition@fa000 { label = "izuma_storage"; ... };
  *   storage:         partition@...   { label = "storage";        ... };
  *
  * We key off the *node label* (izuma_partition / storage), not the "label" string.
  */
 
 #if DT_NODE_EXISTS(DT_NODELABEL(izuma_partition))
 /* Use: izuma_partition: partition@... { ... }; */
 static izuma::FlashMap flash(FIXED_PARTITION_ID(izuma_partition));
 
 #elif DT_NODE_EXISTS(DT_NODELABEL(storage)) && !IS_ENABLED(CONFIG_SETTINGS)
 /* Only use the generic 'storage' partition if the Zephyr settings subsystem isn't using it. */
 static izuma::FlashMap flash(FIXED_PARTITION_ID(storage));
 
 #else
 #error "Missing izuma_partition (node label) for storing credentials/settings; add it in your overlay"
 #endif
 
 int FlashIAP::init()                   { return flash.init(); }
 int FlashIAP::deinit()                 { return flash.deinit(); }
 int FlashIAP::read(void *b, uint32_t a, uint32_t s)   { return flash.read(b, a, s); }
 int FlashIAP::program(const void *b, uint32_t a, uint32_t s) { return flash.program(b, a, s); }
 int FlashIAP::erase(uint32_t a, uint32_t s)           { return flash.erase(a, s); }
 uint32_t FlashIAP::get_page_size() const              { return flash.get_page_size(); }
 uint32_t FlashIAP::get_sector_size(uint32_t a) const  { return flash.get_sector_size(a); }
 uint32_t FlashIAP::get_flash_start() const            { return flash.get_flash_start(); }
 uint32_t FlashIAP::get_flash_size() const             { return flash.get_flash_size(); }
 uint8_t  FlashIAP::get_erase_value() const            { return flash.get_erase_value(); }
 
 } // namespace mbed
 