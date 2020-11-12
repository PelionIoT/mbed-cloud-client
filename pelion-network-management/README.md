# Pelion Network Management

## Introduction

The Pelion Network Management module manages the network interfaces of a Wi-SUN device. It also handles all the configurations and statistics resources related to a Wi-SUN network. It is designed to be integrated with the Pelion Border Router and the Device Management Client example application.

## Block diagram

Pelion Network Management communicates with other modules of a Border router or Router application:

![](images/block_diagram.png)

## Configurations

The Pelion Network Management module supports both Wi-SUN Border router and Wi-SUN router application. To select the device type, define the `"mbed-mesh-api.wisun-device-type"` parameter of the `.json` file as `"MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER"` or `"MESH_DEVICE_TYPE_WISUN_ROUTER"`.

## Supported resources

The list of supported resources and corresponding parameters are listed below.

|Resource Path | Resources | Parameters | Supported in Device Type |
|--------------|-----------|------------|--------------------------|
|33455/0/1   | Wi-SUN Common Configuration<br> (Get & Put Allowed) | Resource Version | Both Node & BR|
||                                        | Configuration Delay                    ||
||                                        | Channel Mask                           ||
||                                        | Regulatory Domain                      ||
||                                        | Operating Class                        ||
||                                        | Operating Mode                         ||
||                                        | Network Size                           ||
||                                        | Unicast Channel Function               ||
||                                        | Unicast Fixed Channel                  ||
||                                        | Unicast Dwell Interval                 ||
||                                        | Broadcast Channel Function             ||
||                                        | Broadcast Fixed Channel                ||
||                                        | Broadcast Dwell Interval               ||
||                                        | Broadcast Interval                     ||
||                                        | Disc Trickle Imin                      ||
||                                        | Disc Trickle Imax                      ||
||                                        | Disc Trickle Constant                  ||
||                                        | Pan Timeout                            ||
||                                        | Device Minimum Sensitivity             ||
||                                        |                                        ||
|33455/0/2   | Wi-SUN Border Router Configuration<br>(Get & Put Allowed) | Resource Version    | BR Only |
||                                        | Configuration Delay                    ||
||                                        | Network Name                           ||
||                                        | PAN ID                                 ||
||                                        | DIO Interval Min                       ||
||                                        | DIO Interval Doubling                  ||
||                                        | DIO Redundancy Constant                ||
||                                        |                                        ||
|33455/0/3 | Device Information<br>(Only Get Allowed) | NS Heap Sector Size     | Both Node & BR |
||                                        | NS Heap Sector Allocation Count        ||
||                                        | NS Heap Sector Allocated Bytes         ||
||                                        | NS Heap Sector Allocated Bytes Max     ||
||                                        | NS Heap Allocation Fail Count          ||
||                                        | CPU Up Time                            ||
||                                        | CPU Idle Time                          ||
||                                        | CPU Sleep Time                         ||
||                                        | CPU Deep Sleep Time                    ||
||                                        | Mbed Heap Current Size                 ||
||                                        | Mbed Heap Max Size                     ||
||                                        | Mbed Heap Total Size                   ||
||                                        | Mbed Heap Reserved Size                ||
||                                        | Mbed Heap Allocation Count             ||
||                                        | Mbed Heap Allocation Fail Count        ||
||                                        |                                        ||
|33455/0/4 | General Network Information<br>(Only Get Allowed) | MAC Rx Count   | Both Node & BR |
||                                        | MAC Tx Count                           ||
||                                        | MAC Broadcast Rx Count                 ||
||                                        | MAC Broadcast Tx Count                 ||
||                                        | MAC Tx Bytes                           ||
||                                        | MAC Rx Bytes                           ||
||                                        | MAC Tx Fail Count                      ||
||                                        | MAC Retry Count                        ||
||                                        | MAC CCA Attempt Count                  ||
||                                        | MAC Failed CCA Count                   ||
||                                        |                                        ||
|33455/0/5   | Wi-SUN Common Information<br> (Only Get Allowed) | Resource Version | Both Node & BR |
||                                        | Global Address                         ||
||                                        | Link Local Address                     ||
||                                        | RPL DODAG ID                           ||
||                                        | RPL Instance ID                        ||
||                                        | RPL Version Number                     ||
||                                        | RPL Total Memory                       ||
||                                        | Asynch Tx Count                        ||
||                                        | Asynch Rx Count                        ||
||                                        |                                        ||
|33455/0/6 | Wi-SUN Border Router Information<br>(Only Get Allowed) | Resource Version | BR Only |
||                                        | Host Time                              ||
||                                        | Joined Device Count                    ||
||                                        | Northbound Global Address              ||
||                                        | Northbound Link Local Address          ||
||                                        |                                        ||
|33455/0/7 | Wi-SUN Node Information<br>(Only Get Allowed) | Resource Version | Node Only |
||                                        | RPL Current Rank                       ||
||                                        | RPL Primary Parent Rank                ||
||                                        | RPL Parent Address                     ||
||                                        | 1st Parent ETX                         ||
||                                        | 2nd Parent ETX                         ||
||                                        |                                        ||
|33455/0/8 | Radio Quality<br>(Only Get Allowed)    | Resource Version | Node Only |
||                                        | RSSI In                                ||
||                                        | RSSI Out                               ||
|33455/0/9 | Wi-SUN Routing Table<br>(Only Get Allowed) | Target IID & Parent IID for each entry | BR Only |
||                                        |                                        ||
|33455/0/10 | Channel Noise<br>(Only Get Allowed) | Table of CCA level for each Channel | Both Node & BR |

## Resource handling

All the resource data is handled in CBOR format.

### Setting data in Device Management Portal

With the **Wi-SUN Border Router Configuration** resource:

1. Fill in the data in JSON format:

    ```
    {
        "nw_name": "Wi-SUN Test Network", 
        "br_ver": 1, 
        "dio_interval_min": 15, 
        "dio_interval_doublings": 5, 
        "dio_redundancy_constant": 10, 
        "pan_id": 65535
    }
    ```
    
2. CBORize the data:

    ```
    A6676E775F6E616D657357692D53554E2054657374204E6574776F726B6662725F766572017064696F5F696E74657276616C5F6D696E0F7664696F5F696E74657276616C5F646F75626C696E6773057764696F5F726564756E64616E63795F636F6E7374616E740A6670616E5F696419FFFF
    ```
    
3. Convert from HEX to ASCII (Optional: Since the [Device Management Portal](https://portal.mbedcloud.com/) only accepts ASCII string).
```
¦gnw_namesWi-SUN Test Networkfbr_verpdio_interval_minvdio_interval_doublingswdio_redundancy_constant
fpan_idÿÿ
```

4. Put the string into the resource.


### Getting values of any resource 

With **Wi-SUN Common Configuration** resource:

1. Get the data from the resource (ASCII format in case of reading from [Device Management Portal](https://portal.mbedcloud.com/)):

    ```
    ±fws_vergch_maskÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿjreg_domainãhop_classâgop_modeãgnw_sizeèguc_funcàfuc_fixhuc_dwelløÿgbc_funcàfbc_fixhbc_dwelløÿkbc_intervalültrickle_iminltrickle_imaxÀmtrickle_constákpan_timeout
    ```

2. Convert from ASCII to HEX:

    ```
    b16677735f766572016763685f6d61736b881affffffff1affffffff1affffffff1affffffff1affffffff1affffffff1affffffff1affffffff6a7265675f646f6d61696ee3686f705f636c617373e2676f705f6d6f6465e3676e775f73697a65e86775635f66756e63e06675635f666978181e6875635f6477656c6cf8ff6762635f66756e63e06662635f666978181e6862635f6477656c6cf8ff6b62635f696e74657276616c1903fc6c747269636b6c655f696d696e181e6c747269636b6c655f696d61781903c06d747269636b6c655f636f6e7374e16b70616e5f74696d656f7574190f00
    ```

3. De-CBORize the HEX stream:

    ```
    {
        "ws_ver": 1, 
        "ch_mask": [4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295], 
        "reg_domain": 3, 
        "op_class": 2, 
        "op_mode": 3, 
        "nw_size": 8, 
        "uc_func": 0, 
        "uc_fix": 30, 
        "uc_dwell": 255, 
        "bc_func": 0, 
        "bc_fix": 30, 
        "bc_dwell": 255, 
        "bc_interval": 1020, 
        "trickle_imin": 30, 
        "trickle_imax": 960, 
        "trickle_const": 1, 
        "pan_timeout": 3840
    }
    ```

4. Data is ready in JSON format.
