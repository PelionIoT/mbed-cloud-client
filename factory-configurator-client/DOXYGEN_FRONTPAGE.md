Factory Configurator Client API
===============================

This is the Doxygen generated documentation of Factory Configurator Client (FCC) and Key and Configuration Manager (KCM).
It should be used together with the [Mbed Cloud documentation](https://cloud.mbed.com/docs/latest). See the [Files](files.html) section to find documentation about a specific API.

## FCC

The FCC APIs initialize the factory flow, store the factory configurations using KCM APIs or FCC bundle handler and
verify that the device is ready for mbed Cloud connection.
 
The FCC APIs allow the following operations:

- Initiating and finalizing of the FCC flow. 
- After items injection, verifying that the device is ready for Mbed Cloud connection.
- Retrieving errors and warnings during the injection process.
- Cleaning all data that was injected to the device.

In developer mode, you do not need to use the Factory Configurator Utility (FCU).

## FCC bundle handler

The FCC bundle handler processes the bundle (in CBOR format) created by Factory Client Utility (FCU) and transferred to the device by the Factory Tool. The device creates a response CBOR message with status and warning details and sends it back to the Factory Tool and the FCU. During the processing, the device stores all relevant factory configuration data to the device's storage.

## KCM

The KCM APIs store parameters, keys and certificates (items) in the device's secure storage and allows other applications (customer or mbed) to access these parameters. 

The KCM APIs allow the following operations on items:

 - Verification and storing items into a secure storage.
 - Retrieving the item data size from the secure storage.
 - Retrieving item data from the secure storage.
 - Deleting items from the secure storage.
