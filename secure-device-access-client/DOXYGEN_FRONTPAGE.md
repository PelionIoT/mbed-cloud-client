# Secure Device Access client API

This is the Doxygen-generated documentation for the Secure Device Access (SDA) client API. See the [Files](files.html) section to review documentation for specific APIs.

See the [Secure Device Access documentation](https://www.pelion.com/docs/device-management/latest/sda/index.html) for information about how Secure Device Access works.

## Integrating the Secure Device Access client API into your device application

Secure Device Access enables policy-based access control for IoT devices. It allows you to control who can access an IoT device, and which operations they can perform on the device. An Mbed device that supports Secure Device Access can validate permissions even when it is offline (not connected to Device Management).

To use Secure Device Access, your device application must call the Secure Device Access client APIs as follows:

-# Initialize Secure Device Access using `sda_init()`.
-# Read a message from the transport medium.
-# Process the message from the transport medium using `sda_operation_process()`:

    -# The API returns a result status and a prepared response message. If the message type is `SDA_OPERATION_FUNC_CALL`, the API calls the device application callback and passes it the operation handle with the verified and parsed payload.
    -# The device application callback must perform a number of steps to determine what the requested operation is and whether it is permitted:
        -# Determine the command type using `sda_command_type_get()`. We currently only support operation (also called function) call commands (`SDA_OPERATION_FUNC_CALL`).
        -# Get the operation name using `sda_func_call_name_get()`.
        -# Get the operation call parameters using `sda_func_call_numeric_parameter_get()` or `sda_func_call_data_parameter_get()`, depending on the operation.
        -# Get the list of scopes permitted by the access token using `sda_scope_get_next()`.
        -# Verify that the list of scopes matches the requested operation.
        -# Perform the operation (in the application-specific manner) only if the verification is successful.

        \note Your device application callback will have its own commands that are entirely specific to your application and IoT device.

-# Send the response message over the transport medium to the SDA application, even if `sda_operation_process` failed with an error.
-# Finalize Secure Device Access using `sda_finalize()`.
