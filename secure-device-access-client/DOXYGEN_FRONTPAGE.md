# Secure Device Access client API

This is the Doxygen-generated documentation for the Secure Device Access (SDA) client API. See the [Files](files.html) section to review documentation for specific APIs.

See the [Secure Device Access documentation](https://www.pelion.com/docs/device-management/current/device-management/how-sda-works.html) for information about how Secure Device Access works.

## Integrating the Secure Device Access client API into your device application

Secure Device Access enables policy-based access control for IoT devices. It allows you to control who can access an IoT device, and which operations they can perform on the device. An Mbed device that supports Secure Device Access can validate permissions even when it is offline (not connected to Device Management).

To use Secure Device Access, your device application must call the Secure Device Access client APIs as follows:

1. Initialize Secure Device Access using `sda_init()`.
1. Read a message from the transport medium.
1. Process the message from the transport medium using `sda_operation_process()`:

    1. The API returns a result status and a prepared response message. If the message type is `SDA_OPERATION_FUNC_CALL`, the API calls the device application callback and passes it the operation handle with the verified and parsed payload.
    1. The device application callback must perform a number of steps to determine what the requested operation is and whether it is permitted:
        1. Determine the command type using `sda_command_type_get()`. We currently only support operation (also called function) call commands (`SDA_OPERATION_FUNC_CALL`).
        1. Get the operation name using `sda_func_call_name_get()`.
        1. Get the operation call parameters using `sda_func_call_numeric_parameter_get()` or `sda_func_call_data_parameter_get()`, depending on the operation.
        1. Get the list of scopes permitted by the access token using `sda_scope_get_next()`.
        1. Verify that the list of scopes matches the requested operation.
        1. Perform the operation (in the application-specific manner) only if the verification is successful.

        <span class="notes">**Note:** Your device application callback will have its own commands that are entirely specific to your application and IoT device.</span>

1. Send the response message over the transport medium to the SDA application, even if `sda_operation_process` failed with an error.
1. Finalize Secure Device Access using `sda_finalize()`.
