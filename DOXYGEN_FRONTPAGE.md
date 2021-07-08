# API documentation

This is the Doxygen-generated API documentation for Device Management Client.
Use it together with [Device Management documentation](../connecting/index.html).

Device Management Client allows developers to create client side applications that connect to **Device Management**, with features as described in the [Lightweight Machine to Machine Technical Specification](http://www.openmobilealliance.org/release/LightweightM2M/V1_0-20170208-A/OMA-TS-LightweightM2M-V1_0-20170208-A.pdf) (LwM2M).

These APIs enable you to:

- Manage devices.
- Securely communicate with internet services over the industry standard TLS/DTLS.
- Use factory-flashed or developer credentials to create a unique device identity.
- Fully control the endpoint and application logic from the service side.
- Update devices over-the-air remotely from the service side.
- Have a unified porting layer for porting to different platforms.

The C++ API allows quick application development.

## Device Management Client C++ API

Device Management Client C++ API is essentially constructed around following classes, their base classes and derivatives:

* MbedCloudClient.
* M2MInterface.
* M2MObject.
* M2MObjectInstance.
* M2MResource.
* M2MResourceInstance.

Device Management Client follows the architecture specified by LwM2M.
`M2MObject`, `M2MObjectInstance`, `M2MResource`, `M2MResourceInstance` are C++ classes that represent what LwM2M specifies as *Object*, *Object Instance*, *Resouce* and *Resource Instance*.

`M2MInterface` is the core *LwM2M client*, as it handles communication of all four interfaces specified by LwM2M.

`MbedCloudClient` is the main application interface that encapsulates `M2MInterface` and provides easier API for a developer.

The public API contains these header files:

* mbed-cloud-client/MbedCloudClient.h
* mbed-cloud-client/MbedCloudClientConfig.h
* mbed-cloud-client/MbedCloudClientConfigCheck.h
* mbed-cloud-client/est_defs.h
* mbed-client/mbed-client/coap_response.h
* mbed-client/mbed-client/functionpointer.h
* mbed-client/mbed-client/m2mbase.h
* mbed-client/mbed-client/m2mblockmessage.h
* mbed-client/mbed-client/m2mconfig.h
* mbed-client/mbed-client/m2mconstants.h
* mbed-client/mbed-client/m2mdevice.h
* mbed-client/mbed-client/m2mendpoint.h
* mbed-client/mbed-client/m2minterface.h
* mbed-client/mbed-client/m2minterfacefactory.h
* mbed-client/mbed-client/m2minterfaceobserver.h
* mbed-client/mbed-client/m2mobject.h
* mbed-client/mbed-client/m2mobjectinstance.h
* mbed-client/mbed-client/m2mresource.h
* mbed-client/mbed-client/m2mresourcebase.h
* mbed-client/mbed-client/m2mresourceinstance.h
* mbed-client/mbed-client/m2mstring.h
* mbed-client/mbed-client/m2mvector.h

## Application usage

This process shows how you can create a client-based application.

1. Create a `MbedCloudClient` object and register certain callbacks with it:

   ```.cpp
   MbedCloudClient client;
   client.on_registered(...);
   client.on_unregistered(...);
   client.on_error(...);
   ```

2. Define your own resources:

   ```.cpp
   M2MObjectList list;

   M2MObject *object = M2MInterfaceFactory::create_object(name);
   M2MObjectInstance* object_instance = object->create_object_instance(instance_id);
   M2MResource* resource = object_instance->create_dynamic_resource(name, resource_type, data_type, observable);

   resource->set_value((const unsigned char*)value, strlen(value));
   resource->set_operation(M2MBase::GET_PUT_ALLOWED);
   resource->set_message_delivery_status_cb(...);
   resource->set_value_updated_function((void(*)(const char*))cb);

   list->push_back(object);
   ```

3. Call `MbedCloudClient::add_objects()` to add LwM2M objects to the client:

   ```.cpp
   client.add_objects(_obj_list);
   ```

4. Give a platform-specific pointer to the client (it uses this as its network interface):

   ```.cpp
   client.setup(mcc_platform_get_network_interface());
   ```

  This initiates the client and starts its state machine.


The rest of the application logic works through various callbacks. A real life example would be more complex than this simplified view.
Please refer to any of the provided Device Management Client examples.

For API usage, refer to the class descriptions.
