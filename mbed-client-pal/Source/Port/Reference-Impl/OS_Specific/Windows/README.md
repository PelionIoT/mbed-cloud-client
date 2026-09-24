# Windows PAL

Native Win32 x64 implementation of the existing PAL platform contracts.
The Edge Windows target selects this directory with `OS_BRAND=Windows` and
`MBED_CLOUD_CLIENT_DEVICE=x86_x64`. Link with `ws2_32`, `iphlpapi`, and `bcrypt`.

- RTOS uses `_beginthreadex`, Windows mutexes/semaphores, waitable timers and
  `GetTickCount64`. Threads release their resources on normal return or deferred
  cancellation at PAL waits. Timer callbacks are serialized per timer and may
  delete their own timer. Stop allows an already dispatched callback to finish;
  deletion from another thread drains it. Do not hold callback-owned locks when
  deleting a timer. As with other PAL ports, deleting an object concurrently
  with arbitrary API use requires synchronization by its owner.
- Entropy comes from `BCryptGenRandom` with the system-preferred RNG. Hardware
  RoT is unsupported; reuse PAL's generic SOTP implementation.
- Filesystem paths are UTF-8, converted to wide strings for Win32 APIs. File
  creation inherits directory ACLs. Writable files use write-through caching.
  Exclusive creation uses `CREATE_NEW`. Folder operations follow the documented
  flat PAL contract, preserve subdirectories, and reject reparse-point roots
  and file entries. They are not a replacement for storage-directory ACLs.
  `off_t` remains the PAL/MSVC 32-bit type; overflowing positions fail explicitly.
- Networking maps PAL's IPv6 family value to Winsock's different family value.
  Nonblocking socket callbacks use `WSAEventSelect` and one worker per socket;
  callbacks may close their own socket. External close waits for the callback
  worker to finish, so do not hold a callback-owned lock when closing. Default
  routing is supported; explicit adapter selection is a later addition.
- DNS API 0 and 1 use the Windows resolver, with API 1 reusing PAL's generic
  worker. This initial Edge profile enables TCP and server sockets.
- Host clock changes and volume formatting return errors. The reboot hook
  exits the application; it never requests a Windows host reboot.

The Edge repository's `test/windows-pal` suite compiles these sources and PAL's
generic RTOS, filesystem and networking layers. Run it from Edge with
`build-windows.ps1 -PalTests`. It needs no cloud account or external network.

Relevant native API semantics:
[Winsock event selection](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaeventselect)
and [waitable timers](https://learn.microsoft.com/en-us/windows/win32/sync/using-waitable-timer-objects).
