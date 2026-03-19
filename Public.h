/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_BEBypasssys,
    0x1ccb2a83,0x288e,0x4a83,0xb1,0x67,0x6f,0x69,0xd0,0x65,0x91,0x44);
// {1ccb2a83-288e-4a83-b167-6f69d0659144}
