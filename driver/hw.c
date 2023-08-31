#include "common.h"

/*
* Stuff we can get:
* 
* 1. CPU ID
* 2. motherboard serial number
* 3. MAC address,
* 4. NIC
*/

typedef struct _HARDWARE_INFORMATION
{
	CHAR cpu_id[0x20];
	CHAR motherboard_serial[0x20];
	CHAR mac_address[0x20];
};

