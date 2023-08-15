#include <iostream>
#include <Windows.h>
#include <string>

#include "common.h"
#include "../user/um/ummanager.h"

int main(int argc, char* argv[])
{
	if ( argc == 1 )
	{
		LOG_INFO( "No target process passed, terminating" );
		return ERROR;
	}

	UserMode::Manager um_manager( argv[1]);

}