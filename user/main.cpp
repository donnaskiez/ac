#include <iostream>
#include <Windows.h>
#include <string>

#include "common.h"

#include "../user/um/threadpool.h"
#include "../user/um/manager.h"

void TestFunction()
{

}

int main(int argc, char* argv[])
{
	//if ( argc == 1 )
	//{
	//	LOG_INFO( "No target process passed, terminating" );
	//	return ERROR;
	//}

	usermode::Manager manager( "notepad.exe" );
	manager.ValidateProcessThreads();


	while ( 1 )
	{

	}
}