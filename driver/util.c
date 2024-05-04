#include "common.h"

LARGE_INTEGER 
GenerateRandSeed()
{
    LARGE_INTEGER system_time = {0};
    LARGE_INTEGER up_time     = {0};
    LARGE_INTEGER seed        = {0};

    KeQuerySystemTime(&system_time);
    KeQueryTickCount(&up_time);

    seed.QuadPart = system_time.QuadPart ^ up_time.QuadPart;
    return seed;
}