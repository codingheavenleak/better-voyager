#pragma once
#include "Utils.h"





// Map PE image (expand section, fix relocation table, fix import table)
VOID MapPeImage(VOID* PeFilePtr, VOID* PeMemPtr, VOID* KernelOsPtr);
