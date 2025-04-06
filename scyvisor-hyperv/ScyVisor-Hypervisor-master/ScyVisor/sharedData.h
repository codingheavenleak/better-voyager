#pragma once


typedef struct _MapperContext
{
	unsigned char DriverData[1 * 1024 * 1024L]; // size -> 1MB

}MapperContext, * PMapperContext;


extern MapperContext g_MapperContext;
