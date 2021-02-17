#ifndef CACHE_H
#define CACHE_H

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <winternl.h>
#include <winioctl.h>

#pragma comment(lib,"Ws2_32.lib")

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_TRANSPORT, Function, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define GET_ADAPTER_LIST                         IOCTL(0x035)
#define GET_ADAPTER_INFO                         IOCTL(0x029)
#define GET_ADAPTER_CACHE                        IOCTL(0x021)
#define QUERY_IP_ADDRESS                         IOCTL(0x02B)


typedef struct _WTF_STRUCT
{
	long address;
	long unknown;
	long unknown2;
	char reserved[2];
	char name[18];
}WTF_STRUCT, * PWTF_STRUCT;

typedef struct _ADAPTERS
{
	int numberOfDevices;
	char reserved[4];
	char firstEntry[1];
}ADAPTERS, * PADAPTERS;

typedef struct _ADAPTER_NAME
{
	wchar_t name[652];
}ADAPTER_NAME, * PADAPTER_NAME;

typedef struct _CACHE_ENTRY
{
	char NbtName[15];
	char lastByte;
	char reserved[2];
	char type;
	char reserved2;
	long ipAddr;
	int life;
}CACHE_ENTRY, * PCACHE_ENTRY;

typedef struct _NBT_CACHE
{
	char reserved[0x3a];
	short numEntries;
	char firstEntry[1];
}NBT_CACHE, * PNBT_CACHE;

typedef struct _QUERY_ENTRY
{
	char NbtName[15];
	char lastByte;
	char reserved[1];
	char type;
}QUERY_ENTRY, * PQUERY_ENTRY;

typedef struct _NBT_QUERY
{
	char reserved[0x3a];
	short numEntries;
	char firstEntry[1];
}NBT_QUERY, * PNBT_QUERY;

typedef void (*RtlInitUnicodeString_fp)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(*RtlGuidFromString_fp)(PUNICODE_STRING, GUID*);
typedef DWORD(*NhGetInterfaceNameFromDeviceGuid_fp)(GUID*, PWCHAR, PULONG, DWORD, DWORD);

#endif