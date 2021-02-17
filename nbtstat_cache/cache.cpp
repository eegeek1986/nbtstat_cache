#include "cache.h"

RtlInitUnicodeString_fp MyRtlInitUnicodeString = NULL;
RtlGuidFromString_fp RtlGuidFromString = NULL;
NhGetInterfaceNameFromDeviceGuid_fp NhGetInterfaceNameFromDeviceGuid = NULL;
char g_scopeID[256] = { 0 };

void init()
{
	HMODULE ntdll = NULL;
	HMODULE iphlpapi = NULL;

	ntdll = LoadLibrary(L"ntdll");
	iphlpapi = LoadLibrary(L"Iphlpapi");

	if (ntdll == NULL)
	{
		wprintf(L"Unable to load ntdll.dll: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	if (iphlpapi == NULL)
	{
		wprintf(L"Unable to load iphlpapi.dll: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	MyRtlInitUnicodeString = (RtlInitUnicodeString_fp)GetProcAddress(ntdll, "RtlInitUnicodeString");
	RtlGuidFromString = (RtlGuidFromString_fp)GetProcAddress(ntdll, "RtlGUIDFromString");
	NhGetInterfaceNameFromDeviceGuid = (NhGetInterfaceNameFromDeviceGuid_fp)GetProcAddress(iphlpapi, "NhGetInterfaceNameFromDeviceGuid");

	if (MyRtlInitUnicodeString == NULL)
	{
		wprintf(L"Unable to get the address of RtlInitUnicodeString: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	if (RtlGuidFromString == NULL)
	{
		wprintf(L"Unable to get the address of RtlGUIDFromString: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	if (NhGetInterfaceNameFromDeviceGuid == NULL)
	{
		wprintf(L"Unable to get the address of NhGetInterfaceNameFromDeviceGuid: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	return;
}

void getScopeID()
{
	HKEY key = { 0 };
	LSTATUS lResult = 0;
	DWORD type = 0;
	DWORD bytes = 256;

	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"system\\currentcontrolset\\services\\netbt\\parameters", 0, KEY_READ, &key);

	if (lResult != ERROR_SUCCESS)
	{
		if (lResult == ERROR_FILE_NOT_FOUND) {
			wprintf(L"Key not found.\n");
			return;
		}
		else {
			wprintf(L"Error opening key.\n");
			return;
		}
	}

	lResult = RegQueryValueExW(key, L"ScopeId", NULL, &type, (LPBYTE)g_scopeID, &bytes);

	if (lResult != ERROR_SUCCESS)
	{
		//Return becuase this is normal and we just have an empty scope.
		if (lResult == ERROR_FILE_NOT_FOUND) {
			return;
		}
		else {
			wprintf(L"Error opening key.\n");
			return;
		}
	}
}

PADAPTERS getDeviceList()
{
	wchar_t device[] = L"\\\\?\\globalroot\\Device\\NetBt_Wins_Export";
	HANDLE deviceHandle = INVALID_HANDLE_VALUE;
	PADAPTERS devicesOutput = NULL;
	DWORD bytesReturned = 0;

	deviceHandle = CreateFileW(
		device,
		GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);


	if (deviceHandle == INVALID_HANDLE_VALUE)
	{
		wprintf(L"\t[-] Unable to open %s: 0x%x\n", device, GetLastError());
		return devicesOutput;
	}

	devicesOutput = (PADAPTERS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x32f4);

	if (devicesOutput == NULL)
	{
		wprintf(L"\t[-]Unable to allocate memory: %d\n", GetLastError());
		return devicesOutput;
	}

	DeviceIoControl(deviceHandle, GET_ADAPTER_LIST, NULL, 0, devicesOutput, 0x32f4, &bytesReturned, NULL);

	CloseHandle(deviceHandle);

	return devicesOutput;
}

void printDeviceInfo(PWCHAR dev)
{
	HANDLE dHandle = INVALID_HANDLE_VALUE;
	wchar_t fullDev[MAX_PATH] = L"\\\\?\\globalroot";
	PWCHAR guid = wcschr(dev, L'{');
	wcscat_s(fullDev, MAX_PATH - 28, dev);
	PVOID adapterInfo = NULL;
	wchar_t ipAddress[16] = { 0 };
	in_addr addr;
	GUID gu = { 0 };
	UNICODE_STRING guidString = { 0 };
	wchar_t deviceName[0x28b] = { 0 };
	ULONG size = 0x28b;
	DWORD bytesReturned = 0;

	MyRtlInitUnicodeString(&guidString, guid);
	RtlGuidFromString(&guidString, &gu);
	NhGetInterfaceNameFromDeviceGuid(&gu, deviceName, &size, 0, 1);

	dHandle = CreateFileW(
		fullDev,
		GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);


	if (dHandle == INVALID_HANDLE_VALUE)
	{
		wprintf(L"\t\t[-] Unable to open %s: 0x%x\n", fullDev, GetLastError());
		return;
	}

	adapterInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 260);

	if (adapterInfo == NULL)
	{
		wprintf(L"\t\t[-]Unable to allocate memory: %d\n", GetLastError());
		return;
	}

	DeviceIoControl(dHandle, GET_ADAPTER_INFO, NULL, 0, adapterInfo, 260, &bytesReturned, NULL);

	addr.S_un.S_addr = htonl(*(PLONG)adapterInfo);
	InetNtopW(AF_INET, (PVOID)&addr, ipAddress, 16);

	wprintf(L"%s:\n", deviceName);
	wprintf(L"Node IpAddress: [%s] ", ipAddress);
	wprintf(L"Scope Id: [%S]\n\n", g_scopeID);

	CloseHandle(dHandle);
	HeapFree(GetProcessHeap(), 0, adapterInfo);

}

void printDeviceCache(PWCHAR dev)
{
	HANDLE dHandle = INVALID_HANDLE_VALUE;
	wchar_t fullDev[MAX_PATH] = L"\\\\?\\globalroot";
	PWCHAR guid = wcschr(dev, L'{');
	wcscat_s(fullDev, MAX_PATH - 28, dev);
	PNBT_CACHE cacheInfo = NULL;
	DWORD bytesReturned = 0;

	dHandle = CreateFileW(
		fullDev,
		GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);


	if (dHandle == INVALID_HANDLE_VALUE)
	{
		wprintf(L"\t\t[-] Unable to open %s: 0x%x\n", fullDev, GetLastError());
		return;
	}

	cacheInfo = (PNBT_CACHE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x600);

	if (cacheInfo == NULL)
	{
		wprintf(L"\t\t[-]Unable to allocate memory: %d\n", GetLastError());
		return;
	}

	DeviceIoControl(dHandle, GET_ADAPTER_CACHE, NULL, 0, cacheInfo, 0x600, &bytesReturned, NULL);

	PCACHE_ENTRY cacheEntry = (PCACHE_ENTRY)cacheInfo->firstEntry;

	if (cacheInfo->numEntries == 0)
	{
		wprintf(L"    No names in cache\n\n");
	}
	else
	{
		wprintf(L"                  NetBIOS Remote Cache Name Table\n\n");
		wprintf(L"        Name              Type       Host Address    Life [sec]\n");
		wprintf(L"    ------------------------------------------------------------\n");
		for (int i = 0; i < cacheInfo->numEntries; i++, cacheEntry++)
		{
			char name[16] = { 0 };
			in_addr raddr = { 0 };
			wchar_t ripAddress[16] = { 0 };

			memcpy(name, cacheEntry->NbtName, 15);
			raddr.S_un.S_addr = htonl(cacheEntry->ipAddr);
			InetNtopW(AF_INET, (PVOID)&raddr, ripAddress, 16);

			wprintf(L"    %S<%02x>  ", name, cacheEntry->lastByte);
			if (-1 < cacheEntry->type)
			{
				wprintf(L"UNIQUE          ");
			}
			else
			{
				wprintf(L"GROUP          ");
			}
			wprintf(L"%s          %d\n", ripAddress, cacheEntry->life);

		}
		wprintf(L"\n");
	}
	CloseHandle(dHandle);
	HeapFree(GetProcessHeap(), 0, cacheInfo);
	return;
}

void queryDeviceName(PWCHAR dev, PWCHAR name)
{
	HANDLE dHandle = INVALID_HANDLE_VALUE;
	wchar_t fullDev[MAX_PATH] = L"\\\\?\\globalroot";
	PWCHAR guid = wcschr(dev, L'{');
	wcscat_s(fullDev, MAX_PATH - 28, dev);
	PNBT_QUERY queryInfo = NULL;
	DWORD bytesReturned = 0;

	dHandle = CreateFileW(
		fullDev,
		GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);


	if (dHandle == INVALID_HANDLE_VALUE)
	{
		wprintf(L"\t\t[-] Unable to open %s: 0x%x\n", fullDev, GetLastError());
		return;
	}

	queryInfo = (PNBT_QUERY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x600);

	if (queryInfo == NULL)
	{
		wprintf(L"\t\t[-]Unable to allocate memory: %d\n", GetLastError());
		return;
	}

	PWTF_STRUCT wtfStruct = (PWTF_STRUCT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WTF_STRUCT));
	wtfStruct->address = 0;
	wtfStruct->unknown = 1;
	wtfStruct->unknown2 = 0x110012;
	
	size_t size = 0;
	wcstombs_s(&size, wtfStruct->name, 18, name, 15);

	if (!DeviceIoControl(dHandle, QUERY_IP_ADDRESS, wtfStruct, 0x20, queryInfo, 0x600, &bytesReturned, NULL))
	{
		DWORD error = GetLastError();
		if (error == 0x79)
		{
			wprintf(L"    Host not found.\n\n");
		}
		else
		{
			wprintf(L"    Error: 0x%X\n", error);
		}
	}
	else
	{
		PQUERY_ENTRY queryEntry = (PQUERY_ENTRY)queryInfo->firstEntry;
		wprintf(L"           NetBIOS Remote Machine Name Table\n\n");
		wprintf(L"       Name               Type         Status\n");
		wprintf(L"    ---------------------------------------------\n");
		for (int i = 0; i < queryInfo->numEntries; i++, queryEntry++)
		{
			char name[16] = { 0 };

			memcpy(name, queryEntry->NbtName, 15);

			wprintf(L"    %S<%02x>  ", name, queryEntry->lastByte);
			if (-1 < queryEntry->type)
			{
				wprintf(L"UNIQUE        ");
			}
			else
			{
				wprintf(L"GROUP         ");
			}

			char status = queryEntry->type & 0xf;
			if (status == 0)
			{
				wprintf(L"Registering\n");
			}
			else if (status == 4)
			{
				wprintf(L"Registered\n");
			}
			else if (status == 5)
			{
				wprintf(L"Deregistered\n");
			}
			else if (status == 6)
			{
				wprintf(L"Conflict\n");
			}
			else if (status == 7)
			{
				wprintf(L"Conflict-Deregistered\n");
			}
			else
			{
				wprintf(L"??\n");
			}
		}
		wprintf(L"\n");
	}
	CloseHandle(dHandle);
	HeapFree(GetProcessHeap(), 0, queryInfo);
	HeapFree(GetProcessHeap(), 0, wtfStruct);
	return;
}

void queryDeviceIP(PWCHAR dev, PWCHAR ipString)
{
	HANDLE dHandle = INVALID_HANDLE_VALUE;
	wchar_t fullDev[MAX_PATH] = L"\\\\?\\globalroot";
	PWCHAR guid = wcschr(dev, L'{');
	wcscat_s(fullDev, MAX_PATH - 28, dev);
	PNBT_QUERY queryInfo = NULL;
	DWORD bytesReturned = 0;

	dHandle = CreateFileW(
		fullDev,
		GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);


	if (dHandle == INVALID_HANDLE_VALUE)
	{
		wprintf(L"\t\t[-] Unable to open %s: 0x%x\n", fullDev, GetLastError());
		return;
	}

	queryInfo = (PNBT_QUERY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x600);

	if (queryInfo == NULL)
	{
		wprintf(L"\t\t[-]Unable to allocate memory: %d\n", GetLastError());
		return;
	}

	PWTF_STRUCT wtfStruct = (PWTF_STRUCT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WTF_STRUCT));
	IN_ADDR ipAddres = { 0 };
	InetPtonW(AF_INET, ipString, &ipAddres);
	wtfStruct->address = ntohl(ipAddres.S_un.S_addr);
	wtfStruct->unknown = 1;
	wtfStruct->unknown2 = 0x110012;
	wtfStruct->name[0] = 0x2a;

	if (!DeviceIoControl(dHandle, QUERY_IP_ADDRESS, wtfStruct, 0x20, queryInfo, 0x600, &bytesReturned, NULL))
	{
		DWORD error = GetLastError();
		if (error == 0x79)
		{
			wprintf(L"    Host not found.\n\n");
		} 
		else
		{
			wprintf(L"    Error: 0x%X\n", error);
		}
	}
	else
	{
		PQUERY_ENTRY queryEntry = (PQUERY_ENTRY)queryInfo->firstEntry;
		wprintf(L"           NetBIOS Remote Machine Name Table\n\n");
		wprintf(L"       Name               Type         Status\n");
		wprintf(L"    ---------------------------------------------\n");
		for (int i = 0; i < queryInfo->numEntries; i++, queryEntry++)
		{
			char name[16] = { 0 };

			memcpy(name, queryEntry->NbtName, 15);
			
			wprintf(L"    %S<%02x>  ", name, queryEntry->lastByte);
			if (-1 < queryEntry->type)
			{
				wprintf(L"UNIQUE        ");
			}
			else
			{
				wprintf(L"GROUP         ");
			}

			char status = queryEntry->type & 0xf;
			if (status == 0)
			{
				wprintf(L"Registering\n");
			}
			else if (status == 4)
			{
				wprintf(L"Registered\n");
			}
			else if (status == 5)
			{
				wprintf(L"Deregistered\n");
			}
			else if (status == 6)
			{
				wprintf(L"Conflict\n");
			}
			else if (status == 7)
			{
				wprintf(L"Conflict-Deregistered\n");
			}
			else
			{
				wprintf(L"??\n");
			}
		}
		wprintf(L"\n");
	}
	CloseHandle(dHandle);
	HeapFree(GetProcessHeap(), 0, queryInfo);
	HeapFree(GetProcessHeap(), 0, wtfStruct);
	return;
}

int wmain(int argc, wchar_t* argv[])
{

	PADAPTERS devicesOutput = NULL;
	int numDevices = 0;

	init();
	getScopeID();

	devicesOutput = getDeviceList();

	if (devicesOutput == NULL)
	{
		exit(EXIT_FAILURE);
	}

	numDevices = devicesOutput->numberOfDevices;

	PADAPTER_NAME name = (PADAPTER_NAME)devicesOutput->firstEntry;

	if (argc == 2 && argv[1][0] == L'-' && argv[1][1] == L'c')
	{

		for (int i = 0; i < numDevices; i++, name++)
		{
			printDeviceInfo(name->name);
			printDeviceCache(name->name);

		}

	}
	else if (argc == 3 && argv[1][0] == L'-' && argv[1][1] == L'A')
	{

		for (int i = 0; i < numDevices; i++, name++)
		{
			printDeviceInfo(name->name);
			queryDeviceIP(name->name, argv[2]);

		}
		
	}
	else if (argc == 3 && argv[1][0] == L'-' && argv[1][1] == L'a')
	{

		for (int i = 0; i < numDevices; i++, name++)
		{
			printDeviceInfo(name->name);
			queryDeviceName(name->name, argv[2]);

		}

	}
	else 
	{
		wprintf(L"unknown option\n");
	}

	HeapFree(GetProcessHeap, 0, devicesOutput);

}