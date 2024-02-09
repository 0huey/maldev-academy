#include <Windows.h>
#include <stdio.h>
#include <rpcdce.h>

INT main(INT argc, PSTR* argv) {
	HANDLE file = INVALID_HANDLE_VALUE;
	DWORD buff_size;
	BYTE* payload_buff = NULL;
	BYTE* pbuff = NULL;
	UUID* uuid_bytes = NULL;

	if (argc != 2) {
		return 1;
	}

	file = CreateFileA(
		argv[1],
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (file == INVALID_HANDLE_VALUE) {
		return 2;
	}

	buff_size = GetFileSize(file, NULL);

	if (buff_size % 16 != 0) {
		//pad buffer size to 16 bytes
		buff_size += 16 - (buff_size % 16);
	}

	payload_buff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buff_size);

	ReadFile(file, payload_buff, buff_size, NULL, NULL);

	CloseHandle(file);
	file = INVALID_HANDLE_VALUE;

	pbuff = payload_buff;

	puts("PCSTR uuid_payload[] = {");

	while (pbuff < payload_buff + buff_size) {
		uuid_bytes = (UUID*)pbuff;

		printf("\t\"%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\",\n",
			uuid_bytes->Data1,
			uuid_bytes->Data2,
			uuid_bytes->Data3,
			uuid_bytes->Data4[0],
			uuid_bytes->Data4[1],
			uuid_bytes->Data4[2],
			uuid_bytes->Data4[3],
			uuid_bytes->Data4[4],
			uuid_bytes->Data4[5],
			uuid_bytes->Data4[6],
			uuid_bytes->Data4[7]
		);

		pbuff += sizeof(UUID);
	}

	puts("};");

	return 0;
}
