#include <Windows.h>
#include "module.h"
#include <stdio.h>

#define ECB 0
#define CTR 0

#include "aes.h"

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
	printf("unsigned char %s[%d] = {", Name, Size);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
	  		printf("\n\t");
		
	if (i < Size - 1) {
		printf("0x%0.2x,", Data[i]);
	} else {
		printf("0x%0.2x", Data[i]);
	}
  }
  printf("};\n\n\n");
}

INT main(int argc, char** argv) {
	struct AES_ctx ctx;
	VOID* payload_buff = NULL; 
	HANDLE file;
	DWORD file_size;
	DWORD buff_size;

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

	file_size = GetFileSize(file, NULL);

	buff_size = file_size + 16 - (file_size % 16);

	payload_buff = VirtualAlloc(
		NULL,
		buff_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	ReadFile(file, payload_buff, file_size, NULL, NULL);

	AES_init_ctx_iv(&ctx, key_bytes, iv_bytes);

	AES_CBC_encrypt_buffer(&ctx, payload_buff, buff_size);

	PrintHexData("encrypted_payload", payload_buff, buff_size);

	return 0;
}