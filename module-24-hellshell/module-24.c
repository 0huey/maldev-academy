#include <Windows.h>
#include <stdio.h>
#include <ip2string.h>
#include <Ip2string.h>
#include <Mstcpip.h>

void PayloadToMAC(BYTE* payload, DWORD len);
void PayloadToIPv4(BYTE* payload, DWORD len);

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <payload> <obfuscation type>\n", argv[0]);
        puts("Obfuscation Type can be one of:");
        puts("\tmac");
        puts("\tipv4");
        puts("\tipv6");
        puts("\tuuid");
        puts("\taes");
        puts("\trc4");
        return 1;
    }

    HANDLE file = CreateFileA(
		argv[1],
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

    if (file == INVALID_HANDLE_VALUE) {
        printf("Could not open file %s", argv[1]);
		return 2;
	}

    DWORD buff_size = GetFileSize(file, NULL);
    BYTE* shellcode = malloc(buff_size);
    ReadFile(file, shellcode, buff_size, NULL, NULL);
    CloseHandle(file);

    if (strcmp(argv[2], "mac") == 0) {
        PayloadToMAC(shellcode, buff_size);
    }
    else if (strcmp(argv[2], "ipv4") == 0) {
        PayloadToIPv4(shellcode, buff_size);
    }
    else if (strcmp(argv[2], "ipv6") == 0) {
        //PayloadToIPv6(shellcode, buff_size);
    }
    else if (strcmp(argv[2], "uuid") == 0) {
        //PayloadToUUID(shellcode, buff_size);
    }
    else if (strcmp(argv[2], "aes") == 0) {
        //PayloadToAES(shellcode, buff_size);
    }
    else if (strcmp(argv[2], "rc4") == 0) {
        //PayloadToRC4(shellcode, buff_size);
    }
    else {
        printf("invalid option: %s\n", argv[2]);
        return 3;
    }

    return 0;
}

#define MAC_SIZE 6
void PayloadToMAC(BYTE* payload, DWORD len) {
    CHAR buff[32];

    puts("PCSTR mac_payload[] = {");

    while (len >= MAC_SIZE) {
        RtlEthernetAddressToStringA((DL_EUI48*)payload, buff);
        printf("\"%s\"\n", buff);
        payload += MAC_SIZE;
        len -= MAC_SIZE;
    }

    if (len > 0 && len <= MAC_SIZE) {
        BYTE leftover[MAC_SIZE] = {0};
        memcpy(leftover, payload, len);
        RtlEthernetAddressToStringA((DL_EUI48*)leftover, buff);
        printf("\"%s\"\n", buff);
    }

    puts("};");
    puts("#define MAC_SIZE 6");
    puts("#define payload_array_len sizeof(mac_payload) / sizeof(PCSTR)");
    puts("#define payload_size payload_array_len * MAC_SIZE");
    puts("void* decode_payload(void) {\n"
            "BYTE* decode = malloc(payload_size);\n"
            "BYTE* output = decode;\n"
            "PCSTR dummy;\n"
            "for (int i = 0; i < payload_array_len; i++) {\n"
                "RtlEthernetStringToAddressA(mac_payload[i], &dummy, (DL_EUI48)decode);\n"
                "decode += MAC_SIZE;\n"
            "}\n"
            "return output;\n"
        "}\n");
}

#define IPV4_SIZE 4
void PayloadToIPv4(BYTE* payload, DWORD len) {
    CHAR buff[32];

    puts("PCSTR ipv4_payload[] = {");

    while (len >= IPV4_SIZE) {
        RtlIpv4AddressToStringA((struct in_addr*)payload, buff);
        printf("\"%s\"\n", buff);
        payload += IPV4_SIZE;
        len -= IPV4_SIZE;
    }

    if (len > 0 && len <= IPV4_SIZE) {
        BYTE leftover[IPV4_SIZE] = {0};
        memcpy(leftover, payload, len);
        RtlIpv4AddressToStringA((struct in_addr*)leftover, buff);
        printf("\"%s\"\n", buff);
    }

    puts("};");
}
