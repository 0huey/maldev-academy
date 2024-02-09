obfuscate malicous payload as UUIDs

Went with a custom UUID decode with sscanf because it was annoying to figure out the typing in Win32 functions `UuidFromStringA` and `CLSIDFromString`

generated exec calc.exe payload with
`.\msfvenom.bat -p windows/x64/exec CMD=calc.exe -f raw -o calc-payload.bin`

the shellcode payload doesn't have to be 16 byte aligned; the `payload-to-uuid` program can handle padding.
