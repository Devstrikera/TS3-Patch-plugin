# Some random notices

## General
## Windows specific
```
getaddrinfo(...) => return n > 0 | Cause blacklist abort
3.1.8 - 3.1.9 (was the latest)
Sign: \x4C\x8D\x4C\x24\x00\x4C\x8D\x45\x8F\x33\xD2\xFF\x15\x00\x00\x00\x00\x85\xC0\x0F\x85\x00\x00\x00\x00\x48\x8B\x44\x24\x00\x8B\x48\x04\x83\xF9\x17\x75\x05\x8D\x79\xEA\xEB\x0C
Mask: xxxx?xxxxxxxx????xxxx????xxxx?xxxxxxxxxxxxx

_hook_windows_x64_getaddrinfo_318:
    lea r9, [rsp+130h -0F8h]                   ; F8 = ppResult
    lea r8, [rbp+57h - 0C8h]                   ; C8 = pHints
    xor edx, edx                               ; pServiceName

```
### Windows x64
### Windows x32

## Linux specific
### Linux x64
### Linux x32