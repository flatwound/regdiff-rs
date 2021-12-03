# Regdiff CLI tool
Small cli tool to get a diff of registry after making a change, useful for capturing settings from policies etc.
Currently only supports REG_DWORD and REG_SZ values and the HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER hives

```
regdiff.exe --hkcu --subkey Test
Scanning HKLM is disabled
Scanning HKCU is enabled
Processing HKEY_CURRENT_USER\Test
Snapshot saved, please make the modifications and press ENTER...

Processing HKEY_CURRENT_USER\test
===================
Values added:
===================
[HKEY_CURRENT_USER\Test]
"added_value"=""
[HKEY_CURRENT_USER\Test\added_key]
"added_key_value"="yes"
===================
Values removed:
===================
===================
Values changed:
===================
```

## Usage:
    regdiff --hkcu
    limits capturing regvalues from HKCU only
    regsdiff --hklm
    limits capturing revalues from HKLM only
    regdiff --hkcu --subkey Console
    limits capturing regvalues from HKCU\Console only
## TODO:
- Logic to detect removed keys
- Add other keys such as HKU, HKCR, HKCC
- Add support for other registry types
- Code review
