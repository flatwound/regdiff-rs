# Regdiff CLI tool
Small cli tool to get a diff of registry after making a change, usefull for capturing settings from policies etc.
Currently only supports REG_DWORD and REG_SZ values and the HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER hives

## Usage:
    regdiff --hkcu
    limits capturing regvalues from HKCU only
    regsdiff --hklm
    limits capturing revalues from HKLM only
    regdiff --hkcu --subkey Console
    limits capturing regvalues from HKCU\Console only
## TODO:
- Add other keys such as HKU, HKCR, HKCC
- Add support for other registry types
- Code review
