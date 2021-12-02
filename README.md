# Regdiff CLI tool
Small cli tool to get a diff of registry after making a change, usefull for capturing settings from policies etc.


## Usage:
    regdiff --hkcu
    limits capturing regvalues from HKCU only
    regsdiff --hklm
    limits capturing revalues from HKLM only
    regdiff --hkcu --subkey Console
    limits capturing regvalues from HKCU\Console only
## TODO:
- Storing snapshot in vector/struct
- Diff functionality
- Refactor and make a tolerable code_base
- Lot's of other stuff
