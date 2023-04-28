# BlackByteNT_HashResolver
IDA Python Script to resolve APIs in BlackByteNT samples

Tested on sample SHA256: 02a0a39dbe0dcb5600f4179aeab457bb86965699e45d1d154082b02139dc701d

## Prerequisites
- Offset of the function used to resolve the APIs (in the analyzed sample `sub_140001DF0`)
- Must run on Windows to have access to the list of DLLs in the System32 directory

## Usage
- Set the value of the variable `r_offset` to the offset of the function used to resolve the APIs in the analyzed sample (default value `0x0000000140001DF0`)
- Run the script in IDA Pro
