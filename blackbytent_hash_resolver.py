## IDA Python Script to resolve APIs in BlackByteNT samples
## Created by Cluster25
## Tested on sample SHA256: 02a0a39dbe0dcb5600f4179aeab457bb86965699e45d1d154082b02139dc701d
## Prerequisites: 
##  - Offset of the function used to resolve the APIs (in the analyzed sample it is sub_140001DF0)
##  - Must run on Windows to have access to the list of DLLs in the System32 directory

import idautils
import pefile

# Offset of function used to resolve the APIs (may vary in other samples)
r_offset = 0x0000000140001DF0

# Initial hash value in the used hashing algorithm (may vary in other samples)
hash_init = 0x99 

# List of DLLs dynamically loaded by BlackByteNT
modules = [
"C:\\Windows\\System32\\kernel32.dll", 
"C:\\Windows\\System32\\ntdll.dll", 
"C:\\Windows\\System32\\advapi32.dll", 
"C:\\Windows\\System32\\user32.dll", 
"C:\\Windows\\System32\\shell32.dll", 
"C:\\Windows\\System32\\rstrtmgr.dll", 
"C:\\Windows\\System32\\netapi32.dll", 
"C:\\Windows\\System32\\shlwapi.dll", 
"C:\\Windows\\System32\\mpr.dll",
"C:\\Windows\\System32\\psapi.dll", 
"C:\\Windows\\System32\\ole32.dll", 
"C:\\Windows\\System32\\OleAut32.dll", 
"C:\\Windows\\System32\\version.dll", 
"C:\\Windows\\System32\\Winhttp.dll", 
"C:\\Windows\\System32\\IPHLPAPI.dll", 
"C:\\Windows\\System32\\Ws2_32.dll", 
"C:\\Windows\\System32\\Dbghelp.dll"]
         
# Returns the hash of the input string
def get_hash(name):
    name_b = bytearray()
    name_b.extend(map(ord, name))
    hash_string = hash_init
    for i in range(len(name_b)):
        hash_string = name_b[i] + hash_string*3
    return hex(hash_string)
    
# Receives an hash and returns the corresponding function name
def find_api_name(hash_tofind):
    for dll_path in modules:
        pe = pefile.PE(dll_path)
        # Get hash of all the exported functions in the DLL
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols: 
            if exp.name:
                api_name = exp.name.decode()
                api_hash = get_hash(api_name)
                if api_hash == hash_tofind:
                    return api_name
    return None
    
# Adds a comment with the name of the function to be resolved near each call to the resolver function 
def resolve_apis(resolver_offset):
    # Retrieves all the Xrefs to the resolver function
    for xref in idautils.XrefsTo(resolver_offset):
        # Searches backword for the hash passed as input to the resolver function (second argument)
        # Starts at the offset preceding the call to the resolver function
        off = idc.prev_head(xref.frm)
        for i in range(1, 101): 
            if i == 100: 
                # Limit to 100 searches to avoid infinite loops
                print ("Hash not found for address: %s" % hex(xref.frm))
                break
            # Gets the type of operation (must be a MOV)    
            operation = idc.print_insn_mnem(off) 
            # Gets first operand (must be EDX or RDX to be the second argument passed to the function)
            first_operand = idc.print_operand(off, 0)
            # If the instruction is not MOV [R-E]DX, ??? proceedes backword with the search
            if not (operation == "mov" and (first_operand == "edx" or first_operand == "rdx")):
                off = idc.prev_head(off) 
                continue
            # Gets the hash value passed as input to the function    
            api_hash = idc.print_operand(off, 1) 
            # Removes the "h" character in the string representation of the Hex value and converts the result to Hex
            api_hash = hex(int(api_hash[:-1], 16))
            # Finds the function name corresponding to the Hash            
            api_name = find_api_name(api_hash) 
            # Adds a comment near the function invocation with the name of the function to be resolved ("unknown" otherwise)
            comment = "Unknown Function" if not api_name else api_name
            idc.set_cmt(xref.frm, comment, True) 
            break

def main(resolver_function):
    resolve_apis(resolver_function)

main(r_offset)