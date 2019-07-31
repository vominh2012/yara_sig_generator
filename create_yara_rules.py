import sys
import time
import argparse
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32
from my_mkyara import YaraGenerator

def string_to_int(str):
    if str.startswith("0x"):
        return int(str, 16)
    else:
        return int(str, 10)

def read_address_file(file_path, addresses, default_code_size):
    f = open(file_path, "r")
    for x in f:
        arr = x.split(",")
        
        if len(arr) < 1:
            print("Invalid address file")
            exit(0)

        address = string_to_int(arr[0])
        code_size = default_code_size
        if len(arr) > 2:
            code_size = string_to_int(arr[1])

        func_name = ""
        if len(arr) > 2:
           func_name = arr[2].strip("\r").strip("\n")
        
        addresses.append([address, code_size, func_name])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--target", required=True,
        help="target execution module")
    ap.add_argument("-a", "--address", required=False,
        help="function address")
    ap.add_argument("-f", "--address_file", required=False,
        help="address file (each line format is address[,length,function_name]")
    ap.add_argument("-o", "--output", required=True,
        help="output yara rule")
    args = vars(ap.parse_args())

    DefaultCodeSize = 128

    addresses = [] # format of each item is [address, code_size, function_name]

    address_file = args["address_file"]
    address = args["address"]
    if address_file:
        address_file = address_file.strip()
        read_address_file(address_file, addresses, DefaultCodeSize)
    elif address:
        address = address.strip()
        addresses.append([string_to_int(address), DefaultCodeSize, ""])
    else:
        print("You must specify address/address file input")
        exit(0)

    start_time = time.time()

    file_path = args["target"].strip()
    pe        = pefile.PE(file_path)

    # The default for DLLs is 0x10000000, EXE is 0x400000
    ImageBase = 0x400000
    if (file_path.upper().endswith('.DLL')):
        ImageBase = 0x10000000


    codes = []
    count = 0

    MAX_NUMBER_FUNC = 20000
    MIN_CODE_SIZE = 64

    gen = YaraGenerator("loose", CS_ARCH_X86, CS_MODE_32)
    gen.do_comment_sig = False

    for section in pe.sections:
        if section.IMAGE_SCN_CNT_CODE == True or section.IMAGE_SCN_MEM_EXECUTE == True: # Only work on code sections
            for address_detail in addresses:
                code_address = address_detail[0] - ImageBase
                code_section_size = min(section.SizeOfRawData, address_detail[1])
                if code_section_size < MIN_CODE_SIZE:
                    continue # skip too small function
                code_section    = pe.sections[count].get_data(code_address, code_section_size)
                gen.add_chunk(code_section, 0, False, address_detail[2])
                if (len(codes) > MAX_NUMBER_FUNC):
                    break
        count += 1
        

    rule = gen.generate_rule()

    rule_str = rule.get_rule_string()

    print("execution time is %s" % (time.time() - start_time))

    # write rule to file
    if rule_str:
        f = open(args["output"].strip(), "w")
        f.write(rule_str)
        f.close()

if __name__== "__main__":
  main()
