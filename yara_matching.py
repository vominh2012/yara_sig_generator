import sys
import yara
import pefile
import argparse

def read_entire_file_bin(filename):
    file = open(filename,mode='rb')
    all_of_it = file.read()
    file.close()
    return all_of_it
 
def get_va_address(pe, file_offset):
    for s in pe.sections:
        if s.contains_offset(file_offset):
            return int(s.get_rva_from_offset(file_offset) + pe.OPTIONAL_HEADER.ImageBase)
    return 0

ap = argparse.ArgumentParser()
ap.add_argument("-r", "--yara_rule_file", required=True,
    help="yara rule")
ap.add_argument("-t", "--target", required=True,
    help="taget file")
ap.add_argument("-o", "--output", required=True,
    help="output matching result")
args = vars(ap.parse_args())

rule = yara.compile(filepath=args["yara_rule_file"].strip())

binary_path = args["target"].strip()
pe =  pefile.PE(binary_path)

matches = rule.match(binary_path)

f = open(args["output"].strip(), "w")
out_contents = ""
for match in matches:
    prev_line = ("","", "")
    skip = False # skip multiple match string
    for line in match.strings:
        if prev_line[1] != line[1]:
            if not skip and prev_line[1]:
                out_contents += hex(get_va_address(pe, prev_line[0]))  + " " + prev_line[1] + "\n"
            skip = False
        else:
            skip = True
        prev_line = line
    if not skip and prev_line[1]:
       out_contents += hex(get_va_address(pe, prev_line[0]))  + " " + prev_line[1] + "\n"
       
# write result to file
f.write(out_contents)
f.close()
