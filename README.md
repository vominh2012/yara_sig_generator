"# yara_sig_generator" 

usage: create_yara_rules.py [-h] -t TARGET [-a ADDRESS] [-f ADDRESS_FILE] -o
                            OUTPUT
							
Examples:
 - create_yara_rules.py -t notepad.exe -a 0x576580 -o notepad_sig.yara
 - create_yara_rules.py -t notepad.exe -f notepad_offset.txt -o notepad_sig.yara
	
Notes:
- Work well on both Python 2.7 & 3.7
- address file, each line format is address[,length, function_name]

Depends:
- https://github.com/fox-it/mkYARA (I modified and use customize one for performance reason)
- https://github.com/aquynh/capstone
