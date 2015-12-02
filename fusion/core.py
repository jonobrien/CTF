#!/usr/bin/python
import socket
import struct

def alphabet(nIntegers):
    data = ""
    cur_val = "A"
    for _ in range(nIntegers):
        data += cur_val*4
        cur_val = chr(ord(cur_val)+1)
    return data

def pack_le(packme):
    return struct.pack("<I", packme)

def rx_until(fd, delim):
    rxd = ""
    while True:
        rxd += fd.recv(1)
        if rxd[-1] == delim:
            break
    return rxd 

def attach(ip, port, wait=True):
    fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fd.connect((ip, port))
    if not wait:
        return fd
    print "Please attach debugger to spawned process now. (Press any key)"
    raw_input()
    return fd
