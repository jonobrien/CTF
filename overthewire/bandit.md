# [BANDIT](http://overthewire.org/wargames/bandit/)

## level 0
ssh into bandit.labs.overthewire.org username: bandit0, password: bandit0
open the readme and use that string as password for username: bandit1
```bash
cat readme
```

## level 1
ssh into bandit1 and open the file `-`
```bash
$ cat ./-
```

## level 2
ssh into bandit2 and open the file `spaces in this filename`
- tab complete the name from the command line, or escape the spaces
```bash
$ cat spaces\ in\ this\ filename
```

## level 3
ssh into bandit3 and open the `.hidden` file in the `inhere` directory
```bash
$ cat .hidden
```

## level 4
ssh into bandit4 and open the only human-readable file in the `inhere` directory
```bash
$ file ./-*
$ cat ./-<human-readable-file>
```

## level


## level
