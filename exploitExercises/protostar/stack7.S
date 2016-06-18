.intel_syntax noprefix  ; / Make crushr mad by turning on intel syntax




        xor eax, eax;
        add al, 4
        //mov eax, 4     ; // system calls in eax
        jmp cool       ;

yes:
        nop;
        xor ebx, ebx;
        inc ebx;
        //mov ebx, 1      ;// fd -> stdout
        pop ecx         ;// get the string pushed on by call
        xor edx, edx;
        mov dl, 6;
        //mov edx, 6      ;// length of ascii string

        int 0x80        ;// interrupt 80 sys call

cool:
        call yes        ;// push on string, goto yes
        .ascii "BOOOOM" ;// string winnnn

