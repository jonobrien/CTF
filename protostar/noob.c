#include <stdio.h>


int main(int argc, char **argv) 
{
    int nub = 0;
    void *cool = malloc(1024);

    memcpy(cool, "omg", 4);
    printf("%s\n", cool);

    printf(argv[1]);
    return 0;
}
