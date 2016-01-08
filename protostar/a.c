#include <stdio.h>

void main(){
	int a = 0xFFFFFFFF;
	printf("Reset a = 0xFFFFFFFF\n");
	printf("            %n", &a);
	printf("a: 0x%x\n", a);

	a = 0xFFFFFFFF;
	printf("Reset a = 0xFFFFFFFF\n");
	printf("            %hn\n", &a);
	printf("a: 0x%x\n", a);


	printf("Reset a = 0xFFFFFFFF\n");
	a = 0xFFFFFFFF;
	printf("            %hhn\n", &a);
	printf("a: 0x%x\n", a);
}
