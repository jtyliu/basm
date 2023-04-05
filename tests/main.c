#include <stdio.h>
int main(){
	int a, b;
	scanf("%d %d", &a, &b);
	printf("%d %d %d %d %d %d %d %d", a+3, a-7, a/2, a*3, a&4, a|3, a^2, a<b);
}