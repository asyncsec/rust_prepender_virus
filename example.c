#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void main() {
	srand(time(0));

	int fav_number;
	int my_fav_number = rand();

	printf("Hello!  I'm a binary that does nothing!\n");
	printf("Well, what's your favorite number?: ");
	scanf("%d", &fav_number);
	printf("Oh, cool!  Mine is: %d\n", my_fav_number);
	printf("Bye!\n");

}
