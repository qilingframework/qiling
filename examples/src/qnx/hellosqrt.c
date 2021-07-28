#include <math.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	double a = atan(1.0);
	double b = sin(a);
	double c = 1.0 / b;
	printf("hello, sqrt(2) = %lf\n", c);
	return 0;
}
