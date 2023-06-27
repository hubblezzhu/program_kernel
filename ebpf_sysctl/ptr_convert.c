#include <stdio.h>
#include <stdint.h>

struct A {
    int i1;
    int i2;
    int i3;
};


int b[3] = {1, 2, 3};


int main()
{
    uint64_t addr = (uint64_t)b;

    printf("addr of b: %lx\n", addr);

    struct A *a = (struct A *)addr;

    a->i1 = 4;
    a->i2 = 5;
    a->i3 = 6;


    for (int i = 0; i < 3; i++)
    {
        printf("b[%d] = %d\n", i, b[i]);
    }

    return 0;
}