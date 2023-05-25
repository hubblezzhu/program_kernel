#include <stdio.h>
#include <string.h>

long tcp_mem[3] = {33519, 44692, 67038};

long tmp_tcp_mem[3] = {0, 0, 0};

int main()
{
    printf("tcp_mem addr: %lx\n", tcp_mem);
    printf("tmp_tcp_mem addr: %lx\n", tmp_tcp_mem);

    memcpy(tmp_tcp_mem, tcp_mem, sizeof(long) * 3);

    printf("tmp_tcp_mem 0: %d\n", tmp_tcp_mem[0]);
    printf("tmp_tcp_mem 1: %d\n", tmp_tcp_mem[1]);
    printf("tmp_tcp_mem 2: %d\n", tmp_tcp_mem[2]);

    return 0;
}