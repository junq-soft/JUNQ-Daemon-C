#include "include/ygg_proxy_lib.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>

int ygg_proxy_init_cnct(int sock)
{
    char fbuf[3] = {5,1,0};
    send(sock, fbuf, 3, 0);

    char fabuf[2];
    recv(sock, fabuf, 2, 0);

    if (fabuf[0]!=5 || fabuf[1]!=0)
    {
        return 1;
    }
    return 0;
}

int ygg_proxy_connect_r(int sock, char *addr, short port)
{
    // char sraddr[16];
    short srport;

    int r;

    // r = inet_pton(AF_INET6,addr,sraddr);
    // if (r <= 0)
    // {
    //     return -1;
    // }
    srport = htons(port);

    char sbuf[22];
    sbuf[0] = 5;
    sbuf[1] = 1;
    sbuf[2] = 0;
    sbuf[3] = 4;
    for (int i=0; i < 16; i++)
    {
        sbuf[4+i] = addr[i];
    }
    sbuf[4+16] = ((char *)&srport)[0];
    sbuf[4+17] = ((char *)&srport)[1];

    send(sock, sbuf, 22, 0);
    
    char sabuf[2];
    recv(sock, sabuf, 22, 0);
    if (sabuf[1]!=0)
    {
        return 1;
    }
    return 0;
}