#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <unistd.h>

#include "include/log.h"
#include "include/types.h"

void jexit(int status){
    printf("exit with status \'%d\' \n", status);
    exit(status);
}


int bytes_to_int(unsigned char *buf, int start, int end)
{
    int res = 0;
    for (int i=start; i < end; i++){
        res = (res << 8) + buf[i];
    }
    return res;
}


// char *int_to_bytes(unsigned long, int n)
// {
//     for (int i=0; i < n; i++)
// }
