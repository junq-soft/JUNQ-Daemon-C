#include <stdio.h>

void log_error(char * info)
{
    printf("\033[0;31m[%s]\033[0m -- \033[0;36m%s\033[0m\n","ERROR",  info);
    fflush(stdout);
    perror("");
}

void log_debug(char * info){
    printf("\033[0;33m[%s]\033[0m -- \033[0;36m%s\033[0m\n","DEBUG",  info);
    fflush(stdout);
}