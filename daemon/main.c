#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>


#include "include/cJSON.h"
#include "include/log.h"
#include "include/types.h"
#include "include/tools.h"
#include "include/ygg_proxy_lib.h"


void end()
{
    free(pfds);
    jexit(0);
}

void send_ok(int i)
{
    char buf[] = {255,255, 255, 255};
    send(pfds[i].fd,buf,sizeof(buf),0);
}

void send_err(int i)
{
    char buf[] = {255,255,255,0};
    send(pfds[i].fd, buf,sizeof(buf), 0);
}


static inline void _ctrlc_handler(int sig)
{
    char  c;
    signal(sig, SIG_IGN);
    running = 0;
    printf("%s\n","");
}

int reg(int sock, int events)
{
    if (nsocks >= config.max_connections)
    {
        // какая нибудь функция которая будет смотреть на последнюю активность других подключений
        log_error("reg :: max_connections :: Limit of connections");
        return 1;
    }
    nsocks++;
    pfds = realloc(pfds, sizeof(struct pollfd)*nsocks);
    

    if (pfds == NULL){
        log_error("reg :: realloc pfds :: err");
        jexit(ERR_REALLOC);
    }

    pfds[nsocks-1].fd = sock;
    pfds[nsocks-1].events = events;
    pfds[nsocks-1].revents = 0;
    if (nsocks > n_users)
    {
        clients = realloc(clients, sizeof(struct client_s)*(nsocks-n_users));
        clients[(nsocks - n_users)-1].step = 0;
        clients[(nsocks - n_users)-1].auth = 0;
        clients[(nsocks - n_users)-1].dest_yggs = 0;
    }
    
    log_debug("client_connected");
    char buf[100];
    sprintf(buf,"nsocks: %d", nsocks);
    log_debug(buf);

    return 0;
}
int unreg(int i)
{
    nsocks--;
    shutdown(pfds[i].fd, SHUT_RDWR);
    if (pfds[i].fd != pfds[nsocks].fd){

        pfds[i].fd = pfds[nsocks].fd;
        pfds[i].events = pfds[nsocks].events;

        // strcpy(clients[i].addr, clients[nsocks].addr);
        if (nsocks > n_users+1)
        {
            clients[i-n_users].addr = clients[nsocks-n_users].addr;
            clients[i-n_users].step = clients[nsocks-n_users].step;
            clients[i-n_users].dest_yggs = clients[nsocks-n_users].dest_yggs;
        }
        

    }

    pfds = realloc(pfds, sizeof(struct pollfd)*nsocks);
    if (nsocks >= n_users)
    {
        clients = realloc(clients, sizeof(struct client_s)*(nsocks-n_users));
    }
    
    log_debug("client disconnected");

    char buf[100];
    sprintf(buf,"nsocks: %d", nsocks);
    log_debug(buf);
    return 0;
}


void create_tcp()
{
    int sock;
    struct sockaddr_in sock_addr , osocks_addr;

    for (int i = 0; i < n_users; i++)
    {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            log_error("create_tcp :: socket :: Сan\'t create a socket");
            jexit(ERR_CREATE_SERVER_SOCKET);
        }
        if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) {
            log_error("create_tcp :: setsockopt :: Can\'t set socket option");
            jexit(ERR_CREATE_SERVER_SETSOCKOPT);
        }


        sock_addr.sin_family = AF_INET;
        inet_pton(AF_INET, config.listen, &sock_addr.sin_addr);
        sock_addr.sin_port = htons(jusers[i].socket_port);

        if (bind(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0)
        {
            printf("%s %d\n", config.listen, config.port);
            log_error("create_tcp :: bind :: Can\'t bind socket");
            jexit(ERR_CREATE_SERVER_BIND);
        }

        if (listen(sock, 0) < 0)
        {
            log_error("create_tcp :: listen :: Can\'t set socket as listening");
            jexit(ERR_CREATE_SERVER_LISTEN);
        }

        reg(sock, POLLIN);
        n_host_socks++;
    }
    
}

void create_server()
{
    create_tcp();
    // create_unix();
}

int crecv(int i, char *buf, size_t n, int flags)
{
    int r = recv(pfds[i].fd,buf,n,flags);
    if (r <= 0)
    {
        unreg(i);
    }
    return r;
}

void handle_connection(int i)
{
    int sock = accept(pfds[i].fd, NULL,NULL);
    if (sock < 0)
    {
        log_error("handle_connection :: accept :: Сan\'t accept a client");
        jexit(ERR_ACCEPT_CLIENT);
    }
    log_debug("client connected");
    reg(sock, POLLIN);
    clients[(nsocks-n_users)-1].dest_yggs = i;
}

int ygg_check(int i, int msg_size)
{
    printf("%s\n", "ygg chck");
    if (msg_size == 16)
    {
        printf("%s\n", "mb ygg");
        char str_addr[INET6_ADDRSTRLEN];
        int r = crecv(i,(char *)&clients[i-n_users].addr.sin6_addr,msg_size,0);
        if (r <= 0){return 0;}
        log_debug("yggdrasil connect");
        clients[i-n_users].addr.sin6_family = AF_INET6;
        inet_ntop(AF_INET6, (char *)&clients[i-n_users].addr.sin6_addr, str_addr, INET6_ADDRSTRLEN);
        log_debug(str_addr);
        printf("%d", *(int*)&clients[i-n_users].addr.sin6_addr);
        send_ok(i);
        return 1;
    }
    else {
        char buf[msg_size];
        int r = crecv(i, buf, msg_size, 0);
        if (r <= 0){return 0;}
        log_debug("normal connect");
        char str_addr[INET6_ADDRSTRLEN];
        
        socklen_t addrlen;
        getpeername(pfds[i].fd, (struct sockaddr*)&clients[i-n_users].addr, &addrlen);
        getpeername(pfds[i].fd, (struct sockaddr*)&clients[i-n_users].addr, &addrlen);
        inet_ntop(AF_INET6, &clients[i-n_users].addr.sin6_addr, str_addr, INET6_ADDRSTRLEN);

        log_debug(str_addr);
        send_ok(i);
        return 1;
    }

    return 0;
}


void login(int i, int msg_size)
{

    
    char buf[msg_size];
    int login_s;
    int passw_s;
    
    int r = crecv(i, buf, msg_size, 0);
    if (r != msg_size || r == 0)
    {
        send_err(i);
        return;
    }

    login_s = bytes_to_int((unsigned char*)buf, 0, BYTES_LOGIN_LEN);
    passw_s = bytes_to_int((unsigned char*)buf, BYTES_LOGIN_LEN+login_s, BYTES_LOGIN_LEN+login_s+BYTES_PASSWORD_LEN);
    
    short ygg_dst = clients[i-n_users].dest_yggs;
    
    if (login_s == strlen(jusers[ygg_dst].login) && passw_s == strlen(jusers[ygg_dst].password) &&  BYTES_LOGIN_LEN+login_s+BYTES_PASSWORD_LEN < msg_size)
    {
        char login_b[login_s+1];
        char passw_b[passw_s+1];
        

        strncpy(login_b, buf+BYTES_LOGIN_LEN,login_s);
        strncpy(passw_b, buf+BYTES_LOGIN_LEN+login_s+BYTES_PASSWORD_LEN, passw_s);
        strcpy(&login_b[login_s], "\0");
        strcpy(&passw_b[passw_s],"\0");

        // printf("%s:%s | %s|%s", login_b, jusers[j].login, passw_b, jusers[j].password);

        if (strcmp(login_b, jusers[ygg_dst].login) == 0 && strcmp(passw_b, jusers[ygg_dst].password) == 0)
        {
            log_debug("login succes");
            clients[i-n_users].auth = 1;
            send_ok(i);
            return;
        }

    }
    send_err(i);
}


void write_msg_l(int i, int msg_size)
{
    char buf[msg_size];
    // int login_s;
    int msg_s;
    int lid;
    short dest_yggs;
    
    int r = crecv(i, buf, msg_size, 0);
    if (r != msg_size | r == 0)
    {
        send_err(i);
        return;
    }

    // login_s = bytes_to_int((unsigned char*)buf, 0, BYTES_LOGIN_LEN);
    // msg_s = bytes_to_int((unsigned char *)buf, BYTES_LOGIN_LEN+login_s, BYTES_LOGIN_LEN+login_s+BYTES_TEXT_LEN);
    msg_s = bytes_to_int((unsigned char*)buf, 0, BYTES_TEXT_LEN);
    dest_yggs = clients[i-n_users].dest_yggs;
    if (BYTES_TEXT_LEN+msg_s == msg_size) 
    {
        printf("%s\n", "write local message");
        char msg_b[msg_s+1];

        strncpy(msg_b, buf+BYTES_TEXT_LEN, msg_s);
        strcpy(&msg_b[msg_s],"\0");

        lid = jusers[dest_yggs].current_id%SAVED_MESSAGES_N;

        log_debug(msg_b);

        jusers[dest_yggs].messages[lid].id = jusers[dest_yggs].current_id;
        strcpy(jusers[dest_yggs].messages[lid].msg, msg_b);
        // strcpy(jusers[j].messages[lid].recipient, login_b);
        jusers[dest_yggs].messages[lid].sender_addr = clients[i-n_users].addr.sin6_addr;
        jusers[dest_yggs].messages[lid].time = (unsigned long)time(NULL);
        log_debug("wm");
        jusers[dest_yggs].current_id++;
        send_ok(i);
        return;
    }
}



void get_messages(int i, int msg_size)
{
    
    char buf[msg_size];
    unsigned short count;
    unsigned int offset;
    unsigned int id;

    int r = crecv(i, buf, msg_size, 0);
    if (r != msg_size || r == 0)
    {
        send_err(i);
        return;
    }

    count = bytes_to_int((unsigned char *)buf, 0, 2);
    offset = bytes_to_int((unsigned char *)buf, 2, 6);

    short user_id = clients[i-n_users].dest_yggs;
    // if ((jusers[user_id].current_id - SAVED_MESSAGES_N) <= (int)offset)
    if (offset <= jusers[user_id].current_id)
    {
        char msg[MAX_MESSAGE_LEN];
        struct in6_addr sender_addr;
        char rbuf[sizeof(struct message)];


        int last;
        int msize;
        int mlen;
        
        if (offset+count < jusers[user_id].current_id)
        {
            last = count;

        } else 
        {
            last = jusers[user_id].current_id-offset;
            
        }
        send_ok(i);
        send(pfds[i].fd, &last, BYTES_NUM,0);
        for (int j = 0; j < last; j++)
        {
            rbuf[0] = '\0';

            id = (offset+j)%SAVED_MESSAGES_N;

            
            strcpy(msg, jusers[user_id].messages[id].msg);
            sender_addr = jusers[user_id].messages[id].sender_addr;
            // recipient = jusers[user_id].messages[lid].recipient;

            strncat(rbuf, msg, strlen(msg));
            strcat(rbuf, "\0");


            mlen = strlen(rbuf);
            msize = mlen + BYTES_TEXT_LEN + sizeof(sender_addr)+sizeof(jusers[user_id].messages[id].time)+sizeof(jusers[user_id].messages[id].id);

            send(pfds[i].fd, &msize, BYTES_MSG_LEN,0);                  // all msg size
            send(pfds[i].fd, &mlen, BYTES_TEXT_LEN,0);                          // text size
            send(pfds[i].fd, rbuf, mlen,0);                                     // text
            send(pfds[i].fd, &sender_addr, sizeof(sender_addr), 0);             // sender addr
            send(pfds[i].fd, &jusers[user_id].messages[id].time,sizeof(jusers[user_id].messages[id].time),0);           // time
            send(pfds[i].fd, &jusers[user_id].messages[id].id,sizeof(jusers[user_id].messages[id].id),0);               // id
            
        }
    } else {
        send_err(i);
    }

    return;
}

// int ygg_proxy_check(int ssock)
// {
//     char fbuf[3] = {5,1,0};
//     send(ssock, fbuf, 3, 0);

//     char fabuf[2];
//     recv(ssock, fabuf, 2, 0);

//     if (fabuf[0]!=5 || fabuf[1]!=0)
//     {
//         return 1;
//     }

//     return 0;
// }

// int ygg_proxy_r_connect(int sock, char *addr)
// {



//     return 0;
// }

// 21e:e795:8e82:a9e2:ff48:952d:55f2:f0bb
void write_msg_r(int i, int msg_size)
{
    char buf[msg_size];
    int csock = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(csock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    int r = crecv(i, buf, msg_size, 0);
    if (r != msg_size || r == 0 || clients[i-n_users].auth != 1)
    {
        log_debug("write_msg_r::crecv not logined or wrong len");
        send_err(i);
        return;
    }

    struct sockaddr_in raddr;
    raddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    // inet_pton(AF_INET, "127.0.0.1", &raddr.sin_addr);
    raddr.sin_port = htons(jusers[clients[i-n_users].dest_yggs].ygg_proxy_port);
    raddr.sin_family = AF_INET;

    r = connect(csock, (struct sockaddr *)&raddr, sizeof(raddr));
    if (r != 0)
    {
        // log_error("write")
        printf("%d %d\n", r, raddr.sin_port);
        log_debug("cant connect to ygg proxy");
        send_err(i);
        close(csock);
        return; 
    }

    // r = ygg_proxy_check(csock);
    r = ygg_proxy_init_cnct(csock);
    if (r != 0)
    {
        log_debug("proxy err");
        send_err(i);
        close(csock);
        return;
    }
    r = ygg_proxy_connect_r(csock, buf, 1109);
    if (r != 0){
        log_debug("ygg proxy remote err");
        send_err(i);
        close(csock);
        return;
    }

    char msg_s[3];
    msg_s[0] = ((msg_size-16) >> 16) & 0xFF;
    msg_s[1] = ((msg_size-16) >> 8) & 0xFF;
    msg_s[2] = ((msg_size-16)& 0xFF)+1;

    printf("%d\n", bytes_to_int(msg_s, 0, sizeof(msg_s)));

    char cmd = {1};

    send(csock, msg_s, 3, 0);
    send(csock, &cmd, 1,0);
    send(csock, (char *)(buf+16), (msg_size-16), 0);

    unsigned char ret[4];
    recv(csock, ret, 4, 0);
    if (ret[3] != 255)
    {
        send_err(i);
    } else {
        send_ok(i);
    }
    
    close(csock);
    return;
}

void handle_data(int i)
{
    char buf[BYTES_MSG_LEN];
    int n1,n2;
    n1 = crecv(i, buf, BYTES_MSG_LEN, 0);
    if (n1 <= 0) {return;}
    int msg_size = bytes_to_int((unsigned char*)buf, 0, BYTES_MSG_LEN);
    
    switch (clients[i-n_users].step) 
    {
        case 0: // just connected
        {
            ygg_check(i, msg_size);
            clients[i-n_users].step = 1;
            break;
        }
        case 1: // cmd
        {
            log_debug("cmd");
            int cmd;
            n2 = crecv(i, buf, BYTES_CMD_LEN,0);
            if (n2 == 0) {return;}
            cmd = bytes_to_int((unsigned char*)buf, 0, BYTES_CMD_LEN);
            // printf("%d %d\n", n2, msg_size);
            switch (cmd) 
            {
                case 0: // login
                {
                log_debug("logining");
                    
                    if (msg_size < BYTES_LOGIN_LEN+1+BYTES_PASSWORD_LEN+1)//2*BYTES_TO_MSG_SIZE+2) //min |ls |l| ps|p|
                    {                 //    |3  |1| 3 |1|
                        
                        break;
                    }
                    login(i,msg_size-BYTES_CMD_LEN);
                    break;
                }
                case 1: // write messages from another daemon to local
                {
                    log_debug("writing l message");
                    if (msg_size >= BYTES_TEXT_LEN+1)//2*BYTES_TO_MSG_SIZE+2)   //min |ls |l| ms|p|
                    {       
                        write_msg_l(i, msg_size-BYTES_CMD_LEN);                                //    |3  |1| 3 |1|
                    }
                    
                    break;
                }
                case 2: // get messages
                {
                    log_debug("getting m");
                    if (clients[i-n_users].auth == 1)
                    {
                        if (msg_size >= sizeof(short)+sizeof(int))
                        {
                            get_messages(i, msg_size-BYTES_CMD_LEN);
                        }
                    }
                    break;
                }
                case 3: // ping
                {
                    send_ok(i);
                    break;
                }
                case 4: // write message to remote daemon
                {
                    log_debug("write r message");
                    if (msg_size >= 16+BYTES_TEXT_LEN+1)
                    {
                        write_msg_r(i, msg_size-BYTES_CMD_LEN);
                    }
                    break;
                }
                default:
                {
                    log_debug("unknown cmd");
                    send_err(i);
                    unreg(i);
                    break;
                }
            }
        }
    }
}


void loop()
{
    signal(SIGINT, _ctrlc_handler);
    while (running && nsocks > 0)
    {
        
        
        int ret = poll(pfds, nsocks, -1);
        if (ret == -1)
        {
            
            log_debug("loop :: poll :: Poll error");
        } 
        else if (ret == 0)
        {
            log_debug("loop :: poll :: Poll timeout");
        }
        else 
        {
            for (int i = 0; i < nsocks; i++) {
                if (pfds[i].revents & POLLIN)
                {
                    if (i < n_host_socks)
                    {
                        printf("i = %d\n", i);
                        handle_connection(i);
                    }
                    else 
                    {
                        handle_data(i);
                    }
                }
            }
        }
    }
}





void ygg_check_u()
{
    int ssock, r;
    struct sockaddr_in paddr;
    for (int i=0; i < n_users; i++)
    {
        // strcpy(jusers[i].ygg_proxy_addr, (char *)&paddr.sin_addr);
        inet_pton(AF_INET, jusers[i].ygg_proxy_addr, &paddr.sin_addr);
        paddr.sin_port = htons(jusers[i].ygg_proxy_port);
        paddr.sin_family = AF_INET;

        ssock = socket(AF_INET, SOCK_STREAM, 0);
        r = connect(ssock, (struct sockaddr*)&paddr, sizeof(paddr));
        if (r != 0)
        {
            log_error("ygg_check_u::connect cant connect to yggstack proxy");
            printf("%d\n", i);
            jexit(ERR_YGG_PROXY_CONNECT);
        }
        r = ygg_proxy_init_cnct(ssock);
        if (r != 0)
        {
            log_error("ygg_check_u::ygg_proxy_check wrong proxy");
            printf("%d\n", i);
            jexit(ERR_YGG_PROXY_CONNECT);
        }
        close(ssock);
    }
}


void prnt_config()
{
    char debug_info[4096];
    for (int i = 0; i < n_users; i++)
    {
        sprintf(debug_info, "Listen tcp on: [%s]:%d\t", config.listen, jusers[i].socket_port);
        log_debug(debug_info);
    }
   
    
    // sprintf(debug_info, "Listen unix on %s\t", config.unix_path);
    // log_debug(debug_info);

    for (int i = 0; i < MAX_USERS && i < n_users; i++){
        sprintf(debug_info, "Users[%d]: { %s : %s} { %s : %d }",i, jusers[i].login, jusers[i].password, jusers[i].ygg_proxy_addr, jusers[i].ygg_proxy_port);
        log_debug(debug_info);
    }

    return;
}


void sockets_config_parse(cJSON *sockets_c)
{

    cJSON *jobj;
    // if (!cJSON_IsNumber(jobj)) {
    //     log_error("config_parse::sockets_c.cJSON_GetObjectItemCaseSensitive::can not parse \'connection.port\' object");
    //     jexit(ERR_CONFIG_PARSE);
    // }
    // config.port = jobj->valueint;

    jobj = cJSON_GetObjectItemCaseSensitive(sockets_c, "listen");
    if (!cJSON_IsString(jobj)) {
        log_error("config_parse::sockets_c.cJSON_GetObjectItemCaseSensitive::can not parse \'connection.listen\' object");
        jexit(ERR_CONFIG_PARSE);
    }
    strcpy(config.listen,jobj->valuestring);


    // jobj = cJSON_GetObjectItemCaseSensitive(sockets_c, "unix_path");
    // if (!cJSON_IsString(jobj)) {
    //     log_error("config_parse::sockets_c.cJSON_GetObjectItemCaseSensitive::can not parse \'connection.unix_path\' object");
    //     jexit(ERR_CONFIG_PARSE);
    // }
    // strcpy(config.unix_path, jobj->valuestring);

    jobj = cJSON_GetObjectItemCaseSensitive(sockets_c, "max_connections");
    if (!cJSON_IsNumber(jobj)) {
        log_error("config_parse::sockets_c.cJSON_GetObjectItemCaseSensitive::can not parse \'connection.max_connections\' object");
        jexit(ERR_CONFIG_PARSE);
    }
    config.max_connections = jobj->valueint;

    free(jobj);

    return;
}

void users_config_parse(cJSON *users_c)
{
    n_users = 0;
    cJSON *user, *jobj;
    unsigned short i = 0;

    for (int i = 0; i < cJSON_GetArraySize(users_c) && i < MAX_USERS; i++)
    {
        user = cJSON_GetArrayItem(users_c, i);

        if (cJSON_IsObject(user))
        {
            jobj = cJSON_GetObjectItem(user, "login");
            if (cJSON_IsString(jobj) && strlen(jobj->valuestring) <= MAX_LOGIN_LEN)
            {
                strcpy(jusers[i].login, jobj->valuestring);
            } else {
                log_error("users_config_parse::login login is not a string or too long");
                jexit(ERR_CONFIG_PARSE);
            }

            jobj = cJSON_GetObjectItem(user, "password");
            if (cJSON_IsString(jobj) && strlen(jobj->valuestring) <= MAX_PASSW_LEN)
            {
                strcpy(jusers[i].password, jobj->valuestring);
            } else {
                log_error("users_config_parse::password password is not a string or too long");
                jexit(ERR_CONFIG_PARSE);
            }

            jobj = cJSON_GetObjectItem(user, "socket_port");
            if (cJSON_IsNumber(jobj) && jobj->valueint <= 65536)
            {
                jusers[i].socket_port = jobj->valueint;
            } else {
                log_error("users_config_parse::socket_port socket port is not a number or too big");
                jexit(ERR_CONFIG_PARSE);
            }

            jobj = cJSON_GetObjectItem(user, "ygg_proxy_addr");
            if (cJSON_IsString(jobj) && strlen(jobj->valuestring) <= INET_ADDRSTRLEN)
            {
                strcpy(jusers[i].ygg_proxy_addr, jobj->valuestring);
            } else {
                log_error("users_config_parse::ygg_proxy_addr ygg_p_a is not a string or too long");
                jexit(ERR_CONFIG_PARSE);
            }

            jobj = cJSON_GetObjectItem(user, "ygg_proxy_port");
            if (cJSON_IsNumber(jobj) && jobj->valueint <= 65536)
            {
                jusers[i].ygg_proxy_port = jobj->valueint;
            } else {
                log_error("users_config_parse::ygg_proxy_port ygg_p_a is not a number or too big");
                jexit(ERR_CONFIG_PARSE);
            }
        } else {
            log_error("users_config_parse::user user object wrong format");
            jexit(ERR_CONFIG_PARSE);
        }
        n_users++;
    }
    free(user);
    free(jobj);

    return;
}

void config_parse()
{
    FILE *jfile;
    jfile = fopen(CONFIG_PATH, "r");
    if (jfile == NULL)
    {
        log_error("config_parse::fopen::can not read config file");
        jexit(ERR_CONFIG_PARSE);
    }

    char buffer[1024]; 
    size_t len = fread(buffer, 1, sizeof(buffer), jfile); 
    fclose(jfile);

    cJSON *json = cJSON_Parse(buffer); 
    if (json == NULL) { 
        const char *error_ptr = cJSON_GetErrorPtr(); 
        if (error_ptr != NULL) { 
            printf("Error: %s\n", error_ptr); 
        } 
        cJSON_Delete(json); 
        log_error("config_parse::cJSON_Parse::can not parse json");
        jexit(ERR_CONFIG_PARSE);
    } 

    cJSON *sockets_c = cJSON_GetObjectItemCaseSensitive(json, "sockets"); 
    if (cJSON_IsString(sockets_c) && (sockets_c->valuestring != NULL)) {
        log_error("config_parse::cnct.cJSON_GetObjectItemCaseSensitive::can not parse \'connection\' object");
        jexit(ERR_CONFIG_PARSE);
    }

    cJSON *users = cJSON_GetObjectItemCaseSensitive(json, "users");

    cJSON *yggstack = cJSON_GetObjectItemCaseSensitive(json, "yggstack");

    sockets_config_parse(sockets_c);
    users_config_parse(users);

    free(sockets_c);
    free(users);
    free(yggstack);

    return;
}


int main(int argc, char **argv)
{
    config_parse();
    ygg_check_u();
    prnt_config();
    create_server();
    loop();
    end();
}