#include <netinet/in.h>


// -- ERRORS -- //
#define ERR_CONFIG_PARSE                        1



// server create
#define ERR_CREATE_SERVER_SOCKET                2
#define ERR_CREATE_SERVER_SETSOCKOPT            3
#define ERR_CREATE_SERVER_BIND                  4
#define ERR_CREATE_SERVER_LISTEN                5



// regc
#define ERR_REG_MAX_CONNECTIONS                 6

// else
#define ERR_REALLOC                             7
#define ERR_POLL_ERR                            8

// client socket errors
#define ERR_ACCEPT_CLIENT                       9

// ygg proxy errs
#define ERR_YGG_PROXY_CONNECT                   0
#define ERR_YGG_PROXY_PING_CONNECT

// send to client codes
// ERR
#define R_ERR                                   0
// #define R_ERR_UNKNOWN_CMD                       1
// #define R_ERR_WRITE_R                           2

// OK
#define R_OK                                    0


#define BYTES_MSG_LEN                           3
#define BYTES_TEXT_LEN                          2
#define BYTES_NUM                               2
#define BYTES_LOGIN_LEN                         1
#define BYTES_PASSWORD_LEN                      1
#define BYTES_CMD_LEN                           1

#define MAX_USERS                               4*5
#define MAX_MESSAGE_LEN                         65536
#define MAX_PASSW_LEN                           256
#define MAX_LOGIN_LEN                           256

#define SAVED_MESSAGES_N                        300


#define CONFIG_PATH                             "./junq-daemon.conf"


struct jcfg
{
    int port;
    char listen[INET6_ADDRSTRLEN];
    char unix_path[1024];
    
    int max_connections;
    char *login;
    char *password;

    char *ygg_addr;
    int ygg_port;
};

struct message
{
    char msg[MAX_MESSAGE_LEN];
    struct in6_addr sender_addr;
    // char recipient[MAX_LOGIN_LEN];
    unsigned long time;
    unsigned int id;
};


struct user
{
    char login[MAX_LOGIN_LEN];
    char password[MAX_PASSW_LEN];
    unsigned int current_id;
    unsigned short socket_port;
    char ygg_proxy_addr[INET6_ADDRSTRLEN];
    unsigned short ygg_proxy_port;
    struct message messages[SAVED_MESSAGES_N];
};

struct client_s
{
    unsigned short step;
    struct sockaddr_in6 addr;
    unsigned short auth;
    // char login[MAX_LOGIN_LEN];
    short dest_yggs;
};



static unsigned int nsocks = 0;
static struct pollfd* pfds;
static struct client_s* clients;


static struct jcfg config;
static struct user jusers[MAX_USERS];

static unsigned int n_host_socks = 0;
static int running = 1;
static int n_users = 0;
