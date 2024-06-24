# Junq_deamon_C
## P2P messages manager over yggdrasil network
### Used libaries:
- [CJSON](https://github.com/DaveGamble/cJSON): MIT License

### Functions
- create_tcp - creates a tcp socket
- create_unix - creates a UNIX socket
- create_server - run two abovementioned functions
- crecv - catch recv signal
- reg - register client
- unreg - unregister client
- handle_connection -  handle connection to daemon
- ygg_check - check yggdrasil network connection
- send_ok - send okay message to socket
- send_err - send okay message to socket
- login - login deamon to user data files
- write_msg_l - write on disk messages
- get_messages - get messages
- end - ends all processes
- prnt_config - DEBUG function to print a conf file
- config_parse - read config file
- sockets_config_parse - parse data from config_parse
- users_config_parse - parse data from config_parse
