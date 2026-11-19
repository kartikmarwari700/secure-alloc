/* config.h - server settings read from secure_alloc.conf (ports, timeouts, shared resources) */
#ifndef CONFIG_H
#define CONFIG_H
#include "resource.h"

typedef struct {
    int  tcp_port;
    int  udp_port;
    int  hb_timeout;           /* seconds of silence before a client is dropped */
    int  status_interval;      /* seconds between UDP status broadcasts */
    int  max_clients;
    char log_path[128];
    int  nres;
    char rname[MAX_RES][16];
    int  rtotal[MAX_RES];
} config_t;

void config_defaults(config_t *c);
int  config_load(config_t *c, const char *path);   /* 0 ok, -1 file not found, -2 syntax error (message printed) */
#endif
