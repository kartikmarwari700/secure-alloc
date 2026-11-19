/* config.c - tiny "key = value" parser for secure_alloc.conf
 * Owner   : Ishita (module M1 support)
 *
 * Example file:
 *     tcp_port = 5000        # spaces around '=' are optional
 *     hb_timeout = 6
 *     resource R1 1          # name and number of units
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "config.h"
#include "common.h"

void config_defaults(config_t *c)
{
    memset(c, 0, sizeof *c);
    c->tcp_port = TCP_PORT;
    c->udp_port = UDP_PORT;
    c->hb_timeout = HB_TIMEOUT;
    c->status_interval = STATUS_INTERVAL;
    c->max_clients = MAX_CLIENTS;
    snprintf(c->log_path, sizeof c->log_path, "logs/server.log");
    c->nres = 3;
    strcpy(c->rname[0], "R1"); c->rtotal[0] = 1;
    strcpy(c->rname[1], "R2"); c->rtotal[1] = 1;
    strcpy(c->rname[2], "R3"); c->rtotal[2] = 3;
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

int config_load(config_t *c, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[200];
    int lineno = 0, custom_res = 0, rc = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        char *l = trim(line);
        if (!*l) continue;                                     /* blank / comment line */

        char *eq = strchr(l, '=');
        if (eq) {                                              /* key = value */
            *eq = 0;
            char *key = trim(l), *val = trim(eq + 1);
            int v = atoi(val);
            if      (!strcmp(key, "tcp_port"))        c->tcp_port = v;
            else if (!strcmp(key, "udp_port"))        c->udp_port = v;
            else if (!strcmp(key, "hb_timeout"))      c->hb_timeout = v;
            else if (!strcmp(key, "status_interval")) c->status_interval = v;
            else if (!strcmp(key, "max_clients"))     c->max_clients = v > MAX_CLIENTS ? MAX_CLIENTS : v;
            else if (!strcmp(key, "log_file"))        snprintf(c->log_path, sizeof c->log_path, "%s", val);
            else { fprintf(stderr, "%s:%d: unknown setting '%s'\n", path, lineno, key); rc = -2; }
            if ((!strcmp(key, "tcp_port") || !strcmp(key, "udp_port")) && (v < 1 || v > 65535)) {
                fprintf(stderr, "%s:%d: '%s' needs a port number 1-65535\n", path, lineno, key); rc = -2;
            }
            continue;
        }
        char name[64], units[64];
        if (sscanf(l, "resource %63s %63s", name, units) == 2) {   /* resource R1 3 */
            if (!custom_res) { c->nres = 0; custom_res = 1; }      /* first 'resource' line replaces the defaults */
            if (c->nres >= MAX_RES || atoi(units) <= 0) { fprintf(stderr, "%s:%d: bad resource line\n", path, lineno); rc = -2; continue; }
            snprintf(c->rname[c->nres], sizeof c->rname[0], "%.15s", name);
            c->rtotal[c->nres++] = atoi(units);
            continue;
        }
        fprintf(stderr, "%s:%d: cannot understand '%s'\n", path, lineno, l); rc = -2;
    }
    fclose(f);
    return rc;
}
