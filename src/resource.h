/* resource.h - Module M5: Resource Manager + Deadlock Detection (pure logic, no sockets)
 * Owner : Kartik */
#ifndef RESOURCE_H
#define RESOURCE_H
#include <stddef.h>

#define MAX_CLIENTS 32
#define MAX_RES     8
#define MAX_WAITS   64

/* reply types (same numbers as protocol message types in common.h) */
#define RM_GRANT 2
#define RM_WAIT  3
#define RM_DENY  4
#define RM_STATUS 6

/* called when the manager must tell some OTHER client something (late GRANT, deadlock notice) */
typedef void (*notify_fn)(int client, int type, const char *text);

void rm_init(notify_fn fn);
void rm_add_resource(const char *name, int total);
void rm_register(int client, const char *id, int priority); /* lower number = higher priority */

/* Returns RM_GRANT / RM_WAIT / RM_DENY and fills 'out' with a message for the requester */
int  rm_request(int client, const char *res, int units, char *out, size_t cap);
int  rm_release(int client, const char *res, int units, char *out, size_t cap);
void rm_remove_client(int client);                 /* disconnect / heartbeat timeout */
void rm_status(int client, char *out, size_t cap); /* table of resources + what 'client' holds */

/* optional: where deadlock messages go (default: printf) */
typedef void (*rm_log_fn)(const char *line);
void rm_set_logger(rm_log_fn fn);

typedef struct { unsigned long grants, waits, denies, releases, deadlocks, rollbacks; } rm_stats_t;
void rm_get_stats(rm_stats_t *out);

/* human readable dump: every resource with holders and waiting clients */
void rm_dump(char *out, size_t cap);

/* wait-for graph: fills cycle[] with client indexes, returns length (0 = no deadlock) */
int  rm_find_cycle(int cycle[], int max);
#endif
