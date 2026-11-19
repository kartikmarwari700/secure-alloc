/* resource.c - Module M5 (owner: Kartik): Resource table, wait queue, wait-for graph, DFS cycle detection, recovery.
 *
 * NOTE: this file is NOT thread-safe on its own. The server locks one global mutex around every call.
 */
#include <stdio.h>
#include <string.h>
#include "resource.h"

typedef struct {
    char name[16];
    int  total;
    int  avail;
    int  held[MAX_CLIENTS];            /* units held by each client */
} resource_t;

typedef struct {
    int used, client, res, units;
    unsigned long order;               /* arrival order (FIFO) */
} waiter_t;

static resource_t R[MAX_RES];
static int        nres = 0;
static waiter_t   W[MAX_WAITS];
static unsigned long arrival = 0;

static char cid[MAX_CLIENTS][16];
static int  cprio[MAX_CLIENTS];
static int  cactive[MAX_CLIENTS];

static notify_fn notify_cb = NULL;
static rm_log_fn log_cb = NULL;
static rm_stats_t stats;

void rm_set_logger(rm_log_fn fn) { log_cb = fn; }
void rm_get_stats(rm_stats_t *out) { *out = stats; }
/* while rm_request() is running we hold back messages for the requester and return them as the reply */
static int  quiet_client = -1;
static int  quiet_type   = 0;
static char quiet_text[256];

static void say(int c, int type, const char *text)
{
    if (c == quiet_client) {
        quiet_type = type;
        snprintf(quiet_text, sizeof quiet_text, "%s", text);
    } else if (notify_cb && cactive[c]) {
        notify_cb(c, type, text);
    }
}

void rm_init(notify_fn fn)
{
    memset(R, 0, sizeof R); memset(W, 0, sizeof W);
    memset(cprio, 0, sizeof cprio); memset(cactive, 0, sizeof cactive); memset(cid, 0, sizeof cid);
    nres = 0; arrival = 0; notify_cb = fn; quiet_client = -1; memset(&stats, 0, sizeof stats);
}

void rm_add_resource(const char *name, int total)
{
    if (nres >= MAX_RES) return;
    snprintf(R[nres].name, sizeof R[nres].name, "%s", name);
    R[nres].total = R[nres].avail = total;
    nres++;
}

void rm_register(int client, const char *id, int priority)
{
    snprintf(cid[client], sizeof cid[client], "%s", id);
    cprio[client] = priority;
    cactive[client] = 1;
}

static int find_res(const char *name)
{
    for (int i = 0; i < nres; i++) if (strcmp(R[i].name, name) == 0) return i;
    return -1;
}

static int find_wait(int client)
{
    for (int i = 0; i < MAX_WAITS; i++) if (W[i].used && W[i].client == client) return i;
    return -1;
}

/* ---------------- wait-for graph + DFS ---------------- */

/* edge i -> j  means: client i is waiting for a resource that client j currently holds */
static void build_graph(int adj[MAX_CLIENTS][MAX_CLIENTS])
{
    memset(adj, 0, sizeof(int) * MAX_CLIENTS * MAX_CLIENTS);
    for (int w = 0; w < MAX_WAITS; w++) {
        if (!W[w].used) continue;
        for (int j = 0; j < MAX_CLIENTS; j++)
            if (j != W[w].client && R[W[w].res].held[j] > 0) adj[W[w].client][j] = 1;
    }
}

/* colour: 0 = not visited, 1 = on current DFS path, 2 = finished. Meeting a colour-1 node = cycle. */
static int dfs(int u, int adj[MAX_CLIENTS][MAX_CLIENTS], int color[], int path[], int *plen,
               int cycle[], int max)
{
    color[u] = 1;
    path[(*plen)++] = u;
    for (int v = 0; v < MAX_CLIENTS; v++) {
        if (!adj[u][v]) continue;
        if (color[v] == 0) {
            int n = dfs(v, adj, color, path, plen, cycle, max);
            if (n) return n;
        } else if (color[v] == 1) {
            int i = 0, n = 0;
            while (path[i] != v) i++;
            for (; i < *plen && n < max; i++) cycle[n++] = path[i];
            return n;
        }
    }
    color[u] = 2;
    (*plen)--;
    return 0;
}

int rm_find_cycle(int cycle[], int max)
{
    static int adj[MAX_CLIENTS][MAX_CLIENTS];
    int color[MAX_CLIENTS] = {0}, path[MAX_CLIENTS + 1], plen;
    build_graph(adj);
    for (int s = 0; s < MAX_CLIENTS; s++) {
        if (color[s] != 0) continue;
        plen = 0;
        int n = dfs(s, adj, color, path, &plen, cycle, max);
        if (n) return n;
    }
    return 0;
}

/* ---------------- granting + recovery ---------------- */

static void drop_waiter(int client)
{
    int w = find_wait(client);
    if (w >= 0) W[w].used = 0;
}

static void release_all(int client)
{
    for (int r = 0; r < nres; r++) {
        R[r].avail += R[r].held[client];
        R[r].held[client] = 0;
    }
}

/* give freed units to waiting clients, oldest request first */
static void serve_queues(void)
{
    int progress = 1;
    while (progress) {
        progress = 0;
        int best = -1;
        for (int i = 0; i < MAX_WAITS; i++) {        /* oldest waiter that can now be satisfied */
            if (!W[i].used) continue;
            if (R[W[i].res].avail < W[i].units) continue;
            if (best < 0 || W[i].order < W[best].order) best = i;
        }
        if (best >= 0) {
            char msg[128];
            int c = W[best].client, r = W[best].res, u = W[best].units;
            R[r].avail -= u; R[r].held[c] += u; W[best].used = 0;
            snprintf(msg, sizeof msg, "%s x%d granted (you were waiting)", R[r].name, u);
            say(c, RM_GRANT, msg);
            progress = 1;
        }
    }
}

/* detect -> choose victim -> abort + roll back -> notify -> repeat until graph has no cycle */
static void resolve_deadlocks(void)
{
    int cycle[MAX_CLIENTS];
    int n;
    serve_queues();
    while ((n = rm_find_cycle(cycle, MAX_CLIENTS)) > 0) {
        int victim = cycle[0];
        for (int i = 1; i < n; i++)                  /* lowest priority = biggest priority number */
            if (cprio[cycle[i]] > cprio[victim]) victim = cycle[i];

        char chain[256] = "";
        for (int i = 0; i < n; i++) {
            strncat(chain, cid[cycle[i]], sizeof chain - strlen(chain) - 1);
            strncat(chain, " -> ", sizeof chain - strlen(chain) - 1);
        }
        strncat(chain, cid[cycle[0]], sizeof chain - strlen(chain) - 1);

        char line[400];
        snprintf(line, sizeof line, "DEADLOCK cycle: %s | victim: %s (lowest priority)", chain, cid[victim]);
        if (log_cb) log_cb(line); else printf("[DEADLOCK] %s\n", line);
        stats.deadlocks++;
        for (int r = 0; r < nres; r++) if (R[r].held[victim] > 0) { stats.rollbacks++; break; }

        drop_waiter(victim);
        release_all(victim);

        char msg[400];
        snprintf(msg, sizeof msg, "DEADLOCK detected (%s). Your request was aborted and your resources were released.", chain);
        say(victim, RM_DENY, msg);
        snprintf(msg, sizeof msg, "DEADLOCK detected (%s). Victim %s was aborted; your request will be served.", chain, cid[victim]);
        for (int i = 0; i < n; i++)
            if (cycle[i] != victim) say(cycle[i], RM_STATUS, msg);

        serve_queues();
    }
}

/* ---------------- public API ---------------- */

int rm_request(int c, const char *res, int units, char *out, size_t cap)
{
    int r = find_res(res);
    if (r < 0)                       { snprintf(out, cap, "unknown resource '%s'", res); return RM_DENY; }
    if (units <= 0 || units > R[r].total) { snprintf(out, cap, "invalid units (1..%d allowed for %s)", R[r].total, res); return RM_DENY; }
    if (find_wait(c) >= 0)           { snprintf(out, cap, "you already have a request waiting"); return RM_DENY; }

    if (R[r].avail >= units) {
        R[r].avail -= units; R[r].held[c] += units;
        snprintf(out, cap, "%s x%d granted", R[r].name, units);
        stats.grants++;
        return RM_GRANT;
    }

    for (int i = 0; i < MAX_WAITS; i++) {
        if (W[i].used) continue;
        W[i].used = 1; W[i].client = c; W[i].res = r; W[i].units = units; W[i].order = ++arrival;
        quiet_client = c; quiet_type = 0;
        resolve_deadlocks();                         /* a new waiting edge may have closed a cycle */
        quiet_client = -1;
        if (quiet_type) {
            snprintf(out, cap, "%s", quiet_text);
            if (quiet_type == RM_GRANT) stats.grants++; else stats.denies++;
            return quiet_type;
        }
        snprintf(out, cap, "%s x%d not available (free: %d) - request queued", R[r].name, units, R[r].avail);
        stats.waits++;
        return RM_WAIT;
    }
    snprintf(out, cap, "server wait queue is full");
    return RM_DENY;
}

int rm_release(int c, const char *res, int units, char *out, size_t cap)
{
    int r = find_res(res);
    if (r < 0)                          { snprintf(out, cap, "unknown resource '%s'", res); return RM_DENY; }
    if (units <= 0 || units > R[r].held[c]) { snprintf(out, cap, "you hold only %d unit(s) of %s", R[r].held[c], res); return RM_DENY; }
    R[r].held[c] -= units; R[r].avail += units;
    stats.releases++;
    snprintf(out, cap, "%s x%d released", R[r].name, units);
    resolve_deadlocks();                             /* serves the queue, re-checks the graph */
    return RM_STATUS;
}

void rm_remove_client(int c)
{
    drop_waiter(c);
    release_all(c);
    cactive[c] = 0;
    resolve_deadlocks();
}

void rm_status(int c, char *out, size_t cap)
{
    size_t n = 0;
    out[0] = 0;
    for (int r = 0; r < nres && n < cap; r++)
        n += snprintf(out + n, cap - n, "%s %d/%d free; ", R[r].name, R[r].avail, R[r].total);
    if (n < cap) n += snprintf(out + n, cap - n, "| you hold: ");
    int any = 0;
    for (int r = 0; r < nres && n < cap; r++)
        if (R[r].held[c] > 0) { n += snprintf(out + n, cap - n, "%s x%d ", R[r].name, R[r].held[c]); any = 1; }
    if (!any && n < cap) snprintf(out + n, cap - n, "nothing");
    if (find_wait(c) >= 0 && strlen(out) + 24 < cap) strcat(out, "| 1 request waiting");
}

void rm_dump(char *out, size_t cap)
{
    size_t n = 0;
    out[0] = 0;
    for (int r = 0; r < nres && n < cap; r++) {
        n += snprintf(out + n, cap - n, "%s  free %d/%d  held by:", R[r].name, R[r].avail, R[r].total);
        int any = 0;
        for (int c = 0; c < MAX_CLIENTS && n < cap; c++)
            if (R[r].held[c] > 0) { n += snprintf(out + n, cap - n, " %s(x%d)", cid[c], R[r].held[c]); any = 1; }
        if (!any && n < cap) n += snprintf(out + n, cap - n, " nobody");
        n += snprintf(out + n, cap - n, "  waiting:");
        any = 0;
        for (int w = 0; w < MAX_WAITS && n < cap; w++)
            if (W[w].used && W[w].res == r) { n += snprintf(out + n, cap - n, " %s(x%d)", cid[W[w].client], W[w].units); any = 1; }
        if (!any && n < cap) n += snprintf(out + n, cap - n, " nobody");
        if (n < cap) n += snprintf(out + n, cap - n, "\n");
    }
}
