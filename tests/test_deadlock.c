/* test_deadlock.c - tests TC2, TC7, TC8 logic without any network (module M5 alone). */
#include <stdio.h>
#include <string.h>
#include "../src/resource.h"

static int fails = 0;
static char last_note[8][300];
static int  last_type[8];
static int  seen[8][10];

static void notify(int c, int type, const char *text)
{
    last_type[c] = type; seen[c][type] = 1;
    snprintf(last_note[c], sizeof last_note[c], "%s", text);
    printf("   [notify C%d] type=%d : %s\n", c + 1, type, text);
}

static void check(const char *name, int cond)
{
    printf("%s  %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails++;
}

int main(void)
{
    char out[300];
    rm_init(notify);
    rm_add_resource("R1", 1);
    rm_add_resource("R2", 1);
    rm_add_resource("R3", 3);
    rm_register(0, "C1", 1);
    rm_register(1, "C2", 2);
    rm_register(2, "C3", 3);

    puts("--- TC2: request available resource ---");
    check("C1 gets R1", rm_request(0, "R1", 1, out, sizeof out) == RM_GRANT);
    check("C3 gets 2 units of R3", rm_request(2, "R3", 2, out, sizeof out) == RM_GRANT);
    check("asking more than total is denied", rm_request(2, "R3", 9, out, sizeof out) == RM_DENY);

    puts("--- TC7: C1 holds R1 wants R2, C2 holds R2 wants R1 ---");
    check("C2 gets R2", rm_request(1, "R2", 1, out, sizeof out) == RM_GRANT);
    check("C1 waits for R2 (no deadlock yet)", rm_request(0, "R2", 1, out, sizeof out) == RM_WAIT);
    int r = rm_request(1, "R1", 1, out, sizeof out);
    printf("   C2 reply: %s\n", out);
    check("C2 (lower priority) is the victim -> DENY", r == RM_DENY);
    check("C1 was notified about the deadlock", seen[0][RM_STATUS]);
    check("C1 then got R2 granted (was waiting)", last_type[0] == RM_GRANT);
    int cyc[MAX_CLIENTS];
    check("no cycle left in the graph", rm_find_cycle(cyc, MAX_CLIENTS) == 0);
    rm_status(0, out, sizeof out);
    printf("   C1 status: %s\n", out);
    check("C1 now holds R2", strstr(out, "R2 x1") != NULL);

    puts("--- TC8: client disappears, waiter gets its resource ---");
    check("C2 asks R1 (held by C1) and waits", rm_request(1, "R1", 1, out, sizeof out) == RM_WAIT);
    rm_remove_client(0);                       /* C1 killed */
    check("C2 got R1 after C1 vanished", last_type[1] == RM_GRANT);

    puts("--- 3-client cycle ---");
    rm_init(notify);
    rm_add_resource("R1", 1); rm_add_resource("R2", 1); rm_add_resource("R3", 1);
    rm_register(0, "C1", 1); rm_register(1, "C2", 2); rm_register(2, "C3", 3);
    rm_request(0, "R1", 1, out, sizeof out);
    rm_request(1, "R2", 1, out, sizeof out);
    rm_request(2, "R3", 1, out, sizeof out);
    rm_request(0, "R2", 1, out, sizeof out);
    rm_request(1, "R3", 1, out, sizeof out);
    check("C3 closing the 3-cycle is aborted", rm_request(2, "R1", 1, out, sizeof out) == RM_DENY);

    printf("\n%s (%d failed)\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails != 0;
}
