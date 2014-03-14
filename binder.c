#include "binder.h"

endpoint_t who_e;
int call_type;
endpoint_t SELF_E;

static struct {
        int type;
	int (*func)(message *);
	int reply;      /* whether the reply action is passed through */
	} binder_calls[] = {
};

