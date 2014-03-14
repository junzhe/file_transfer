#define BINDER_MESSAGE "Binder called\n"

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

int main(int argc, char *argv[])
{
        message m;

        /* SEF local startup. */
        env_setargs(argc, argv);
        sef_local_startup();

        while(TRUE) {
                printf("%s",BINDER_MESSAGE);
                int r;
                int binder_number;

                if ((r = sef_receive(ANY, &m)) != OK)
                        printf("sef_receive failed %d.\n", r);
                who_e = m.m_source;
                call_type = m.m_type;

                if(verbose)
                        printf("BINDER: get %d from %d\n", call_type, who_e);

                /*
                 * The ipc number in the table can be obtained
                 * with a simple equation because the values of
                 * IPC system calls are consecutive and begin
                 * at ( ASHMEM_BASE + 1 )
                 */

                binder_number = call_type - (BINDER_BASE + 1);
                printf("BINDER binder_number: %d\n", binder_number);

                /* dispatch message */
                if (binder_number >= 0 && binder_number < SIZE(binder_calls)) {
                        int result;

                        if (binder_calls[binder_number].type != call_type)
                                panic("BINDER: call table order mismatch");

                        /* If any process does an IPC call,
                         * we have to know about it exiting.
                         * Tell VM to watch it for us.
                         */
                        if(vm_watch_exit(m.m_source) != OK) {
                                printf("BINDER: watch failed on %d\n", m.m_source);
                        }

                        result = binder_calls[binder_number].func(&m);

                        /*
                         * The handler of the IPC call did not
                         * post a reply.
                         */
                        if (!binder_calls[binder_number].reply) {

                                m.m_type = result;

                                if(verbose && result != OK)
                                        printf("BINDER: error for %d: %d\n",
                                                        call_type, result);

                                if ((r = sendnb(who_e, &m)) != OK)
                                        printf("BINDER send error %d.\n", r);
                        }
                } else {
                       /* warn and then ignore */
                       printf("BINDER unknown call type: %d from %d.\n",
                                                      call_type, who_e);
                }
                                                                                                                                                                                                                                                                  147,2-9       31        }

        return -1;
}

/*===========================================================================*
 *                             sef_local_startup                             *
 *===========================================================================*/
static void sef_local_startup()
{
        /* Register init callbacks. */
        sef_setcb_init_fresh(sef_cb_init_fresh);
        sef_setcb_init_restart(sef_cb_init_fresh);

        /* No live update support for now. */

        /* Register signal callbacks. */
        sef_setcb_signal_handler(sef_cb_signal_handler);

        /* Let SEF perform startup. */
        sef_startup();
}

/*===========================================================================*
 *                          sef_cb_init_fresh                                *
 *===========================================================================*/
static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
        /* Initialize the ipc server. */

        SELF_E = getprocnr();

        if(verbose)
                printf("BINDER: self: %d\n", SELF_E);

        return(OK);
}

/*===========================================================================*
 *                          sef_cb_signal_handler                            *
 *===========================================================================*/
static void sef_cb_signal_handler(int signo)
{
        /* Only check for termination signal, ignore anything else. */
        if (signo != SIGTERM) return;
}

