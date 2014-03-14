#define ASHMEM_MESSAGE "Ashmem called\n"
#define MAX_ASHMEM_N 1024
#define ASHMEM_NAME_PREFIX "dev/ashmem/"
#define ASHMEM_NAME_PREFIX_LEN (sizeof(ASHMEM_NAME_PREFIX) - 1)
#define ASHMEM_FULL_NAME_LEN (ASHMEM_NAME_LEN + ASHMEM_NAME_PREFIX_LEN)

#include "ashmem.h"

endpoint_t who_e;
int call_type;
endpoint_t SELF_E;

static struct {
	int type;
	int (*func)(message *);
	int reply;      /* whether the reply action is passed through */
	} ashmem_calls[] = {
	{ ASHMEM_CREATE,	do_ashmem_create_region,	0 },
	{ ASHMEM_RELEASE,	do_ashmem_release_region,	0 },
	{ ASHMEM_SET_NAME,	do_ashmem_set_name_region,	0 },
	{ ASHMEM_SET_SIZE,	do_ashmem_set_size_region,	0 },
	{ ASHMEM_MMAP,		do_ashmem_mmap_region, 		0 },
	{ ASHMEM_PIN,		do_ashmem_pin_region,		0 },
	{ ASHMEM_UNPIN,		do_ashmem_unpin_region,		0 },
	{ ASHMEM_SET_PROT, 	do_ashmem_set_prot_region, 	0 },
	{ ASHMEM_GET_SIZE,	do_ashmem_get_size_region, 	0 }
};

#define SIZE(a) (sizeof(a)/sizeof(a[0]))

static int verbose = 1;

unsigned long lru_count;

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init_fresh(int type, sef_init_info_t *info);
static void sef_cb_signal_handler(int signo);

struct ashmem_area {
	char name[ASHMEM_FULL_NAME_LEN];
	int id;
	struct shmid_ds shmid_ds;
	vir_bytes page;
	int vm_id;
	struct list_head unpinned_list;
	unsigned long prot_mask;
}; 

struct ashmem_range {
	struct list_head lru;
	struct list_head unpinned;
	struct ashmem_area *asma;
	size_t pgstart;
	size_t pgend;
	unsigned int purged;
};

struct ashmem_pin {
	unsigned int offset;
	unsigned int len;
};

#define min_t(type, x, y) ({                    \
        type __min1 = (x);                      \
        type __min2 = (y);                      \
        __min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({                    \
        type __max1 = (x);                      \
        type __max2 = (y);                      \
        __max1 > __max2 ? __max1: __max2; })

#define range_size(range) \
	((range)->pgend - (range)->pgstart + 1)

#define range_on_lru(range) \
	((range)->purged == ASHMEM_NOT_PURGED)

#define page_range_subsumes_range(range, start, end) \
	(((range)->pgstart >= (start)) && ((range)->pgend <= (end)))

#define page_range_subsumed_by_range(range, start, end) \
	(((range)->pgstart <= (start)) && ((range)->pgend >= (end)))

#define page_in_range(range, page) \
	(((range)->pgstart <= (page)) && ((range)->pgend >= (page)))

#define page_range_in_range(range, start, end) \
	(page_in_range(range, start) || page_in_range(range, end) || \
		page_range_subsumes_range(range, start, end))

#define range_before_page(range, page) \
	((range)->pgend < (page))

static LIST_HEAD(ashmem_lru_list);
static struct ashmem_area ashmem_list[MAX_ASHMEM_N];
static int ashmem_list_n = 0;

void lru_add(struct ashmem_range *range)
{
	list_add_tail(&range->lru, &ashmem_lru_list);
	lru_count += range_size(range);
}

void lru_del(struct ashmem_range *range)
{
	list_del(&range->lru);
	lru_count -= range_size(range);
}

inline void range_shrink(struct ashmem_range *range,
				size_t start, size_t end)
{
	size_t pre = range_size(range);

	range->pgstart = start;
	range->pgend = end;

	if(range_on_lru(range))
		lru_count -= pre - range_size(range);
}

int range_alloc(struct ashmem_area *asma,
		struct ashmem_range *prev_range, unsigned int purged,
		size_t start, size_t end)
{
	struct ashmem_range *range = malloc(sizeof(struct ashmem_range));

	range->asma = asma;
	range->pgstart = start;
	range->pgend = end;
	range->purged = purged;

	list_add_tail(&range->unpinned, &prev_range->unpinned);

	if(range_on_lru(range))
		lru_add(range);

	return 0;
}

void range_del(struct ashmem_range *range)
{
	list_del(&range->unpinned);

	if(range_on_lru(range))
		lru_del(range);
	free(range);
}

int main(int argc, char *argv[])
{
	message m;

	/* SEF local startup. */
	env_setargs(argc, argv);
	sef_local_startup();

	while(TRUE) {
		printf("%s",ASHMEM_MESSAGE); 
		int r;
		int ashmem_number;

		if ((r = sef_receive(ANY, &m)) != OK)
			printf("sef_receive failed %d.\n", r);
		who_e = m.m_source;
		call_type = m.m_type;

		if(verbose)
			printf("ASHMEM: get %d from %d\n", call_type, who_e);

		/*
		 * The ipc number in the table can be obtained
	 	 * with a simple equation because the values of
	         * IPC system calls are consecutive and begin
	         * at ( ASHMEM_BASE + 1 )
	         */

	     	ashmem_number = call_type - (ASHMEM_BASE + 1);
		printf("ASHMEM ashmem_number: %d\n", ashmem_number);
	
		/* dispatch message */
		if (ashmem_number >= 0 && ashmem_number < SIZE(ashmem_calls)) {
			int result;

			if (ashmem_calls[ashmem_number].type != call_type)
				panic("ASHMEM: call table order mismatch");

			/* If any process does an IPC call,
			 * we have to know about it exiting.
			 * Tell VM to watch it for us.
			 */
		  	if(vm_watch_exit(m.m_source) != OK) {
				printf("ASHMEM: watch failed on %d\n", m.m_source);
		   	}

		   	result = ashmem_calls[ashmem_number].func(&m);

		   	/*
			 * The handler of the IPC call did not
			 * post a reply.
			 */
		      	if (!ashmem_calls[ashmem_number].reply) {

				m.m_type = result;

			        if(verbose && result != OK)
			      		printf("ASHMEM: error for %d: %d\n",
							call_type, result);

				if ((r = sendnb(who_e, &m)) != OK)
					printf("ASHMEM send error %d.\n", r);
		        }
	        } else {
		       /* warn and then ignore */
		       printf("ASHMEM unknown call type: %d from %d.\n",
						      call_type, who_e);
		}	
	}

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
		printf("ASHMEM: self: %d\n", SELF_E);

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

static struct ashmem_area *ashmem_find_area()
{
	struct ashmem_area *ashmem = &ashmem_list[ashmem_list_n];
	
	ashmem->id = ashmem_list_n;

	ashmem_list_n++;

	return ashmem;
}

static struct ashmem_area *ashmem_find_by_id(int id)
{
	struct ashmem_area *ashmem = &ashmem_list[id];

	return ashmem;
}

static void update_ref_count_destroy()
{
	int i, j;

	for(i = 0, j = 0; i < ashmem_list_n; i++) {
		u8_t rc;

		rc = vm_getrefcount(SELF_E, (void *) ashmem_list[i].page);
		if (rc == (u8_t) -1) {
			printf("ASHMEM: can't find physical region.\n");
			continue;
		}

		ashmem_list[i].shmid_ds.shm_nattch = rc - 1;

		if(ashmem_list[i].shmid_ds.shm_nattch) {
			if(i != j)
				ashmem_list[j] = ashmem_list[i];
			j++;
		}else {
			int size = ashmem_list[i].shmid_ds.shm_segsz;
			if (size % PAGE_SIZE)
				size += PAGE_SIZE - size % PAGE_SIZE;
			minix_munmap((void *)ashmem_list[i].page, size);
		}
	}

	ashmem_list_n = j;
}

int do_ashmem_create_region(message *m)
{
	printf("Call do_ashmem_create_region\n");

	struct ashmem_area *ashmem;

	ashmem = ashmem_find_area();

	memset(ashmem, 0, sizeof(struct ashmem_area));

	m->ASHMEM_CREATE_RETID = ashmem->id;

	return OK;
}

int do_ashmem_mmap_region(message *m)
{
	int id, flag;
	vir_bytes addr;
	void *ret;
	struct ashmem_area *ashmem;

	id = m->ASHMEM_MMAP_ID;
	addr = m->ASHMEM_MMAP_ADDR;

	ashmem = ashmem_find_by_id(id);

	ret = vm_remap(who_e, SELF_E, (void *)addr, (void *)ashmem->page,
				ashmem->shmid_ds.shm_segsz);

	ashmem->shmid_ds.shm_atime = time(NULL);
	ashmem->shmid_ds.shm_lpid = getnpid(who_e);
	/* nattach is updated lazily */

	m->ASHMEM_MMAP_RETADDR = (long) ret;
	return OK;
}

int do_ashmem_release_region(message *m)
{
	vir_bytes addr;
        phys_bytes vm_id;
	int i;

	addr = m->ASHMEM_RELEASE_ADDR;

	if ((vm_id = vm_getphys(who_e, (void *) addr)) == 0)
		return EINVAL;

	for(i = 0; i < ashmem_list_n; i++) {
		if(ashmem_list[i].vm_id == vm_id) {
			struct ashmem_area *ashmem = &ashmem_list[i];
			
			ashmem->shmid_ds.shm_atime = time(NULL);
			ashmem->shmid_ds.shm_lpid = getnpid(who_e);

			vm_unmap(who_e, (void *) addr);

			break;
		}
	}

	update_ref_count_destroy();

	return OK;
}

int do_ashmem_set_name_region(message *m)
{
	return OK;
}

int do_ashmem_set_size_region(message *m)
{
	int id;
	long size;
	struct ashmem_area *ashmem;

	id = m->ASHMEM_SET_SIZE_ID;
	size = m->ASHMEM_SET_SIZE_SIZE;

	ashmem = ashmem_find_by_id(id);

	ashmem->page = (vir_bytes) minix_mmap(0, size,
				PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
	if (ashmem->page == (vir_bytes) MAP_FAILED)
		return ENOMEM;

	ashmem->vm_id = vm_getphys(SELF_E, (void *) ashmem->page);
	memset((void *)ashmem->page, 0, size);

	ashmem->shmid_ds.shm_perm.cuid =
		ashmem->shmid_ds.shm_perm.uid = getnuid(who_e);
	ashmem->shmid_ds.shm_perm.cgid =
		ashmem->shmid_ds.shm_perm.gid = getngid(who_e);
	ashmem->shmid_ds.shm_perm.mode = 0777;
	ashmem->shmid_ds.shm_segsz = size;
	ashmem->shmid_ds.shm_atime = 0;
	ashmem->shmid_ds.shm_dtime = 0;
	ashmem->shmid_ds.shm_ctime = time(NULL);
	ashmem->shmid_ds.shm_cpid = getnpid(who_e);
	ashmem->shmid_ds.shm_lpid = 0;
	ashmem->shmid_ds.shm_nattch = 0;
	ashmem->id = id;

	return OK;
}

int do_ashmem_set_prot_region(message *m)
{
	int id;
	unsigned long prot;
	struct ashmem_area *asma;

	id = m->ASHMEM_SET_PROT_ID;
	prot = m->ASHMEM_SET_PROT_PROT;

	asma = ashmem_find_by_id(id);

	if(asma->prot_mask != prot)
		return EINVAL;

	asma->prot_mask = prot;

	return OK;
}

int do_ashmem_pin_region(message *m)
{
	int id;
	size_t len, offset;
	size_t pgstart, pgend;
	struct ashmem_area *asma;
	struct ashmem_range *range, *next;
	int ret = ASHMEM_NOT_PURGED;

	id = m->ASHMEM_PIN_ID;
	len = m->ASHMEM_PIN_LEN;
	offset = m->ASHMEM_PIN_OFFSET;

	asma = ashmem_find_by_id(id);

	pgstart = offset / PAGE_SIZE;
	pgend = pgstart + (len / PAGE_SIZE) - 1;
	
	list_for_each_entry_safe(range, next, &asma->unpinned_list, unpinned) {
	
		if(range_before_page(range, pgstart))
			break;

		if (page_range_in_range(range, pgstart, pgend)) {
			ret |= range->purged;

			/* Case #1: Easy. Just nuke the whole thing. */
			if (page_range_subsumes_range(range, pgstart, pgend)) {
				range_del(range);
				continue;
			}

			/* Case #2: We overlap from the start, so adjust it */
			if (range->pgstart >= pgstart) {
				range_shrink(range, pgend + 1, range->pgend);
				continue;
			}

			/* Case #3: We overlap from the rear, so adjust it */
			if (range->pgend <= pgend) {
				range_shrink(range, range->pgstart, pgstart-1);
				continue;
			}

			/*
		 	* Case #4: We eat a chunk out of the middle. A bit
		 	* more complicated, we allocate a new range for the
		 	* second half and adjust the first chunk's endpoint.
	 	 	*/
			range_alloc(asma, range, range->purged,
					pgend + 1, range->pgend);
			range_shrink(range, range->pgstart, pgstart - 1);
			break;
		}
	}

	return OK;
}

int do_ashmem_unpin_region(message *m)
{
	int id;
	size_t len, offset;
	size_t pgstart, pgend;
	struct ashmem_area *asma;
	struct ashmem_range *range, *next;
	unsigned int purged = ASHMEM_NOT_PURGED;

	id = m->ASHMEM_UNPIN_ID;
	len = m->ASHMEM_UNPIN_LEN;
	offset = m->ASHMEM_UNPIN_OFFSET;

	asma = ashmem_find_by_id(id);

	pgstart = offset / PAGE_SIZE;
	pgend = pgstart + (len / PAGE_SIZE) - 1;

restart:
	list_for_each_entry_safe(range, next, &asma->unpinned_list, unpinned) {
		if(range_before_page(range, pgstart))
			break;

		if(page_range_subsumed_by_range(range, pgstart, pgend))
			return OK;
		if(page_range_in_range(range, pgstart, pgend)) {
			pgstart = min_t(size_t, range->pgstart, pgstart);
			pgend = max_t(size_t, range->pgend, pgend);
			purged |= range->purged;
			range_del(range);
			goto restart;
		}
	}

	range_alloc(asma, range, purged, pgstart, pgend);
	return OK;
}

int do_ashmem_get_size_region(message *m)
{
	return OK;
}
