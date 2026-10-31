// this is originally a part of hammerhead device tree
// author: acroreiser (with AI assistance)
// 2026, 11
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <elf.h>
#include <sched.h>
#include <sys/resource.h>

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

#if defined(__has_include)
# if __has_include(<sys/system_properties.h>)
#  include <sys/system_properties.h>
#  define HAVE_SYSTEM_PROPERTIES 1
# endif
#elif defined(__ANDROID__)
# include <sys/system_properties.h>
# define HAVE_SYSTEM_PROPERTIES 1
#endif

#ifndef PROP_VALUE_MAX
# define PROP_VALUE_MAX 92
#endif

#ifndef __NR_bpf
# if defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__arm__)
#  define __NR_bpf 386
# endif
#endif

#ifndef __NR_perf_event_open
# if defined(__x86_64__)
#  define __NR_perf_event_open 298
# elif defined(__aarch64__)
#  define __NR_perf_event_open 241
# elif defined(__arm__)
#  define __NR_perf_event_open 364
# endif
#endif

#ifndef BPF_PROG_TYPE_TRACEPOINT
# define BPF_PROG_TYPE_TRACEPOINT 5
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
# define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_PROG_TYPE_KPROBE
# define BPF_PROG_TYPE_KPROBE 2
#endif
#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD 1
#endif

#ifndef PERF_EVENT_IOC_ENABLE
# define PERF_EVENT_IOC_ENABLE _IO('$', 0)
#endif
#ifndef PERF_EVENT_IOC_SET_BPF
# define PERF_EVENT_IOC_SET_BPF _IOW('$', 8, __u32)
#endif

#define BPF_RINGBUF_BUSY_BIT    (1U << 31)
#define BPF_RINGBUF_DISCARD_BIT (1U << 30)

#define KERNEL_LMK_DISABLED_PATH "/sys/module/lowmemorykiller/parameters/disable"
#define DEFAULT_BPF_OBJ_PATH     "/vendor/etc/marco/bpf_lmk.o"
#define NUM_TIERS 6

struct bpf_config
{
	uint64_t window_ns;
	uint64_t stall_limit_ns;
	uint64_t rate_limit_ns;
	uint32_t count_threshold;
	uint32_t pad;
};

struct lmk_config
{
	int oom_adj[NUM_TIERS];
	int minfree_mb[NUM_TIERS];
	int swap_free_low_percent;
	int kill_timeout_ms;
	int debug;
	int filecache_min_mb;

	/* BPF Stall properties */
	int stall_limit_ms;
	int stall_window_ms;
	int rate_limit_ms;
	int count_threshold;
};

static struct lmk_config cfg = {
	.oom_adj = {0, 100, 200, 300, 700, 900},
	.minfree_mb = {113, 132, 150, 188, 209, 256},
	.swap_free_low_percent = 35,
	.kill_timeout_ms = 100,
	.debug = 0,
	.filecache_min_mb = 110,
	.stall_limit_ms = 700,
	.stall_window_ms = 1000,
	.rate_limit_ms = 50,
	.count_threshold = 400,
};

int oom_score_adj_map_fd = -1;

struct proc_info
{
	int pid;
	int oom_score_adj;
	char comm[16];
};

struct victim_advice
{
	struct proc_info active;
	struct proc_info inactive;
};

static volatile sig_atomic_t stop = 0;
static int is_shell = 0;
static int kmsg_fd = -1;
static uint64_t last_kill_time_ms = 0;
int config_map_fd = -1;

static void sig_handler(int sig)
{
	(void)sig;
	stop = 1;
}

static void init_config_from_props(void);
static int sync_bpf_config(int cfg_map_fd);

static void sigusr_handler(int sig)
{
	(void)sig;
	init_config_from_props();
	sync_bpf_config(config_map_fd);
}

static void lmk_log(int is_crit, const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (is_shell)
	{
		fputs(buf, stdout);
		fflush(stdout);
	}
	if (kmsg_fd >= 0)
	{
		char kbuf[600];
		snprintf(kbuf, sizeof(kbuf), "%s[marco] %s", is_crit ? "<3>" : "<5>", buf);
		write(kmsg_fd, kbuf, strlen(kbuf));
	}
}

static void set_sched_fifo(int pid, int prio)
{
	struct sched_param param;
	memset(&param, 0, sizeof(param));
	param.sched_priority = prio;

	if (sched_setscheduler(pid, SCHED_FIFO, &param) < 0)
	{
		lmk_log(1, "Warning: failed to set SCHED_FIFO (prio %d): %s\n", prio, strerror(errno));
	}
	else
	{
		if (!pid)
			lmk_log(0, "Scheduling policy set to SCHED_FIFO (priority %d)\n", prio);
	}
}

static void lock_memory(void)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &rl) < 0)
		lmk_log(1, "Warning: failed to raise RLIMIT_MEMLOCK: %s\n", strerror(errno));

	if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0)
		lmk_log(1, "Warning: mlockall failed: %s\n", strerror(errno));
	else
		lmk_log(0, "Process memory locked in RAM (mlockall)\n");
}

static void get_clean_kernel_version(char *buf, size_t sz)
{
	struct utsname u;
	int major = 0, minor = 0, patch = 0;

	if (uname(&u) == 0)
	{
		int parsed = sscanf(u.release, "%d.%d.%d", &major, &minor, &patch);
		if (parsed >= 3)
		{
			snprintf(buf, sz, "%d.%d.%d", major, minor, patch);
			return;
		}
		else if (parsed == 2)
		{
			snprintf(buf, sz, "%d.%d", major, minor);
			return;
		}
	}
	snprintf(buf, sz, "unknown");
}

static void set_kernel_lmk_disabled(int disabled)
{
	int fd = open(KERNEL_LMK_DISABLED_PATH, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
	{
		if (errno != ENOENT)
			lmk_log(1, "Warning: failed to open %s: %s\n", KERNEL_LMK_DISABLED_PATH,
					strerror(errno));

		return;
	}

	char val = disabled ? '1' : '0';
	if (write(fd, &val, 1) != 1)
		lmk_log(1, "Warning: failed to write '%c' to %s: %s\n", val, KERNEL_LMK_DISABLED_PATH,
				strerror(errno));
	else
		lmk_log(0, "%s in-kernel LMK (%s = %c)\n",
				disabled ? "Disabled" : "Re-enabled", KERNEL_LMK_DISABLED_PATH, val);

	close(fd);
}

static void atexit_cleanup(void)
{
	set_kernel_lmk_disabled(0);
}

static int property_get(const char *key, char *buf, const char *default_val)
{
#if defined(HAVE_SYSTEM_PROPERTIES)
	int len = __system_property_get(key, buf);
	if (len > 0)
		return len;
#endif
	char env_key[128];
	snprintf(env_key, sizeof(env_key), "%s", key);
	for (char *p = env_key; *p; p++)
	{
		if (*p == '.')
			*p = '_';
	}

	char *v = getenv(env_key);
	if (!v)
		v = getenv(key);
	if (v && *v)
	{
		strncpy(buf, v, PROP_VALUE_MAX - 1);
		buf[PROP_VALUE_MAX - 1] = '\0';
		return strlen(buf);
	}

	if (default_val)
	{
		strncpy(buf, default_val, PROP_VALUE_MAX - 1);
		buf[PROP_VALUE_MAX - 1] = '\0';
		return strlen(buf);
	}
	buf[0] = '\0';
	return 0;
}

static int property_get_bool(const char *key, int default_val)
{
	char buf[PROP_VALUE_MAX];
	if (property_get(key, buf, NULL) <= 0)
		return default_val;
	if (!strcmp(buf, "1") || !strcasecmp(buf, "true") || !strcasecmp(buf, "on")
		|| !strcasecmp(buf, "yes"))
		return 1;
	if (!strcmp(buf, "0") || !strcasecmp(buf, "false") || !strcasecmp(buf, "off")
		|| !strcasecmp(buf, "no"))
		return 0;
	return default_val;
}

static int property_get_int32(const char *key, int default_val)
{
	char buf[PROP_VALUE_MAX];
	if (property_get(key, buf, NULL) <= 0)
		return default_val;
	return atoi(buf);
}

static int parse_int_list(const char *str, int *out_arr, int max_count, int is_minfree)
{
	char tmp[PROP_VALUE_MAX];
	strncpy(tmp, str, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';

	char *token = strtok(tmp, ", \t");
	int count = 0;
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		page_size = 4096;

	while (token && count < max_count)
	{
		int v = atoi(token);
		if (is_minfree && v > 1024)
		{
			v = (int)(((long long)v * page_size) / (1024 * 1024));
		}
		out_arr[count++] = v;
		token = strtok(NULL, ", \t");
	}
	return count;
}

static void init_config_from_props(void)
{
	cfg.kill_timeout_ms = property_get_int32("ro.marco.kill_timeout_ms", cfg.kill_timeout_ms);
	cfg.swap_free_low_percent =
		property_get_int32("ro.marco.swap_free_low_percentage", cfg.swap_free_low_percent);
	cfg.debug = property_get_bool("ro.marco.debug", cfg.debug);
	cfg.filecache_min_mb = property_get_int32("ro.marco.filecache_min_mb", cfg.filecache_min_mb);
	cfg.stall_limit_ms = property_get_int32("ro.marco.stall_limit_ms", cfg.stall_limit_ms);
	cfg.stall_window_ms = property_get_int32("ro.marco.stall_window_ms", cfg.stall_window_ms);
	cfg.rate_limit_ms = property_get_int32("ro.marco.rate_limit_ms", cfg.rate_limit_ms);
	cfg.count_threshold = property_get_int32("ro.marco.count_threshold", cfg.count_threshold);

	char val[PROP_VALUE_MAX];
	if (property_get("ro.marco.minfree_mb", val, NULL) > 0)
		parse_int_list(val, cfg.minfree_mb, NUM_TIERS, 1);

	if (property_get("ro.marco.oom_adj", val, NULL) > 0)
		parse_int_list(val, cfg.oom_adj, NUM_TIERS, 0);
}

enum mem_event_reason
{
	MEM_REASON_NONE = 0,
	MEM_REASON_STALL_EXCEEDED = 1,
	MEM_REASON_COUNT_EXCEEDED = 2,
	MEM_REASON_FILECACHE = 3,
	MEM_REASON_LOWMEM_DEFICIT = 4,
};

struct mem_event
{
	unsigned int pid;
	int order;
	unsigned int gfp_flags;
	char comm[16];
	unsigned int reason;
	unsigned int stall_ms;
	unsigned int reclaim_count;
	struct proc_info target;
};

struct mem_info
{
	unsigned long mem_total;
	unsigned long mem_free;
	unsigned long mem_available;
	unsigned long swap_total;
	unsigned long swap_free;
	unsigned long active_file;
	unsigned long inactive_file;
};

static const char *get_mem_reason_desc(struct mem_event *ev, struct mem_info *mi, int reason,
									   char *buf, size_t sz)
{
	switch (reason) {
	case MEM_REASON_STALL_EXCEEDED:
		snprintf(buf, sz, "LATENCY_STALL (%u ms >= %d ms limit)",
				 ev->stall_ms, cfg.stall_limit_ms);
		break;

	case MEM_REASON_COUNT_EXCEEDED:
		snprintf(buf, sz, "HIGH_FREQUENCY (%u calls/window >= %d)",
				 ev->reclaim_count, cfg.count_threshold);
		break;

	case MEM_REASON_FILECACHE:
		snprintf(buf, sz, "FILECACHE (Active(file) %u < %d)",
				 mi->active_file, cfg.filecache_min_mb);
		break;

	case MEM_REASON_LOWMEM_DEFICIT:
		snprintf(buf, sz, "LOWMEM_DEFICIT");
		break;

	default:
		snprintf(buf, sz, "UNKNOWN (code %u)", reason);
		break;
	}

	return buf;
}

static uint64_t get_time_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t) tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int read_meminfo(struct mem_info *mi)
{
	FILE *f = fopen("/proc/meminfo", "r");
	if (!f)
		return -1;

	memset(mi, 0, sizeof(*mi));

	char line[128];
	unsigned long cached = 0, buffers = 0;
	int has_avail = 0;

	while (fgets(line, sizeof(line), f))
	{
		unsigned long val;
		if (sscanf(line, "MemTotal: %lu kB", &val) == 1)
			mi->mem_total = val / 1024;
		else if (sscanf(line, "MemFree: %lu kB", &val) == 1)
			mi->mem_free = val / 1024;
		else if (sscanf(line, "MemAvailable: %lu kB", &val) == 1)
		{
			mi->mem_available = val / 1024;
			has_avail = 1;
		}
		else if (sscanf(line, "Buffers: %lu kB", &val) == 1)
			buffers = val / 1024;
		else if (sscanf(line, "Cached: %lu kB", &val) == 1)
			cached = val / 1024;
		else if (sscanf(line, "Active(file): %lu kB", &val) == 1)
			mi->active_file = val / 1024;
		else if (sscanf(line, "Inactive(file): %lu kB", &val) == 1)
			mi->inactive_file = val / 1024;
		else if (sscanf(line, "SwapTotal: %lu kB", &val) == 1)
			mi->swap_total = val / 1024;
		else if (sscanf(line, "SwapFree: %lu kB", &val) == 1)
			mi->swap_free = val / 1024;
	}
	fclose(f);

	if (!has_avail)
	{
		mi->mem_available = mi->mem_free + cached + buffers;
	}
	return 0;
}

static int get_target_adj(struct mem_info *mi, int reason)
{
	int target_adj = -1;

	for (int i = 0; i < NUM_TIERS; i++)
	{
		if (mi->mem_available < (unsigned long)cfg.minfree_mb[i])
		{
			target_adj = cfg.oom_adj[i];
			break;
		}
	}

	if (mi->swap_total > 0 && target_adj >= 0)
	{
		unsigned long swap_pct = (mi->swap_free * 100) / mi->swap_total;
		if (swap_pct < (unsigned long)cfg.swap_free_low_percent && target_adj > 0)
		{
			target_adj = (target_adj <= 100) ? 0 : target_adj - 100;
		}
	}

	switch (reason) {
	case MEM_REASON_STALL_EXCEEDED:
		if (target_adj < 0 || target_adj > 800)
			target_adj = 700;

		break;

	case MEM_REASON_FILECACHE:
		if (target_adj == -1)
			target_adj = 950;

		break;

	case MEM_REASON_LOWMEM_DEFICIT:
		if (target_adj > 700)
			target_adj = 700;

		break;
	}

	return target_adj;
}

/* BPF_MAP_GET_NEXT_KEY */
static int map_next_key(int fd, const __u32 * key, __u32 * next_key)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.map_fd = fd;
	attr.key = (uint64_t) (uintptr_t) key;
	attr.next_key = (uint64_t) (uintptr_t) next_key;

	return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

/* BPF_MAP_LOOKUP_ELEM */
static int map_lookup(int fd, const __u32 * key, __u32 * value)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.map_fd = fd;
	attr.key = (uint64_t) (uintptr_t) key;
	attr.value = (uint64_t) (uintptr_t) value;

	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int find_best_victim(int map_fd, uint32_t max_entries,
									  int32_t min_adj, int32_t max_adj, struct proc_info *best)
{
	uint32_t key;
	uint32_t next_key;
	bool have_key = false;
	bool found = false;

	for (uint32_t i = 0; i < max_entries; i++)
	{

		if (map_next_key(map_fd, have_key ? &key : NULL, &next_key) < 0)
		{
			if (errno == ENOENT)
				break;

			return -1;
		}

		key = next_key;
		have_key = true;

		struct proc_info target;

		if (map_lookup(map_fd, &key, &target) < 0)
		{
			if (errno == ENOENT)
				continue;

			return -1;
		}

		if (target.oom_score_adj < min_adj || target.oom_score_adj >= max_adj)
			continue;

		if (!found || target.oom_score_adj > best->oom_score_adj)
		{
			best->pid = target.pid;
			best->oom_score_adj = target.oom_score_adj;
			strlcpy(best->comm, &target.comm, 15);
			found = true;
		}
	}

	return found ? 1 : 0;
}

static void try_kill_process(struct mem_event *ev)
{
	uint64_t now = get_time_ms();
	int reason = MEM_REASON_NONE;
	int ret;
	bool do_fallback = false;
	bool victim_from_event = false;

	reason = ev->reason;

	if (now - last_kill_time_ms < (uint64_t) cfg.kill_timeout_ms
		&& reason != MEM_REASON_STALL_EXCEEDED)
	{
		return;
	}

	struct mem_info mi;
	if (read_meminfo(&mi) < 0)
		return;


	// we are woken up by kernel to check filecache
	if (reason == MEM_REASON_NONE) {
		if (mi.active_file < (unsigned long)cfg.filecache_min_mb)
			reason = MEM_REASON_FILECACHE;
		else
			return;
	}

	// kernel suggested a victim, just kill it
	// fastest path
	if (ev->target.pid)
	{
		victim_from_event = true;
		goto kill_by_advice;
	}

	// no kernel-provided victim,
	// find best victim in oom adj map
	// it is bpf map, fast path
	int min_adj = get_target_adj(&mi, reason);
	if (min_adj < 0)
	{
		if (cfg.debug)
		{
			lmk_log(0, "Event from %s (PID %d), but MemAvailable (%lu MB) is above thresholds\n",
					ev->comm, ev->pid, mi.mem_available);
		}
		return;
	}

	int victim_pid = -1;
	int victim_adj = -1001;
	unsigned long victim_rss = 0;
	char victim_comm[32] = "unknown";
	char path[64];
	long page_size = sysconf(_SC_PAGESIZE);
	struct proc_info victim;

	ret = find_best_victim(oom_score_adj_map_fd, 2048,	// max_entries
									 min_adj,
									 reason == MEM_REASON_LOWMEM_DEFICIT ? 895 : 1000,
									 &victim);

	if (ret > 0)
	{
		snprintf(path, sizeof(path), "/proc/%d/statm", victim.pid);
		FILE *f = fopen(path, "r");
		f = fopen(path, "r");
		if (!f)
		{
			do_fallback = true;
			goto fallback;
		}

		victim_pid = victim.pid;
		victim_adj = victim.oom_score_adj;
		strlcpy(victim_comm, victim.comm, 15);

		unsigned long size_pg, res_pg;
		if (fscanf(f, "%lu %lu", &size_pg, &res_pg) != 2)
			victim_rss = 0;
		else
			victim_rss = (res_pg * page_size) / (1024 * 1024);

		fclose(f);
	}
	else
		do_fallback = true;

	// no eligible tasks in oom adj map? =(
	// fall back to procfs
	// slow path
fallback:
	if (do_fallback)
	{
		DIR *d = opendir("/proc");
		if (!d)
			return;

		long page_size = sysconf(_SC_PAGESIZE);

		struct dirent *de;
		while ((de = readdir(d)))
		{
			if (de->d_name[0] < '0' || de->d_name[0] > '9')
				continue;
			int pid = atoi(de->d_name);
			if (pid <= 1)
				continue;

			snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", pid);
			FILE *f = fopen(path, "r");
			if (!f)
				continue;

			int adj = -1;
			if (fscanf(f, "%d", &adj) != 1)
			{
				fclose(f);
				continue;
			}

			fclose(f);

			if (adj < min_adj || adj <= -1)
				continue;

			snprintf(path, sizeof(path), "/proc/%d/statm", pid);
			f = fopen(path, "r");
			if (!f)
				continue;

			unsigned long size_pg, res_pg;
			if (fscanf(f, "%lu %lu", &size_pg, &res_pg) != 2)
			{
				fclose(f);
				continue;
			}

			fclose(f);

			unsigned long rss_mb = (res_pg * page_size) / (1024 * 1024);
			if (rss_mb == 0)
				continue;

			int select = 0;

			if (adj >= min_adj)
			{
				switch (reason)
				{
				case MEM_REASON_STALL_EXCEEDED:
					select = 1;
					break;

				case MEM_REASON_COUNT_EXCEEDED:
				case MEM_REASON_FILECACHE:
					if (rss_mb > victim_rss)
						select = 1;
					break;

				case MEM_REASON_LOWMEM_DEFICIT:
					if (victim_adj == -1001) // first time you need to pick up any eligible task
						select = 1;
					else if (adj < victim_adj) // then you looking for task with lowest oom_score_adj
						select = 1;
					break;
				}
			}

			if (select)
			{
				victim_pid = pid;
				victim_adj = adj;
				victim_rss = rss_mb;

				snprintf(path, sizeof(path), "/proc/%d/comm", pid);
				f = fopen(path, "r");
				if (f)
				{
					if (fgets(victim_comm, sizeof(victim_comm), f))
						victim_comm[strcspn(victim_comm, "\n")] = 0;
					fclose(f);
				}
				if (reason == MEM_REASON_STALL_EXCEEDED)
					break;
			}
		}
		closedir(d);
	}

// just kill it, Marco
kill_by_advice:
	if (victim_from_event)
		victim_pid = ev->target.pid;

	if (victim_pid > 0)
	{
		if (kill(victim_pid, SIGKILL) == 0)
		{
			last_kill_time_ms = now;
			char r_desc[96];
			get_mem_reason_desc(ev, &mi, reason, r_desc, sizeof(r_desc));
			lmk_log(1,
					"Killing '%s' %s(PID %d, adj %d, RSS %lu MB) | Reason: %s | Triggered by '%s' (%d) | Avail: %lu MB (minfree adj >= %d)\n",
					victim_from_event ? ev->target.comm : victim_comm,
					victim_from_event ? "A " : do_fallback ? "F " : "M ", victim_pid,
					victim_from_event ? ev->target.oom_score_adj : victim_adj,
					victim_from_event ? 0 : victim_rss, r_desc, ev->comm, ev->pid,
					mi.mem_available, min_adj);
		}
		else
			lmk_log(1, "Failed to kill PID %d (%s): %s\n", victim_pid, victim_comm,
					strerror(errno));
	}
}

struct ringbuf_user
{
	int fd;
	size_t size;
	unsigned long *consumer_pos;
	unsigned long *producer_pos;
	void *data;
};

static int ringbuf_init(struct ringbuf_user *rb, int map_fd, size_t size)
{
	long page_size = sysconf(_SC_PAGESIZE);
	rb->fd = map_fd;
	rb->size = size;

	void *cons = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (cons == MAP_FAILED)
		return -1;

	rb->consumer_pos = (unsigned long *)cons;

	size_t prod_sz = page_size + 2 * size;
	void *prod = mmap(NULL, prod_sz, PROT_READ, MAP_SHARED, map_fd, page_size);
	if (prod == MAP_FAILED)
	{
		munmap(cons, page_size);
		return -1;
	}

	rb->producer_pos = (unsigned long *)prod;
	rb->data = (void *)((char *)prod + page_size);
	return 0;
}

static void ringbuf_consume(struct ringbuf_user *rb)
{
	unsigned long cons = __atomic_load_n(rb->consumer_pos, __ATOMIC_ACQUIRE);
	unsigned long prod = __atomic_load_n(rb->producer_pos, __ATOMIC_ACQUIRE);
	unsigned long mask = rb->size - 1;

	while (cons < prod)
	{
		uint32_t *hdr = (uint32_t *) ((char *)rb->data + (cons & mask));
		uint32_t len = *hdr;

		if (len & BPF_RINGBUF_BUSY_BIT)
			break;

		if (!(len & BPF_RINGBUF_DISCARD_BIT))
		{
			struct mem_event *ev = (struct mem_event *)(hdr + 2);
			try_kill_process(ev);
		}

		uint32_t data_len = len & 0x3FFFFFFF;
		uint32_t total_len = ((data_len + 7) & ~7) + 8;
		cons += total_len;
		__atomic_store_n(rb->consumer_pos, cons, __ATOMIC_RELEASE);
	}
}

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd,
							   unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int get_tracepoint_id(const char *subsys, const char *event)
{
	char path[256];

	snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%s/%s/id", subsys, event);

	FILE *f = fopen(path, "r");
	if (!f)
	{
		snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s/id", subsys, event);
		f = fopen(path, "r");
	}

	if (!f)
		return -1;

	int id = -1;
	if (fscanf(f, "%d", &id) != 1)
		id = -1;

	fclose(f);
	return id;
}

#define LMK_MAX_PROGS 8

struct lmk_map_def
{
	uint32_t type, key_size, value_size, max_entries, map_flags;
};

struct lmk_prog
{
	int fd;
	int tp_id;
};

struct lmk_bpf
{
	int rb_fd;
	size_t rb_size;
	int cfg_fd;
	int nprogs;
	struct lmk_prog progs[LMK_MAX_PROGS];
};

static int tracing_write(const char *file, const char *text)
{
	static const char *bases[] = { "/sys/kernel/debug/tracing/", "/sys/kernel/tracing/" };
	for (unsigned i = 0; i < sizeof(bases) / sizeof(bases[0]); i++)
	{
		char path[160];

		snprintf(path, sizeof(path), "%s%s", bases[i], file);

		int fd = open(path, O_WRONLY | O_APPEND);
		if (fd < 0)
			continue;

		ssize_t n = write(fd, text, strlen(text));
		close(fd);

		return n < 0 ? -1 : 0;
	}
	return -1;
}

static int create_map(const struct lmk_map_def *d)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = d->type;
	attr.key_size = d->key_size;
	attr.value_size = d->value_size;
	attr.max_entries = d->max_entries;
	attr.map_flags = d->map_flags;

	int fd = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0 && errno == E2BIG)
		fd = sys_bpf(BPF_MAP_CREATE, &attr, 24);

	return fd;
}

static char verifier_log[256 * 1024];

static int load_bpf_object(const char *file, struct lmk_bpf *o)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &rl))
		fprintf(stderr, "warning: cannot raise RLIMIT_MEMLOCK: %s\n", strerror(errno));

	memset(o, 0, sizeof(*o));
	o->rb_fd = -1;
	o->cfg_fd = -1;

	FILE *f = fopen(file, "rb");
	if (!f)
	{
		fprintf(stderr, "[-] fopen bpf obj '%s': %s\n", file, strerror(errno));
		return -1;
	}
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *buf = malloc(sz);
	if (!buf || fread(buf, 1, sz, f) != (size_t) sz)
	{
		free(buf);
		fclose(f);
		return -1;
	}
	fclose(f);

	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) buf;
	Elf64_Shdr *shdrs = (Elf64_Shdr *) (buf + ehdr->e_shoff);
	const char *shstrtab = buf + shdrs[ehdr->e_shstrndx].sh_offset;

	int maps_idx = -1, symtab_idx = -1;
	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		const char *name = shstrtab + shdrs[i].sh_name;
		if (strcmp(name, "maps") == 0 || strcmp(name, ".maps") == 0)
			maps_idx = i;
		else if (shdrs[i].sh_type == SHT_SYMTAB)
			symtab_idx = i;
	}
	if (maps_idx < 0 || symtab_idx < 0)
	{
		fprintf(stderr, "[-] no maps/symtab section in object\n");
		free(buf);
		return -1;
	}

	Elf64_Sym *syms = (Elf64_Sym *) (buf + shdrs[symtab_idx].sh_offset);
	size_t nsyms = shdrs[symtab_idx].sh_size / sizeof(Elf64_Sym);
	const char *strtab = buf + shdrs[shdrs[symtab_idx].sh_link].sh_offset;

	int *symfd = malloc(nsyms * sizeof(int));
	for (size_t s = 0; s < nsyms; s++)
		symfd[s] = -1;

	for (size_t s = 0; s < nsyms; s++)
	{
		if (syms[s].st_shndx != maps_idx)
			continue;
		if (syms[s].st_value + sizeof(struct lmk_map_def) > shdrs[maps_idx].sh_size)
			continue;
		struct lmk_map_def def;
		memcpy(&def, buf + shdrs[maps_idx].sh_offset + syms[s].st_value, sizeof(def));

		int fd = create_map(&def);
		if (fd < 0)
		{
			fprintf(stderr, "BPF_MAP_CREATE failed (type %u): %s (errno %d)\n", def.type,
					strerror(errno), errno);
			free(symfd);
			free(buf);
			return -1;
		}
		symfd[s] = fd;
		if (def.type == BPF_MAP_TYPE_RINGBUF && o->rb_fd < 0)
		{
			o->rb_fd = fd;
			o->rb_size = def.max_entries;
		}
		const char *sym_name = strtab + syms[s].st_name;

		if (strcmp(sym_name, "cfg_map") == 0)
			o->cfg_fd = fd;

		if (strcmp(sym_name, "adj_map") == 0)
			oom_score_adj_map_fd = fd;
	}

	if (o->rb_fd < 0)
	{
		fprintf(stderr, "[-] no ringbuf map in object\n");
		free(symfd);
		free(buf);
		return -1;
	}

	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		const char *name = shstrtab + shdrs[i].sh_name;
		if (strncmp(name, "tracepoint/", 11) != 0)
			continue;
		if (o->nprogs >= LMK_MAX_PROGS)
			break;

		char subsys[64], event[64];

		if (sscanf(name + 11, "%63[^/]/%63s", subsys, event) != 2)
			continue;

		int required = strstr(event, "direct_reclaim_begin") != NULL;

		char *code = buf + shdrs[i].sh_offset;

		for (int r = 0; r < ehdr->e_shnum; r++)
		{
			Elf64_Shdr *rs = &shdrs[r];
			if ((rs->sh_type != SHT_REL && rs->sh_type != SHT_RELA) ||
				rs->sh_info != (Elf64_Word) i)
				continue;

			size_t entsize = rs->sh_entsize ? rs->sh_entsize :
				(rs->sh_type == SHT_RELA ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel));

			for (size_t k = 0; k < rs->sh_size / entsize; k++)
			{
				Elf64_Rel *rel = (Elf64_Rel *) (buf + rs->sh_offset + k * entsize);
				size_t sym = ELF64_R_SYM(rel->r_info);

				if (sym >= nsyms || symfd[sym] < 0)
				{
					fprintf(stderr, "[-] %s: relocation against non-map symbol %zu\n", name, sym);
					free(symfd);
					free(buf);
					return -1;
				}

				code[rel->r_offset + 1] =
					(code[rel->r_offset + 1] & 0x0F) | (BPF_PSEUDO_MAP_FD << 4);
				*(int32_t *) (code + rel->r_offset + 4) = symfd[sym];
			}
		}

		int tp_id = get_tracepoint_id(subsys, event);
		if (tp_id < 0)
		{
			fprintf(stderr, "[%c] tracepoint %s:%s not found\n", required ? '-' : '!', subsys,
					event);

			if (required)
				goto fail;

			continue;
		}

		union bpf_attr attr;
		memset(&attr, 0, sizeof(attr));
		verifier_log[0] = 0;
		attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
		attr.insns = (uint64_t) (uintptr_t) code;
		attr.insn_cnt = shdrs[i].sh_size / 8;
		attr.license = (uint64_t) (uintptr_t) "GPL";
		attr.log_level = 1;
		attr.log_size = sizeof(verifier_log);
		attr.log_buf = (uint64_t) (uintptr_t) verifier_log;

		int prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
		if (prog_fd < 0 && errno == E2BIG)
			prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, 48);

		if (prog_fd < 0)
		{
			fprintf(stderr, "BPF_PROG_LOAD %s failed: %s (errno %d)\n%s\n", name, strerror(errno),
					errno, verifier_log);

			if (required)
				goto fail;

			continue;
		}

		o->progs[o->nprogs].fd = prog_fd;
		o->progs[o->nprogs].tp_id = tp_id;
		o->nprogs++;
	}

	free(symfd);
	free(buf);
	return o->nprogs > 0 ? 0 : -1;

  fail:
	free(symfd);
	free(buf);
	return -1;
}

static int sync_bpf_config(int cfg_map_fd)
{
	if (cfg_map_fd < 0)
		return 0;

	struct bpf_config bcfg;
	memset(&bcfg, 0, sizeof(bcfg));

	bcfg.stall_limit_ns = (uint64_t) cfg.stall_limit_ms * 1000000ULL;
	bcfg.window_ns = (uint64_t) cfg.stall_window_ms * 1000000ULL;
	bcfg.rate_limit_ns = (uint64_t) cfg.rate_limit_ms * 1000000ULL;
	bcfg.count_threshold = cfg.count_threshold;

	uint32_t key = 0;
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = cfg_map_fd;
	attr.key = (uint64_t) (uintptr_t) & key;
	attr.value = (uint64_t) (uintptr_t) & bcfg;
	attr.flags = 0;

	int err = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	if (err < 0)
	{
		lmk_log(1, "Warning: failed to update BPF cfg_map: %s\n", strerror(errno));
		return -1;
	}

	lmk_log(0,
			"BPF thresholds synced: stall >= %d ms, window = %d ms, rate_limit = %d ms, count = %d\n",
			cfg.stall_limit_ms, cfg.stall_window_ms, cfg.rate_limit_ms, cfg.count_threshold);

	return 0;
}

static void print_usage(const char *prog_name)
{
	printf("Usage: %s [options]\n", prog_name);
	printf("Options:\n");
	printf("  -o <path>    Path to eBPF object file (default: %s)\n", DEFAULT_BPF_OBJ_PATH);
	printf("  -h           Show this help message\n");
}

int main(int argc, char **argv)
{
	const char *bpf_obj_path = DEFAULT_BPF_OBJ_PATH;
	int opt;

	while ((opt = getopt(argc, argv, "o:h")) != -1)
	{
		switch (opt)
		{
		case 'o':
			bpf_obj_path = optarg;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGQUIT, sig_handler);

	atexit(atexit_cleanup);

	is_shell = isatty(STDOUT_FILENO);
	kmsg_fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);

	set_sched_fifo(0, 1);
	lock_memory();
	set_kernel_lmk_disabled(1);
	init_config_from_props();

	char kern_ver[32];
	get_clean_kernel_version(kern_ver, sizeof(kern_ver));

	lmk_log(0, "Starting BPF LowMemoryKiller daemon (Kernel %s)...\n", kern_ver);
	lmk_log(0, "Loading BPF object from: %s\n", bpf_obj_path);

	struct lmk_bpf bpf;
	int err = load_bpf_object(bpf_obj_path, &bpf);
	if (err < 0)
	{
		lmk_log(1, "Failed to load eBPF object from '%s': %d\n", bpf_obj_path, err);
		return 1;
	}

	sync_bpf_config(bpf.cfg_fd);

	config_map_fd = bpf.cfg_fd;
	signal(SIGUSR1, sigusr_handler);

	struct ringbuf_user rb;
	if (ringbuf_init(&rb, bpf.rb_fd, bpf.rb_size) < 0)
	{
		lmk_log(1, "Failed to mmap ringbuf\n");
		return 1;
	}

	int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus <= 0)
		ncpus = 1;

	int nperf = ncpus * bpf.nprogs;
	int *perf_fds = malloc(sizeof(int) * nperf);

	for (int p = 0; p < bpf.nprogs; p++)
	{
		for (int i = 0; i < ncpus; i++)
		{
			struct perf_event_attr pattr;
			memset(&pattr, 0, sizeof(pattr));

			pattr.type = PERF_TYPE_TRACEPOINT;
			pattr.config = bpf.progs[p].tp_id;
			pattr.size = sizeof(pattr);

			int pfd = sys_perf_event_open(&pattr, -1, i, -1, 0);
			perf_fds[p * ncpus + i] = pfd;
			if (pfd >= 0)
			{
				ioctl(pfd, PERF_EVENT_IOC_SET_BPF, bpf.progs[p].fd);
				ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
			}
			else
				lmk_log(1, "perf_event_open failed (tp %d, cpu %d): %s\n", bpf.progs[p].tp_id, i,
						strerror(errno));
		}
	}

	int epfd = syscall(__NR_epoll_create1, O_CLOEXEC);
	struct epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.fd = bpf.rb_fd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, bpf.rb_fd, &ev);

	char minfree_str[128] = { 0 };
	char oom_adj_str[128] = { 0 };
	for (int i = 0; i < NUM_TIERS; i++)
	{
		char buf[16];
		snprintf(buf, sizeof(buf), "%s%d", (i > 0) ? "," : "", cfg.minfree_mb[i]);
		strncat(minfree_str, buf, sizeof(minfree_str) - strlen(minfree_str) - 1);

		snprintf(buf, sizeof(buf), "%s%d", (i > 0) ? "," : "", cfg.oom_adj[i]);
		strncat(oom_adj_str, buf, sizeof(oom_adj_str) - strlen(oom_adj_str) - 1);
	}

	lmk_log(0,
			"Config: Minfree=[%s] MB, OomAdj=[%s], Cooldown=%d ms, SwapLow=%d%%, Debug=%d\n",
			minfree_str, oom_adj_str, cfg.kill_timeout_ms,
			cfg.swap_free_low_percent, cfg.debug);
	lmk_log(0, "Monitoring memory pressure...\n");

	while (!stop)
	{
		struct epoll_event events[4];
		int nfds = epoll_wait(epfd, events, 1, -1);
		if (nfds > 0)
			ringbuf_consume(&rb);
	}

	lmk_log(0, "Shutting down...\n");

	set_kernel_lmk_disabled(0);

	close(epfd);
	for (int i = 0; i < nperf; i++)
	{
		if (perf_fds[i] >= 0)
			close(perf_fds[i]);
	}

	free(perf_fds);

	for (int p = 0; p < bpf.nprogs; p++)
		close(bpf.progs[p].fd);

	close(bpf.rb_fd);

	if (bpf.cfg_fd >= 0)
		close(bpf.cfg_fd);

	if (kmsg_fd >= 0)
		close(kmsg_fd);

	return 0;
}
