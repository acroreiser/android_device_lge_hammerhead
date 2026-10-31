// bpf_lmk.c
#ifndef BPF_MAP_TYPE_RINGBUF
# define BPF_MAP_TYPE_RINGBUF 27
#endif

#ifndef BPF_FUNC_ringbuf_output
# define BPF_FUNC_ringbuf_output 130
#endif

#ifndef BPF_MAP_TYPE_HASH
# define BPF_MAP_TYPE_HASH 1
#endif

#ifndef BPF_MAP_TYPE_ARRAY
# define BPF_MAP_TYPE_ARRAY 2
#endif

#ifndef BPF_ANY
# define BPF_ANY 0
#endif

#define SEC(NAME) __attribute__((section(NAME), used))

#define ___GFP_HIGHMEM 0x02u
#define RECLAIM_WB_ANON 0x1

enum bpf_event_reason
{
	MEM_REASON_NONE = 0,
	MEM_REASON_STALL_EXCEEDED = 1,
	MEM_REASON_COUNT_EXCEEDED = 2,
	/* MEM_REASON_FILECACHE = 3, used in userspace daemon */
	MEM_REASON_LOWMEM_DEFICIT = 4,
};

struct bpf_map_def
{
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") rb_map =
{
	.type = BPF_MAP_TYPE_RINGBUF,
	.key_size = 0,
	.value_size = 0,
	.max_entries = 64 * 1024,
	.map_flags = 0,
};

struct proc_info {
	int pid;
	int oom_score_adj;
	char comm[16];
};

struct bpf_map_def SEC("maps") adj_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct proc_info),
    .max_entries = 2048,
    .map_flags = 0,
};

struct bpf_map_def SEC("maps") advice_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct proc_info),
    .max_entries = 2,
    .map_flags = 0,
};

struct bpf_config
{
	u64 window_ns;
	u64 stall_limit_ns;
	u64 rate_limit_ns;
	u32 count_threshold;
	u32 pad;
};

struct bpf_map_def SEC("maps") cfg_map =
{
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct bpf_config),
	.max_entries = 1,
	.map_flags = 0,
};

struct reclaim_state
{
	u64 window_start;
	u64 last_emit;
	u64 stall_ns;
	u32 count;
	u32 pad;
	u64 nr_stalled;
};

struct bpf_map_def SEC("maps") state_map =
{
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct reclaim_state),
	.max_entries = 1,
	.map_flags = 0,
};


struct bpf_map_def SEC("maps") start_map =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
	.max_entries = 1024,
	.map_flags = 0,
};

struct mem_event
{
	unsigned int pid;
	int order;
	unsigned int gfp_flags;
	char comm[16];
	unsigned int reason;		/* enum mem_event_reason */
	unsigned int stall_ms;		/* direct reclaim stall on last window */
	unsigned int reclaim_count;	/* count of direct reclaim calls on last window */
	struct proc_info target;
};

struct direct_reclaim_args
{
	u16 common_type;
	u8 common_flags;
	u8 common_preempt_count;
	int common_pid;
#ifdef COMMON_PADDING
	int common_padding;
#endif
	int order;
	int may_writepage;
	unsigned int gfp_flags;
};

struct direct_reclaim_end_args
{
	u16 common_type;
	u8 common_flags;
	u8 common_preempt_count;
	int common_pid;
#ifdef COMMON_PADDING
	int common_padding;
#endif
	unsigned long nr_reclaimed;
};

struct writepage_args
{
	u16 common_type;
	u8 common_flags;
	u8 common_preempt_count;
	int common_pid;
#ifdef COMMON_PADDING
	int common_padding;
#endif
	u32 page;
	int reclaim_flags;
};

#define GET_STATE(st, cfg, now)                                     \
	u32 st##_zero = 0;                                              \
	struct reclaim_state *st =                                      \
		bpf_map_lookup_elem(&state_map, &st##_zero);                \
	if (!st)                                                        \
		return 0;                                                   \
	if (cfg->window_ns && ((now) - st->window_start > cfg->window_ns)) { \
		st->window_start = (now);                                   \
		st->count = 0;                                              \
		st->stall_ns = 0;                                           \
		st->nr_stalled = 0;        \
	}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
	 int trace_direct_reclaim(struct direct_reclaim_args *ctx)
{
	struct mem_event ev;
	struct proc_info *adv_target;
	u32 active = 1;
	u32 inactive = 2;
	__builtin_memset(&ev, 0, sizeof(ev));

	u64 pid_tgid = bpf_get_current_pid_tgid();

	ev.pid = (unsigned int)(pid_tgid >> 32);
	ev.order = ctx->order;
	ev.gfp_flags = ctx->gfp_flags;

	if (ev.pid == 0)
		return 0;

	bpf_get_current_comm(ev.comm, sizeof(ev.comm));

	u64 now = bpf_ktime_get_ns();

	bpf_map_update_elem(&start_map, &pid_tgid, &now, BPF_ANY);

	u32 cfg_k = 0;
	struct bpf_config *cfg = bpf_map_lookup_elem(&cfg_map, &cfg_k);
	if (!cfg)
		return 0;

	GET_STATE(st, cfg, now);

	st->count++;

	u32 reason = MEM_REASON_NONE;

	adv_target = bpf_map_lookup_elem(&advice_map, &inactive);
	if (adv_target && adv_target->pid > 0)
		__builtin_memcpy(&ev.target, adv_target, sizeof(struct proc_info));

	if (cfg->stall_limit_ns && st->stall_ns >= cfg->stall_limit_ns)
	{
		st->nr_stalled++;
		if (st->nr_stalled > 50) // TODO: make it configurable??
		{
			reason = MEM_REASON_STALL_EXCEEDED;
			st->nr_stalled = 0;
			adv_target = bpf_map_lookup_elem(&advice_map, &active);
			if (adv_target && adv_target->pid > 0)
				__builtin_memcpy(&ev.target, adv_target, sizeof(struct proc_info));
			goto skip;
		}
	}

	if (cfg->count_threshold && st->count >= cfg->count_threshold)
		reason = MEM_REASON_COUNT_EXCEEDED;

	// sometimes we need to kill something active to free up memory in NORMAL zone
	// 32-bit issues. Maybe I should make it configurable???
	if (!(ev.gfp_flags & ___GFP_HIGHMEM)) {
		reason = MEM_REASON_LOWMEM_DEFICIT;
		adv_target = bpf_map_lookup_elem(&advice_map, &active);
		if (adv_target && adv_target->pid > 0)
			__builtin_memcpy(&ev.target, adv_target, sizeof(struct proc_info));
		goto skip;
	}
	
    if (reason == MEM_REASON_NONE && st->count < 50) // trigger userspace to do filecache check at fifty direct reclamations
	 return 0;

	// Rate limit
	if (now - st->last_emit < cfg->rate_limit_ns)
		return 0;
skip:
	st->last_emit = now;

	ev.reason = reason;
	ev.stall_ms = (unsigned int)(st->stall_ns / (1000ULL * 1000));
	ev.reclaim_count = st->count;

	// wake up, Marco
	bpf_ringbuf_output(&rb_map, &ev, sizeof(ev), 0);
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
	 int trace_direct_reclaim_end(struct direct_reclaim_end_args *ctx)
{
	u64 key = bpf_get_current_pid_tgid();
	u64 *start = bpf_map_lookup_elem(&start_map, &key);
	if (!start)
		return 0;

	u64 now = bpf_ktime_get_ns();
	u64 dur = now - *start;
	bpf_map_delete_elem(&start_map, &key);

	u32 cfg_k = 0;
	struct bpf_config *cfg = bpf_map_lookup_elem(&cfg_map, &cfg_k);
	if (!cfg)
		return 0;

	GET_STATE(st, cfg, now);

	st->stall_ns += dur;
	return 0;
}

struct oom_adj_update_args {
	u16 common_type;
	u8 common_flags;
	u8 common_preempt_count;
	int common_pid;
#ifdef COMMON_PADDING
	int common_padding;
#endif
	int pid;
// char comm[16]; {
	u32 comm0;
	u32 comm1;
	u32 comm2;
	u32 comm3;
// }
	int oom_score_adj;
};

#define SLOT_ACTIVE_PREV 1  // Active (ADJ 700-800)
#define SLOT_INACTIVE    2  // Cached (ADJ 900-995)

// let userspace to kill eligible victim without choosing
SEC("tracepoint/oom/oom_score_adj_update")
int trace_oom_adj_update(struct oom_adj_update_args *ctx)
{
    unsigned int pid = (unsigned int)ctx->pid;
    if (pid <= 1)
        return 0;

    struct proc_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.pid = pid;
    info.oom_score_adj = (int)ctx->oom_score_adj;

    u32 *dst32 = (u32 *)info.comm;

    // no pointer math, no (untrolled) loops
    dst32[0] = ctx->comm0;
    dst32[1] = ctx->comm1;
    dst32[2] = ctx->comm2;
    dst32[3] = ctx->comm3;

    bpf_map_update_elem(&adj_map, &pid, &info, BPF_ANY);

    if (info.oom_score_adj < 700) {
        u32 k_act = SLOT_ACTIVE_PREV;
        struct proc_info *cur_act = bpf_map_lookup_elem(&advice_map, &k_act);
        if (cur_act && cur_act->pid == pid) {
            cur_act->pid = 0;
        }

        u32 k_inact = SLOT_INACTIVE;
        struct proc_info *cur_inact = bpf_map_lookup_elem(&advice_map, &k_inact);
        if (cur_inact && cur_inact->pid == pid) {
            cur_inact->pid = 0;
        }
        return 0;
    }

    if (info.oom_score_adj >= 900) {
        u32 k_inact = SLOT_INACTIVE;
        struct proc_info *cur = bpf_map_lookup_elem(&advice_map, &k_inact);
        if (!cur || cur->pid == 0 || cur->oom_score_adj <= info.oom_score_adj) {
            bpf_map_update_elem(&advice_map, &k_inact, &info, BPF_ANY);
        }

        u32 k_act = SLOT_ACTIVE_PREV;
        struct proc_info *cur_act = bpf_map_lookup_elem(&advice_map, &k_act);
        if (cur_act && cur_act->pid == pid) {
            cur_act->pid = 0;
        }
        return 0;
    }

    if (info.oom_score_adj >= 700) {
        u32 k_act = SLOT_ACTIVE_PREV;
        struct proc_info *cur = bpf_map_lookup_elem(&advice_map, &k_act);
        if (!cur || cur->pid == 0 || cur->oom_score_adj <= info.oom_score_adj) {
            bpf_map_update_elem(&advice_map, &k_act, &info, BPF_ANY);
        }

        u32 k_inact = SLOT_INACTIVE;
        struct proc_info *cur_inact = bpf_map_lookup_elem(&advice_map, &k_inact);
        if (cur_inact && cur_inact->pid == pid) {
            cur_inact->pid = 0;
        }
        return 0;
    }

    return 0;
}

// remove dying task from map
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned int pid = (unsigned int)(pid_tgid >> 32);

    bpf_map_delete_elem(&adj_map, &pid);

    u32 k_active = SLOT_ACTIVE_PREV;
    u32 k_inactive = SLOT_INACTIVE;
    struct proc_info *adv_act = bpf_map_lookup_elem(&advice_map, &k_active);
    if (adv_act && adv_act->pid == pid) {
        adv_act->pid = 0;
    }

    struct proc_info *adv_inact = bpf_map_lookup_elem(&advice_map, &k_inactive);
    if (adv_inact && adv_inact->pid == pid) {
        adv_inact->pid = 0;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
