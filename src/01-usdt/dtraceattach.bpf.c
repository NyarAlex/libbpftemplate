#include <linux/types.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <linux/ptrace.h>
#include <stdint.h>

#include <linux/bpf.h>
#include <bpf/usdt.bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "dtraceattach.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, int);
} perf_map SEC(".maps");

static int processDtrace6Args(struct pt_regs *ctx)
{
	struct data_t evt = {0};
	long temp = 0;
	bpf_usdt_arg(ctx, 0, &temp);
	evt.id = temp;
	bpf_usdt_arg(ctx, 1, &temp);
	bpf_probe_read_user_str(evt.event,sizeof(evt.event),(char *) temp);
	bpf_usdt_arg(ctx, 2, &temp);
	evt.value = *(double *)&temp;
	

	// 将事件发送到用户态
	bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

	return 0;
}

SEC("usdt")
int handle_dtrace6(struct pt_regs *ctx)
{
	return processDtrace6Args(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
