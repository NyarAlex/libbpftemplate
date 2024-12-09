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
#include <linux/types.h>

#include "kcprate.h"

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct keyItem);
  __type(value, __u64);
  __uint(max_entries, 10);
} all_record SEC(".maps");

// ikcp_send
SEC("uprobe")
int bpf_prog_send(struct pt_regs *ctx)
{

  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 bytes = PT_REGS_PARM3(ctx); // 第三个参数是数据长度
  struct keyItem key = {0};
  key.pid = pid;
  key.type = IKCP_SEND;

  __u64 *send_count = bpf_map_lookup_elem(&all_record, &key);
  if (send_count)
  {
    *send_count += bytes;
  }
  else
  {
    __u64 init = bytes;
    bpf_map_update_elem(&all_record, &key, &init, BPF_ANY);
  }

  return 0;
}

// ikcp_input
SEC("uprobe")
int bpf_prog_input(struct pt_regs *ctx)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 bytes = PT_REGS_PARM3(ctx); // 第三个参数是数据长度

  struct keyItem key = {0};
  key.pid = pid;
  key.type = IKCP_INPUT;

  __u64 *send_count = bpf_map_lookup_elem(&all_record, &key);
  if (send_count)
  {
    *send_count += bytes;
  }
  else
  {
    __u64 init = bytes;
    bpf_map_update_elem(&all_record, &key, &init, BPF_ANY);
  }
  return 0;
}

// ikcp_recv
SEC("uretprobe")
int bpf_prog_recv(struct pt_regs *ctx)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  int bytes = PT_REGS_RC(ctx); //获取返回值，ikcp_recv的返回值才是真实长度
  if (bytes<0)
  {
    //跳过小于0的值
    return 0;
  }
  
  struct keyItem key = {0};
  key.pid = pid;
  key.type = IKCP_RECV;

  __u64 *send_count = bpf_map_lookup_elem(&all_record, &key);
  if (send_count)
  {
    *send_count += bytes;
  }
  else
  {
    __u64 init = bytes;
    bpf_map_update_elem(&all_record, &key, &init, BPF_ANY);
  }
  return 0;
}


// ikcp_output
SEC("uprobe")
int bpf_prog_output(struct pt_regs *ctx)
{
   __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 bytes = PT_REGS_PARM3(ctx); // 第三个参数是数据长度

  struct keyItem key = {0};
  key.pid = pid;
  key.type = IKCP_OUTPUT;

  __u64 *send_count = bpf_map_lookup_elem(&all_record, &key);
  if (send_count)
  {
    *send_count += bytes;
  }
  else
  {
    __u64 init = bytes;
    bpf_map_update_elem(&all_record, &key, &init, BPF_ANY);
  }
  return 0;
}

// ikcp_update 用于得到每秒执行次数
SEC("uprobe")
int bpf_prog_update(struct pt_regs *ctx)
{
   __u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct keyItem key = {0};
  key.pid = pid;
  key.type = IKCP_UPDATE;

  __u64 *send_count = bpf_map_lookup_elem(&all_record, &key);
  if (send_count)
  {
    *send_count += 1;
  }
  else
  {
    __u64 init = 1;
    bpf_map_update_elem(&all_record, &key, &init, BPF_ANY);
  }
  return 0;
}
char LICENSE[] SEC("license") = "GPL";