#include <stdio.h>
#include <ctype.h>
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include "kcprate.skel.h"
#include "kcprate.h"
#include <arpa/inet.h>

#define BINARY_PATH_SIZE (256)
#define PERF_BUFFER_PAGES (32)
#define PERF_POLL_TIMEOUT_MS (200)

static struct env
{
  pid_t pid;
  int time;
  bool exiting;
  bool verbose;
  char bpf_path[BINARY_PATH_SIZE];
  char bin_path[BINARY_PATH_SIZE];
} env = {
    .pid = -1,
    .time = 1000,
    .exiting = false,
    .verbose = false,
};

const char *argp_program_version = "kcprate 0.1";
const char *argp_program_bug_address =
    "";

const char argp_program_doc[] =
    "获取kcp传输速率\n"
    "\n"
    "USAGE: kcprate [--help] [-p PID] [-P bpf_path] [-B bin_path]\n"
    "\n"
    "EXAMPLES:\n"
    "kcprate -p 185 -P /test/a.bpf -B /test/run\n";

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "Trace this PID only"},
    {"path", 'P', "bpf_path", 0, "bpf filepath"},
    {"binpath", 'B', "bin_path", 0, "bin path"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
  int err = 0;

  switch (key)
  {
  case 'h':
    argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
    break;
  case 'P':
    strcpy(env.bpf_path, arg);
    break;
  case 'p':
    errno = 0;
    env.pid = strtol(arg, NULL, 10);
    if (errno)
    {
      err = errno;
      fprintf(stderr, "invalid PID: %s\n", arg);
      argp_usage(state);
    }
    break;
  case 'B':
    strcpy(env.bin_path, arg);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return err;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  if (level == LIBBPF_DEBUG && !env.verbose)
    return 0;

  return vfprintf(stderr, format, args);
}

#define PATH_MAX 4096
/// @brief 可以从文件路径获取pin住的bpf map
/// @param pin_dir pin住的map的文件路径，例如/sys/fs/bps
/// @param mapname
/// @return
int open_bpf_map_file(const char *pin_dir, const char *mapname)
{
  char filename[PATH_MAX];
  int len, fd;

  len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
  if (len < 0)
  {
    fprintf(stderr, "ERR: constructing full mapname path\n");
    return -1;
  }

  fd = bpf_obj_get(filename);
  if (fd < 0)
  {
    fprintf(stderr, "WARN: Failed to open bpf map file:%s err(%d):%s\n", filename,
            errno, strerror(errno));
  }

  return fd;
}
/// @brief 加载bpf-elf格式的文件，填充bpfctx
/// @param filename bpf文件路径
int load_bpf_object_file_with_filename(const char *filename, struct kcprate_bpf *bpfctx)
{
  int err;
  struct bpf_object *obj;
  obj = bpf_object__open_file(filename, NULL);
  if (libbpf_get_error(obj))
  {
    printf("open object file failed: %s\n", strerror(errno));
    return -1;
  }
  bpfctx->progs.bpf_prog_send = bpf_object__find_program_by_name(obj, "bpf_prog_send");
  if (bpfctx->progs.bpf_prog_send == NULL)
  {
    printf("find program in object failed: %s\n", strerror(errno));
    return -1;
  }

  bpfctx->progs.bpf_prog_recv = bpf_object__find_program_by_name(obj, "bpf_prog_recv");
  if (bpfctx->progs.bpf_prog_recv == NULL)
  {
    printf("find program in object failed: %s\n", strerror(errno));
    return -1;
  }
  bpfctx->progs.bpf_prog_input = bpf_object__find_program_by_name(obj, "bpf_prog_input");
  if (bpfctx->progs.bpf_prog_input == NULL)
  {
    printf("find program in object failed: %s\n", strerror(errno));
    return -1;
  }

  bpfctx->progs.bpf_prog_output = bpf_object__find_program_by_name(obj, "bpf_prog_output");
  if (bpfctx->progs.bpf_prog_output == NULL)
  {
    printf("find program in object failed: %s\n", strerror(errno));
    return -1;
  }

  bpfctx->progs.bpf_prog_update = bpf_object__find_program_by_name(obj, "bpf_prog_update");
  if (bpfctx->progs.bpf_prog_update == NULL)
  {
    printf("find program in object failed: %s\n", strerror(errno));
    return -1;
  }

  bpfctx->obj = obj;

  err = bpf_object__load(obj);
  if (err)
  {
    printf("load bpf object failed: %s\n", strerror(errno));
    return -1;
  }

  // ## 获取bpf map的指针
  bpfctx->maps.all_record = bpf_object__find_map_by_name(bpfctx->obj, "all_record");

  return 0;
}

static void sig_handler(int sig)
{
  env.exiting = true;
}

struct Stat
{
  __u64 send_bytes;
  __u64 recv_bytes;
  __u64 input_bytes;
  __u64 output_bytes;
  __u64 update_time;
};

int main(int argc, char **argv)
{
  static const struct argp argp = {
      .options = opts,
      .parser = parse_arg,
      .doc = argp_program_doc,
  };

  int err;
  struct perf_buffer *pb = NULL;

  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  printf("当前bpf路径:%s\n", env.bpf_path);
  printf("当前bin路径:%s\n", env.bin_path);

  libbpf_set_print(libbpf_print_fn);
  struct kcprate_bpf bpfctx = {0};

  load_bpf_object_file_with_filename(env.bpf_path, &bpfctx);

  LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
  /* Attach tracepoint handler */
  uprobe_opts.func_name = "ikcp_send";
  uprobe_opts.retprobe = false;
  bpfctx.links.bpf_prog_send = bpf_program__attach_uprobe_opts(bpfctx.progs.bpf_prog_send,
                                                               env.pid /* self pid */, env.bin_path,
                                                               0 /* offset for function */,
                                                               &uprobe_opts /* opts */);
  if (!bpfctx.links.bpf_prog_send)
  {
    err = errno;
    fprintf(stderr, "attach bpf_prog_send failed: %s\n", strerror(err));
    goto cleanup;
  }

  uprobe_opts.func_name = "ikcp_recv";
  uprobe_opts.retprobe = true;
  bpfctx.links.bpf_prog_recv = bpf_program__attach_uprobe_opts(bpfctx.progs.bpf_prog_recv,
                                                               env.pid /* self pid */, env.bin_path,
                                                               0 /* offset for function */,
                                                               &uprobe_opts /* opts */);
  if (!bpfctx.links.bpf_prog_recv)
  {
    err = errno;
    fprintf(stderr, "attach bpf_prog_recv failed: %s\n", strerror(err));
    goto cleanup;
  }

  uprobe_opts.func_name = "ikcp_input";
  uprobe_opts.retprobe = false;
  bpfctx.links.bpf_prog_input = bpf_program__attach_uprobe_opts(bpfctx.progs.bpf_prog_input,
                                                                env.pid /* self pid */, env.bin_path,
                                                                0 /* offset for function */,
                                                                &uprobe_opts /* opts */);
  if (!bpfctx.links.bpf_prog_input)
  {
    err = errno;
    fprintf(stderr, "attach bpf_prog_input failed: %s\n", strerror(err));
    goto cleanup;
  }

  uprobe_opts.func_name = "ikcp_output";
  uprobe_opts.retprobe = false;
  bpfctx.links.bpf_prog_output = bpf_program__attach_uprobe_opts(bpfctx.progs.bpf_prog_output,
                                                                 env.pid /* self pid */, env.bin_path,
                                                                 0 /* offset for function */,
                                                                 &uprobe_opts /* opts */);
  if (!bpfctx.links.bpf_prog_output)
  {
    err = errno;
    fprintf(stderr, "attach bpf_prog_output failed: %s\n", strerror(err));
    goto cleanup;
  }


  uprobe_opts.func_name = "ikcp_update";
  uprobe_opts.retprobe = false;
  bpfctx.links.bpf_prog_update = bpf_program__attach_uprobe_opts(bpfctx.progs.bpf_prog_update,
                                                                 env.pid /* self pid */, env.bin_path,
                                                                 0 /* offset for function */,
                                                                 &uprobe_opts /* opts */);
  if (!bpfctx.links.bpf_prog_update)
  {
    err = errno;
    fprintf(stderr, "attach bpf_prog_output failed: %s\n", strerror(err));
    goto cleanup;
  }

  signal(SIGINT, sig_handler);
  printf("Tracing kcprate time... Hit Ctrl-C to end.\n");

  struct Stat prevStat = {0};
  struct Stat nowStat = {0};

  struct keyItem key1 = {0};
  key1.pid = env.pid;
  key1.type = IKCP_SEND;
  struct keyItem key2 = {0};
  key2.pid = env.pid;
  key2.type = IKCP_INPUT;
  struct keyItem key3 = {0};
  key3.pid = env.pid;
  key3.type = IKCP_RECV;
  struct keyItem key4 = {0};
  key4.pid = env.pid;
  key4.type = IKCP_OUTPUT;
  struct keyItem key5 = {0};
  key5.pid = env.pid;
  key5.type = IKCP_UPDATE;

  printf("time\tpid\tupdate_time\tsend_rate(bps)\toutput_rate(bps)\tinput_rate(bps)\trecv_rate(bps)\n");

  while (!env.exiting)
  {
    sleep(1); // 每秒读取一次速率

    bpf_map_lookup_elem(bpf_map__fd(bpfctx.maps.all_record), &key1, &(nowStat.send_bytes));
    bpf_map_lookup_elem(bpf_map__fd(bpfctx.maps.all_record), &key2, &(nowStat.input_bytes));
    bpf_map_lookup_elem(bpf_map__fd(bpfctx.maps.all_record), &key3, &(nowStat.recv_bytes));
    bpf_map_lookup_elem(bpf_map__fd(bpfctx.maps.all_record), &key4, &(nowStat.output_bytes));
    bpf_map_lookup_elem(bpf_map__fd(bpfctx.maps.all_record), &key5, &(nowStat.update_time));

    // 计算速率
    __u64 send_rate = nowStat.send_bytes - prevStat.send_bytes;
    __u64 recv_rate = nowStat.recv_bytes - prevStat.recv_bytes;
    __u64 input_rate = nowStat.input_bytes - prevStat.input_bytes;
    __u64 output_rate = nowStat.output_bytes - prevStat.output_bytes;
    __u64 update_rate = nowStat.update_time - prevStat.update_time;

    printf("%lu\t%d\t%llu\t%llu\t%llu\t%llu\t%llu\n", time(NULL), env.pid, update_rate,send_rate * 8, output_rate * 8, input_rate * 8, recv_rate * 8);

    // 更新上一轮的值
    prevStat = nowStat;
  }

cleanup:
  perf_buffer__free(pb);
  // ## 卸载bpf程序
  if (bpfctx.links.bpf_prog_send)
  {
    bpf_link__destroy(bpfctx.links.bpf_prog_send);
    bpfctx.links.bpf_prog_send = NULL;
  }
  if (bpfctx.links.bpf_prog_recv)
  {
    bpf_link__destroy(bpfctx.links.bpf_prog_recv);
    bpfctx.links.bpf_prog_recv = NULL;
  }
  if (bpfctx.links.bpf_prog_input)
  {
    bpf_link__destroy(bpfctx.links.bpf_prog_input);
    bpfctx.links.bpf_prog_input = NULL;
  }
  if (bpfctx.links.bpf_prog_output)
  {
    bpf_link__destroy(bpfctx.links.bpf_prog_output);
    bpfctx.links.bpf_prog_output = NULL;
  }
   if (bpfctx.links.bpf_prog_update)
  {
    bpf_link__destroy(bpfctx.links.bpf_prog_update);
    bpfctx.links.bpf_prog_update = NULL;
  }
  bpf_object__close(bpfctx.obj);

  return err != 0;
}
