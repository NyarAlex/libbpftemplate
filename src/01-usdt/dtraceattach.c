#include <stdio.h>
#include <ctype.h>
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include "dtraceattach.skel.h"
#include "dtraceattach.h"
#include <arpa/inet.h>


#define BINARY_PATH_SIZE (256)
#define PERF_BUFFER_PAGES (32)
#define PERF_POLL_TIMEOUT_MS (200)

static struct env {
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

const char *argp_program_version = "dtraceattach 0.1";
const char *argp_program_bug_address =
		"";

const char argp_program_doc[] =
		"加载bpf文件到指定用户程序的USDT上，无需BTF支持\n"
		"\n"
		"USAGE: dtraceattach [--help] [-p PID] [-P bpf_path] [-B bin_path]\n"
		"\n"
		"EXAMPLES:\n"
		"dtraceattach -p 185 -P /test/a.bpf -B /test/run\n";

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

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'P':
		strcpy(env.bpf_path,arg);
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			err = errno;
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'B':
		strcpy(env.bin_path,arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return err;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && ! env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct data_t *evt = (struct data_t *)data;
	struct timespec ts;
  // 获取当前时间，存储在 ts 中
  clock_gettime(CLOCK_REALTIME, &ts);
	//当前纳秒时间
	long long ntime=ts.tv_sec * 1000000000 + ts.tv_nsec;

  printf("time:[%lld],Processing event %d: %s with value %.2f\n",ntime, evt->id, evt->event, evt->value);
}

static void handle_lost_events(void *ctx, int cpu, __u64 data_sz)
{
	printf("lost data\n");
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
	if (len < 0) {
		fprintf(stderr, "ERR: constructing full mapname path\n");
		return -1;
	}

	fd = bpf_obj_get(filename);
	if (fd < 0) {
		fprintf(stderr, "WARN: Failed to open bpf map file:%s err(%d):%s\n", filename,
			errno, strerror(errno));
	}

	return fd;
}
/// @brief 加载bpf-elf格式的文件，填充bpfctx
/// @param filename bpf文件路径
int load_bpf_object_file_with_filename(const char *filename,struct dtraceattach_bpf* bpfctx)
{
	int err;
	struct bpf_object *obj;
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		printf("open object file failed: %s\n", strerror(errno));
		return -1;
	}
	bpfctx->obj=obj;
	struct bpf_program *prog =bpf_object__find_program_by_name(obj, "handle_dtrace6");
	if (prog == NULL) {
		printf("find program in object failed: %s\n", strerror(errno));
		return -1;
	}
	bpfctx->progs.handle_dtrace6=prog;
	err = bpf_object__load(obj);
	if (err) {
		printf("load bpf object failed: %s\n", strerror(errno));
		return -1;
	}

	//## 获取bpf map的指针
	bpfctx->maps.perf_map= bpf_object__find_map_by_name(bpfctx->obj,"perf_map");

	return 0;
}


static void sig_handler(int sig)
{
	env.exiting = true;
}

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
	
	printf("当前bpf路径:%s\n",env.bpf_path);
	printf("当前bin路径:%s\n",env.bin_path);

	libbpf_set_print(libbpf_print_fn);
	struct dtraceattach_bpf bpfctx={0};

	load_bpf_object_file_with_filename(env.bpf_path,&bpfctx);

	bpfctx.links.handle_dtrace6=bpf_program__attach_usdt(bpfctx.progs.handle_dtrace6, env.pid,
									env.bin_path, "myprovider", "event_processed", NULL);
	if (!bpfctx.links.handle_dtrace6) {
		err = errno;
		fprintf(stderr, "attach usdt myprovider::event_processed failed: %s\n", strerror(err));
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	printf("Tracing dtraceattach time... Hit Ctrl-C to end.\n");

	pb = perf_buffer__new(bpf_map__fd(bpfctx.maps.perf_map), PERF_BUFFER_PAGES,
												handle_event, handle_lost_events, NULL, NULL);
	while (!env.exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	//## 卸载bpf程序
	if (bpfctx.links.handle_dtrace6) {
    bpf_link__destroy(bpfctx.links.handle_dtrace6);
    bpfctx.links.handle_dtrace6 = NULL; 
	}
	bpf_object__close(bpfctx.obj);

	return err != 0;
}
