#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sdt.h> // 包含 DTrace USDT 定义

void process_event(int id, const char *event, double value)
{
  printf("Processing event %d: %s with value %.2f\n", id, event, value);

  // 插入静态探测点
  DTRACE_PROBE3(myprovider, event_processed, id, event, value);
}

bool exiting = false;
static void sig_handler(int sig)
{
  exiting = true;
}

int main()
{
  signal(SIGINT, sig_handler);
  while (!exiting)
  {
    sleep(1);
    process_event(42, "example_event", 3.14);
  }
  return 0;
}