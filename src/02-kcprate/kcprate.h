#ifndef __KCPRATE_H
#define __KCPRATE_H

struct keyItem
{
  int pid;
  int type;
};

enum FUNCTYPE{
  IKCP_SEND,
  IKCP_INPUT,
  IKCP_RECV,
  IKCP_OUTPUT,
  IKCP_UPDATE
};

#endif /* __KCPRATE_H */