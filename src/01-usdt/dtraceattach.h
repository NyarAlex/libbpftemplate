#ifndef __DSTRACEATTACH_H
#define __DSTRACEATTACH_H

#include <stdint.h>

struct data_t
{
    int id;
    char event[256];
    double value;
};

#endif /* __DSTRACEATTACH_H */