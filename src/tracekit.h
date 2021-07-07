#ifndef ULOADER_TRACE_H
#define ULOADER_TRACE_H

#define MAX_OP_PATTERN_CB 16

#include <stdint.h>
#include <sys/types.h>
#include <signal.h>

struct trace_item{
    uint64_t addr;
    uint64_t context[1]; // result for cmp , target addr for br / blr, target for b.cond/b/bl
};

int set_trace_buff(struct trace_item* items, size_t count);

int instrument_area(void *start ,size_t size);

uint64_t get_trace_count();

#endif /*ULOADER_TRACE_H*/