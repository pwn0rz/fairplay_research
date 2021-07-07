#include "tracekit.h"
#include "krt.h"
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdbool.h>
#include <assert.h>


#define page_align(addr) (vm_address_t)((uintptr_t)(addr) & (~(vm_page_size - 1)))
#define page_align_end(addr) (vm_address_t) (((addr/vm_page_size)+1) * vm_page_size )
#define shadow_addr(addr) ((void*)(((uintptr_t)addr) + 0x200000000))

static struct trace_item    *g_trace_buff       = NULL;
static atomic_uint_fast64_t  g_trace_counter    = 0;
static size_t                g_trace_max        = 0;

bool hold_cond(uint8_t cond, uint8_t nzcv){
    uint8_t eq = (nzcv >> 2) & 0x1; // z, !ne
    uint8_t cs = (nzcv >> 1) & 0x1; // c, !cc
    uint8_t mi = (nzcv >> 3) & 0x1; // n, !pl
    uint8_t vs = nzcv & 0x1; //v, !vc

    uint8_t hi = cs && (!eq); // !ls
    uint8_t ge = (mi == vs); // !lt
    uint8_t gt = (mi == vs && eq == 0); // !le

    bool r;
    switch ( (cond >> 1) & 0x7 ) {
        case 0:
            r = !eq;
            break;
        case 1:
            r = !cs;
            break;
        case 2:
            r = !mi;
            break;
        case 3:
            r = !vs;
            break;
        case 4:
            r = !hi;
            break;
        case 5:
            r = !ge;
            break;
        case 6:
            r = !gt;
            break;
        default:
            assert(cond != 7);
    }

    if(cond & 0x1){
        r = !r;
    }
    return r;
}

static void breakpoint_handler(int signnum, siginfo_t* info, void *context){
    // get breakpoint address and context
    uint32_t *pc = (uint32_t*)info->si_addr;
    ucontext_t *ctx = (ucontext_t*)context;

    uint32_t *saddr = shadow_addr(pc);
    uint32_t opcode = *saddr;

    uint64_t rn = 0;
    uint64_t ctx_data = 0;
    uint64_t ncov = 0;

    //now let's interpret arm64 instructions lol
    if((opcode & 0xfffffc00) == 0xd73f0800){ /*blraa*/
        // lr = pc + 4
        // br rn

        rn = (opcode >> 5) & 0x1f;
        ctx_data = ctx->uc_mcontext->__ss.__x[rn]; //blr target
        
        ctx->uc_mcontext->__ss.__lr = (uintptr_t)pc + 4;
        ctx->uc_mcontext->__ss.__pc = ctx_data;

        ncov = atomic_fetch_add(&g_trace_counter, 1);
        if(ncov >= g_trace_max){
            return;
        }
        g_trace_buff[ncov].addr = (uint64_t)pc;
        g_trace_buff[ncov].context[0] = ctx_data;
        
        fprintf(stderr, "%#llx: bl %#llx\n", (mach_vm_address_t)pc - krt_image_base, ctx_data - krt_image_base);
        return;
    }else if((opcode & 0xfffffc00) == 0xd71f0800){ /*braa*/
        // br rn

        rn = (opcode >> 5) & 0x1f;
        ctx_data = ctx->uc_mcontext->__ss.__x[rn]; //br target
        
        ctx->uc_mcontext->__ss.__pc = ctx_data;

        ncov = atomic_fetch_add(&g_trace_counter, 1);
        g_trace_buff[ncov].addr = (uint64_t)pc;
        g_trace_buff[ncov].context[0] = ctx_data;

        if(ncov >= g_trace_max){
            return;
        }

        fprintf(stderr, "%#llx: b %#llx\n", (mach_vm_address_t)pc - krt_image_base, ctx_data - krt_image_base);
        return;
    }else if((opcode & 0xffff07e0) == 0x1a9f07e0){/*32bit cset*/
        // cset wd, cond
        uint32_t wd = opcode & 0x1f;
        uint8_t cond = (opcode >> 12) & 0xf;

        uint32_t cpsr = ctx->uc_mcontext->__ss.__cpsr;
        uint8_t nzcv = (cpsr >> 28) & 0xf;

        uint64_t v = ctx->uc_mcontext->__ss.__x[wd];
        if(hold_cond(cond, nzcv)){    
            v = (v & 0xffffffff00000000) | 0x1;
        }else{
            v = (v & 0xffffffff00000000) | 0x0;
        }
        ctx->uc_mcontext->__ss.__x[wd] = v;
        ctx->uc_mcontext->__ss.__pc = (uint64_t)pc + 4;

        ncov = atomic_fetch_add(&g_trace_counter, 1);
        g_trace_buff[ncov].addr = (uint64_t)pc;
        g_trace_buff[ncov].context[0] = v & 0x1; //is cset flag set?

        if(ncov >= g_trace_max){
            return;
        }

        fprintf(stderr, "%#llx: cset %s\n", (mach_vm_address_t)pc - krt_image_base, (v & 0x1) ? "true" : "false");
        return;
    }else{
        fprintf(stderr, "Unhandled sigtrap at %p\n", info->si_addr);
        abort();
    }
}

int set_trace_buff(struct trace_item* items, size_t count){
    g_trace_buff = items;
    g_trace_max = count;
    atomic_store(&g_trace_counter, 0);
    return 0;
}


int set_buff_rw(mach_vm_address_t addr, size_t size){
    int kr = mach_vm_protect(mach_task_self(), addr, size, false , VM_PROT_READ | VM_PROT_WRITE);
    if(kr != 0){
        fprintf(stderr, "set_buff_rw: %s\n", mach_error_string(kr));
        return -1;
    }
    return 0;
}

int set_buff_rx(mach_vm_address_t addr, size_t size){
    int kr = mach_vm_protect(mach_task_self(), addr, size, false , VM_PROT_READ | VM_PROT_EXECUTE);
    if(kr != 0){
        fprintf(stderr, "set_buff_rx: %s\n", mach_error_string(kr));
        return -1;
    }
    return 0;
}


int instrument_area(void *start ,size_t size){
    //allocate memory into shaow addr

    uintptr_t start_aligned = page_align(start);
    size_t size_aligned = page_align_end(size);

    mach_vm_address_t saddr = (mach_vm_address_t)shadow_addr(start_aligned);
    int kr = mach_vm_allocate(mach_task_self(), &saddr, size_aligned, VM_FLAGS_FIXED);
    if(kr != KERN_SUCCESS){
        fprintf(stderr, "allocate shadow buffer failed\n");
        return -1;
    }

    if(saddr != (mach_vm_address_t)shadow_addr(start_aligned)){
        fprintf(stderr, "allocate shdow buffer at %#llx failed, got %#llx\n", (mach_vm_address_t)(shadow_addr(start_aligned)), saddr);
        return -1;
    }
    fprintf(stdout, "allocate shdow buffer at %#llx, size %#lx\n", saddr, size_aligned);

    assert( 0 == set_buff_rw(saddr, size_aligned) );
    assert( 0 == set_buff_rw((mach_vm_address_t)start_aligned , size_aligned) );

    uint32_t *pos = start;
    for(pos = start; (uintptr_t)pos < ((uintptr_t)start + size); pos++ ){
        uint32_t opcode = *pos;
        if( 
            (opcode & 0xfffffc00) == 0xd73f0800 /*blraa*/ || 
            (opcode & 0xfffffc00) == 0xd71f0800 /*braa*/  || 
            (opcode & 0xffff07e0) == 0x1a9f07e0 /*32bit cset*/
        ){
            uint32_t *opcode_shadow = shadow_addr(pos);
            *opcode_shadow = opcode;
            *pos = 0xd4200000; //brk
        }
    }
    assert( 0 == set_buff_rx((mach_vm_address_t)start_aligned , size_aligned) );

    signal(SIGTRAP , (void(*)(int))breakpoint_handler);
    return 0;
}

uint64_t get_trace_count(){
    return atomic_load(&g_trace_counter);
}