//
// Created by pwn0rz on 2021/2/5.
//

#ifndef ULOADER_KRT_H
#define ULOADER_KRT_H

#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>

struct class_meta {
  const char *class_name;
  void *ctor;
};

extern uint32_t PAGE_SHIFT_CONST;
extern uint32_t kernel_task;
extern uint64_t krt_image_base;

int krt_init(uint64_t image_base);

size_t fp_strlen(const char *str);
void *fp_memcpy(void *dst, const void *src, size_t size);
void *fp_memset(void *b, int c, size_t len);

void fp_read_random(void *buffer, uint32_t size);
int fp_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp,
                    size_t newlen);
void clock_get_calendar_microtime(uint32_t *secs, uint32_t *microsecs);

void *fp_host_priv_self();
kern_return_t fp_host_get_special_port(void *host_priv, int node, int which,
                                       mach_port_t *port);
void *fp_mig_get_reply_port();
mach_msg_return_t mach_msg_rpc_from_kernel_proper(mach_msg_header_t *msg,
                                                  mach_msg_size_t send_size,
                                                  mach_msg_size_t rcv_size);
void mach_msg_destroy_from_kernel_proper(mach_msg_header_t *msg);
void ipc_port_release_send(void *port);

kern_return_t kmem_alloc(void *map, vm_offset_t *addrp, vm_size_t size,
                         uint32_t tag);
void kmem_free(void *map, vm_offset_t addr, vm_size_t size);
kern_return_t vm_map_copyin(void *src_map, vm_map_address_t src_addr,
                            vm_map_size_t len, boolean_t src_destroy,
                            uint64_t *copy_result);
kern_return_t vm_map_copyout(void *dst_map, vm_map_address_t *dst_addr,void *copy);
void vm_map_copy_discard(void *copy);
kern_return_t vm_map_wire(void* map, vm_map_offset_t start,vm_map_offset_t end,vm_prot_t access_type,boolean_t user_wire);
kern_return_t vm_map_unwire(void *map,vm_map_offset_t start, vm_map_offset_t end,boolean_t user_wire);
kern_return_t fp_vm_deallocate(mach_port_t task,vm_address_t address, vm_size_t size);

int aes_decrypt_key(const unsigned char *key, int key_len, void *ctx);
int aes_decrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
                    unsigned char *out_blk, void* ctx);
void *IOMalloc(vm_size_t size);
void *IOMallocAligned(vm_size_t size, vm_offset_t alignment);
void IOFree(void *addr, size_t size);
void IOFreeAligned(void *addr, size_t size);

void *IORWLockAlloc();
void IORWLockWrite(void *lock);
void IORWLockRead(void *lock);
void IORWLockUnlock(void *lock);
void IORWLockFree(void *lock);

void *IOLockAlloc(void);
void IOUnlock(void *lock);
void IOLockFree(void *lock);
void IOLockLock(void *lock);

void IOLog(const char *format, ...);

void *OSObject_retain(void *obj);

void *IOService_serviceMatching(const char *class_name, void *table);
void *IOService_waitForService(void *matching, mach_timespec_t *timeout);

#define IOAES_ACC_VTABLE_COUNT 512
struct IOAESAccelerator {
  uint64_t *vtable;
  uint64_t field;
};

struct IOAESAccelerator *IOAESAccelerator_new(const char *class_name);

int IOAESAccelerator_performAES(struct IOAESAccelerator *aesAcc,
                                void *memDescIn, void *memDescOut,
                                unsigned long long size, void *iv,
                                uint32_t operation, void *key_data,
                                unsigned long long unk, unsigned long long unk2,
                                void (*cb)(void *, int), void *arg);

#define IOBUFFMEM_DESC_VTABLE_COUNT 512
struct IOBufferMemoryDescriptor {
  uint64_t *vtable;
  void *buff;
  size_t capacity;
};

struct IOBufferMemoryDescriptor *IOBufferMemoryDescriptor_inTaskWithOptions(
    uint32_t task, uint32_t options, vm_size_t capacity, vm_offset_t alignment);

struct IOBufferMemoryDescriptor *IOBufferMemoryDescriptor_inTaskWithOptions(
    uint32_t task, uint32_t options, vm_size_t capacity, vm_offset_t alignment);

uint32_t IOBufferMemoryDescriptor_prepare(struct IOBufferMemoryDescriptor *desc,
                                          uint32_t direction);

void *IOBufferMemoryDescriptor_getVirtualAddress(
    struct IOBufferMemoryDescriptor *desc);

#endif // ULOADER_KRT_H
