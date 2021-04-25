//
// Created by pwn0rz on 2021/2/5.
//
#include "krt.h"
#include <assert.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdarg.h>
#include <stddef.h>
#include <ctype.h>
#include <sys/random.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>

#define MAX_CLASS_META_COUNT 4096

uint32_t PAGE_SHIFT_CONST = 14;
uint32_t kernel_task = 0xdeadbeef;
uint64_t krt_image_base = 0;

void hexdump(const void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++)
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++)
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}

void bytes_dump(const void* buff,int len){
  uint8_t *ptr = (uint8_t*)buff;
  for(int i=0;i<len;i++){
    printf("%02x",ptr[i]);
  }
  fflush(stdout);
}

int krt_init(uint64_t image_base) {
  kernel_task = mach_task_self();
  krt_image_base = image_base;
  return 0;
}

void backtrace() {
  uint64_t pc = __builtin_return_address(1);
  printf("%#llx ==> ", pc - 4 - krt_image_base);
}

struct class_meta g_class_metas[MAX_CLASS_META_COUNT] = {
    {"IOAESAccelerator", (void *)IOAESAccelerator_new},
    {NULL, NULL},
};

size_t fp_strlen(const char *str) {
  backtrace();
  size_t len = strlen(str);
  printf("strlen(\"%s\") => %#lx\n", str, len);
  return len;
}

void *fp_memcpy(void *dst, const void *src, size_t size) {
  backtrace();
  printf("memcpy(dst=%p,src=%p,size=%#lx)\n", dst, src, size);
  return memcpy(dst, src, size);
}

void *fp_memset(void *b, int c, size_t len) {
  backtrace();

  printf("memset(dst=%p,c=%x,size=%#lx)\n", b, (uint8_t)c, len);
  return memset(b, c, len);
}

void fp_read_random(void *buffer, uint32_t size) {
  backtrace();
  printf("read_random(buff=%p,size=%#x)\n", buffer, size);
  memset(buffer, 0x12, size); // lol, de-randomization
}

int fp_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp,
                    size_t newlen) {
  backtrace();
  printf("sysctlbyname(\"%s\",oldp=%p,oldenp=%p,newp=%p,newlen=%lx)\n", name,
         oldp, oldlenp, newp, newlen);
  return sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

void clock_get_calendar_microtime(uint32_t *secs, uint32_t *microsecs) {
  backtrace();
  struct timeval time;
  gettimeofday(&time, NULL);
  *secs = time.tv_sec;
  *microsecs = time.tv_usec;
  printf("clock_get_calendar_microtime(secs=%p,microsecs=%p) => (%d,%d)\n",
         secs, microsecs, *secs, *microsecs);
}

void *fp_host_priv_self() {
  backtrace();
  void *ret = (void *)(mach_host_self());
  printf("host_priv_self() => %p\n", ret);
  return ret;
}

kern_return_t fp_host_get_special_port(void *host_priv, int node, int which,
                                       mach_port_t *port) {
  backtrace();
  kern_return_t kr =
      host_get_special_port((host_priv_t)host_priv, node, which, port);
  printf(
      "host_get_special_port(priv=%p,node=%d,which=%d,port=%p[%#x]) => %#x\n",
      host_priv, node, which, port, *port, kr);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "failed to get special port : %s\n", mach_error_string(kr));
    abort();
  }
  return kr;
}

void *fp_mig_get_reply_port() {
  backtrace();
  mach_port_t port = mig_get_reply_port();
  printf("mig_get_reply_port() => %p\n", port);
  return (void *)port;
}

typedef struct {
  mach_msg_bits_t msgh_bits;
  mach_msg_size_t msgh_size;
  void *msgh_remote_port;
  void *msgh_local_port;
  mach_port_name_t msgh_voucher_port;
  mach_msg_id_t msgh_id;
} mach_kmsg_header_t;



#pragma pack(push, 4)
struct meta_info{
  uint32_t magic;
  uint32_t unk1;
  uint32_t cpu_type;
  uint32_t cpu_subtype;

  uint8_t unk2[0x30];

  uint32_t size;
  uint32_t unk3[0x44]; //unused
};

struct KFPRequest {
  mach_kmsg_header_t header;
  mach_msg_body_t body;
  mach_msg_ool_descriptor_t ool;
  NDR_record_t ndr;
  uint32_t size;
  uint64_t cpu_type;
  uint64_t cpu_subtype;
};

struct UFPRequest {
  mach_msg_header_t header;
  mach_msg_body_t body;
  mach_msg_ool_descriptor_t ool;
  NDR_record_t ndr;
  uint32_t size;
  uint64_t cpu_type;
  uint64_t cpu_subtype;
};

struct KFPResponse {
  mach_kmsg_header_t header;
  mach_msg_body_t body;
  mach_msg_ool_descriptor_t ool1;
  mach_msg_ool_descriptor_t ool2;
  uint64_t unk1;
  uint8_t unk2[136];
  uint8_t unk3[84];
  uint32_t size1;
  uint32_t size2;
  uint64_t unk5;
};

struct UFPResponse {
  mach_msg_header_t header;
  mach_msg_body_t body;
  mach_msg_ool_descriptor_t ool1;
  mach_msg_ool_descriptor_t ool2;
  uint64_t unk1;
  uint8_t unk2[136];
  uint8_t unk3[84];
  uint32_t size1;
  uint32_t size2;
  uint64_t unk5;
};

union UFPRPC {
  struct UFPRequest req;
  struct UFPResponse res;
};

union KFPRPC {
  struct KFPRequest req;
  struct KFPResponse res;
};
#pragma pack(pop)

mach_msg_return_t mach_msg_rpc_from_kernel_proper(mach_msg_header_t *msg,
                                                  mach_msg_size_t send_size,
                                                  mach_msg_size_t rcv_size) {
  backtrace();

  printf(
      "mach_msg_rpc_from_kernel_proper(msg=%p,send_size=%#x,recv_size=%#x)\n",
      msg, send_size, rcv_size);

  union KFPRPC *krpc = (union KFPRPC *)msg;
  union UFPRPC urpc;
  bzero(&urpc, sizeof(union UFPRPC));

  assert(sizeof(struct KFPRequest) == send_size);
  assert(sizeof(struct KFPResponse) == rcv_size);
  assert(sizeof(struct UFPRequest) == 0x48);
  assert(sizeof(struct UFPResponse) == 0x130);

  printf("[*] transforming kernel-space RPC request into user-space style\n");

  // urpc.req.header.msgh_bits = krpc->req.header.msgh_bits;
  urpc.req.header.msgh_bits =
      MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND);
  urpc.req.header.msgh_size = sizeof(struct UFPRequest);
  urpc.req.header.msgh_id = 502;
  urpc.req.header.msgh_local_port = krpc->req.header.msgh_local_port;
  urpc.req.header.msgh_remote_port = krpc->req.header.msgh_remote_port;
  urpc.req.header.msgh_voucher_port = MACH_PORT_NULL;

  memcpy(&urpc.req.body, &krpc->req.body,
         sizeof(struct UFPRequest) - offsetof(struct UFPRequest, body));

  printf("\tsend ool vm address %p, size %#x from %#x to port %#x\n",
         urpc.req.ool.address, urpc.req.ool.size,
         urpc.req.header.msgh_local_port, urpc.req.header.msgh_remote_port);
  printf("\tpath: %s\n", (char *)urpc.res.ool1.address);
  printf("\tcpu type: %#010llx\n",urpc.req.cpu_type);
  printf("\tcpu sub_type: %#010llx\n",urpc.req.cpu_subtype);

  kern_return_t kr = mach_msg(
      (mach_msg_header_t *)&urpc.req.header,
      MACH_SEND_MSG | MACH_RCV_MSG | MACH_MSG_OPTION_NONE,
      urpc.req.header.msgh_size, sizeof(struct UFPResponse),
      urpc.req.header.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "failed to send mach message : %s\n",
            mach_error_string(kr));
    abort();
  }

  printf("\trecv msg size = %#x\n", urpc.res.header.msgh_size);
  if (urpc.res.header.msgh_size <= 0x24) { // FIXME: this is magic
    fprintf(stderr, "fairplay RPC failed\n");
    abort();
  }
  printf("\tgot ool vm1: %p, size: %#x\n", urpc.res.ool1.address,
         urpc.res.ool1.size);
  printf("\tgot ool vm2: %p, size: %#x\n", urpc.res.ool2.address,
         urpc.res.ool2.size);

  printf("[*] transforming user-space RPC response into kernel-space style\n");

  krpc->res.header.msgh_bits = urpc.res.header.msgh_bits;
  krpc->res.header.msgh_size = urpc.res.header.msgh_size + 8;
  krpc->res.header.msgh_id = urpc.res.header.msgh_id;
  krpc->res.header.msgh_local_port = urpc.res.header.msgh_local_port;
  krpc->res.header.msgh_remote_port = urpc.res.header.msgh_remote_port;
  krpc->res.header.msgh_voucher_port = urpc.res.header.msgh_voucher_port;
  memcpy(&krpc->res.body, &urpc.res.body,
         sizeof(struct KFPResponse) - offsetof(struct KFPResponse, body));

  return MACH_MSG_SUCCESS;
}

void mach_msg_destroy_from_kernel_proper(mach_msg_header_t *msg) {
  backtrace();
  printf("mach_msg_destroy_from_kernel_proper(%p)\n", msg);
}

void ipc_port_release_send(void *port) {
  backtrace();
  printf("ipc_port_release_send(%p)\n", port);
}

kern_return_t kmem_alloc(void *map, vm_offset_t *addrp, vm_size_t size,
                         uint32_t tag) {
  backtrace();
  void *p = malloc(size);
  printf("kmem_alloc(map=%p,addrp=%p,size=%lx,tag=%#x) => %p\n", map, addrp,
         size, tag, p);
  *addrp = (vm_offset_t)p;
  return KERN_SUCCESS;
}

void kmem_free(void *map, vm_offset_t addr, vm_size_t size) {
  backtrace();
  printf("kmem_free(map=%p,addr=%#llx,size=%#lx)\n", map, addr, size);
  free((void *)addr);
}

kern_return_t vm_map_copyin(void *src_map, vm_map_address_t src_addr,
                            vm_map_size_t len, boolean_t src_destroy,
                            uint64_t *copy_result) {
  backtrace();
  void *buff = malloc(len);
  memcpy(buff, (void *)src_addr, len);
  *copy_result = (uint64_t)buff;
  printf("vm_map_copyin(src_map=%#llx,src=%#llx,len=%llx,src_destroy=%d,copy_"
         "result=%p)\n",
         src_map, src_addr, len, src_destroy, copy_result);
  return KERN_SUCCESS;
}

kern_return_t vm_map_copyout(void *dst_map, vm_map_address_t *dst_addr,void *copy){
  backtrace();
  *dst_addr = (uint64_t)copy;
  printf("vm_map_copyout(dst_map=%p,dst_addr=%p[%#llx],copy=%p)\n",dst_map,dst_addr,*dst_addr,copy);
  return KERN_SUCCESS;
}

void vm_map_copy_discard(void *copy){
  backtrace();
  printf("vm_map_copy_discard(copy=%p)\n",copy);
}

kern_return_t vm_map_wire(void* map, vm_map_offset_t start,vm_map_offset_t end,vm_prot_t access_type,boolean_t user_wire){
  backtrace();
  printf("vm_map_wire(map=%p,start=%#llx,end=%#llx,access_type=%d,user_wire=%d)\n",map,start,end,access_type,user_wire);
  return KERN_SUCCESS;
}

kern_return_t vm_map_unwire(void *map,vm_map_offset_t start, vm_map_offset_t end,boolean_t user_wire){
  backtrace();
  printf("vm_map_unwire(map=%p,start=%#llx,end=%#llx,user_wire=%d)\n",map,start,end,user_wire);
  return KERN_SUCCESS;
}

kern_return_t fp_vm_deallocate(mach_port_t task,vm_address_t address, vm_size_t size){
  backtrace();
  printf("vm_deallocate(task=%#x,addr=%#lx,size=%#lx)\n",task,address,size);
  //FIXME: should we proxy it to native syscall or it might leak?
  return KERN_SUCCESS;/*mach_vm_deallocate(mach_task_self(),address,size);*/
}

struct aes_decrypt_ctx{
  int key_len;
  uint8_t key[32];
};

#include <CommonCrypto/CommonCrypto.h>

int aes_decrypt_key(const unsigned char *key, int key_len, void *ctx){
  backtrace();
  printf("aes_decrypt_key(key=%p,len=%#x,ctx=%p)\n",key,key_len,ctx);

  struct aes_decrypt_ctx *dec_ctx = (struct aes_decrypt_ctx*)ctx;
  assert(key_len == 16 || key_len == 24  || key_len == 32);
  memcpy(dec_ctx->key,key,key_len);
  dec_ctx->key_len = key_len;
  return 0;
}

int aes_decrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
                         unsigned char *out_blk, void* ctx)
{
  backtrace();
  struct aes_decrypt_ctx *dec_ctx = (struct aes_decrypt_ctx*)ctx;
  printf("aes_decrypt_cbc(in=%p,iv=%p,n_blk=%#x,out=%p,ctx=%p)\n",in_blk,in_iv,num_blk,out_blk,ctx);
  printf("\taes-%d-cbc key: ",dec_ctx->key_len * 8,dec_ctx->key_len * 8);
  bytes_dump(dec_ctx->key,dec_ctx->key_len);
  printf(", iv: ");
  bytes_dump(in_iv,16);
  printf("\n");

  size_t decrypted_count;
  CCCryptorStatus status = CCCrypt(
      kCCDecrypt,
      kCCAlgorithmAES128,
      kCCOptionPKCS7Padding,
      dec_ctx->key,
      kCCKeySizeAES128,
      in_iv,
      in_blk,
      num_blk * 16,
      out_blk,
      num_blk * 16,
      &decrypted_count
      );
  assert(status == kCCSuccess);
  return 0;
}

void *IOMalloc(vm_size_t size) {
  backtrace();
  void *p = malloc(size);
  printf("IOMalloc(%#llx) => %p\n", size, p);
  return p;
}

void *IOMallocAligned(vm_size_t size, vm_offset_t alignment) {
  backtrace();
  void *p = malloc(size);
  printf("IOMallocAligned(%#lx,%#lx) => %p\n", size, alignment, p);
  return p;
}

void IOFree(void *addr, size_t size) {
  backtrace();
  printf("IOFree(%p,%#lx)\n", addr, size);
  free(addr);
}

void IOFreeAligned(void *addr, size_t size) {
  backtrace();
  printf("IOFreeAligned(%p,%#lx)\n", addr, size);
  free(addr);
}

void *IORWLockAlloc() {
  backtrace();
  void *buff = malloc(8);
  printf("IORWLockAlloc() => %p\n", buff);
  return buff;
}

void IORWLockWrite(void *lock) {
  backtrace();
  printf("IORWLockWrite(%p)\n", lock);
}

void IORWLockRead(void *lock) {
  backtrace();
  printf("IORWLockRead(%p)\n", lock);
}

void IORWLockUnlock(void *lock) {
  backtrace();
  printf("IORWLockUnlock(%p)\n", lock);
}

void IORWLockFree(void *lock) {
  backtrace();
  printf("IORWLockFree(%p)\n", lock);
  free(lock);
}

void *IOLockAlloc(void) {
  backtrace();
  void *buff = malloc(8);
  printf("IORWLockAlloc() => %p\n", buff);
  return buff;
}

void IOLockFree(void *lock) {
  backtrace();
  printf("IOLockFree(%p)\n", lock);
}

void IOUnlock(void *lock) {
  backtrace();
  printf("IOUnlock(%p)\n", lock);
}

void IOLockLock(void *lock) {
  backtrace();
  printf("IOLockLock(%p)\n", lock);
}

void IOLog(const char *format, ...) {
  backtrace();
  va_list ap;
  printf("IOLog: ");
  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
}

void *OSObject_retain(void *obj) {
  backtrace();
  printf("OSObject::retain(%p)\n", obj);
}

void *IOService_serviceMatching(const char *class_name, void *table) {
  backtrace();
  void *result = class_name;
  printf("IOService::serviceMatching(\"%s\",%p) => %p\n", class_name, table);
  return class_name;
}

void *IOService_waitForService(void *matching, mach_timespec_t *timeout) {
  backtrace();
  const char *service_name = matching;
  void *service = NULL;
  for (uint32_t i = 0; i < MAX_CLASS_META_COUNT; i++) {
    if (g_class_metas[i].class_name == NULL) {
      break;
    }
    if (strcmp(g_class_metas[i].class_name, service_name) == 0) {
      void *(*ctor)(char *) = g_class_metas[i].ctor;
      if (ctor == NULL) {
        break;
      } else {
        service = ctor(service_name);
        break;
      }
    }
  }
  printf("IOService::waitForService(%p,%p) => %p\n", matching, timeout,
         service);
  return service;
}

void unhandled_vtable() {
  fprintf(stderr, "unhandled vtable\n");
  __asm__("BRK #0");
}

struct IOAESAccelerator *IOAESAccelerator_new(const char *class_name) {
  struct IOAESAccelerator *service = malloc(sizeof(struct IOAESAccelerator));
  service->vtable = malloc(IOAES_ACC_VTABLE_COUNT * 8);
  service->vtable[4] = (uint64_t)OSObject_retain;
  service->vtable[0x890 / 8] = (uint64_t)IOAESAccelerator_performAES;
  return service;
}

int IOAESAccelerator_performAES(struct IOAESAccelerator *aesAcc,
                                void *memDescIn, void *memDescOut,
                                unsigned long long size, void *iv,
                                uint32_t operation, void *key_data,
                                unsigned long long unk, unsigned long long unk2,
                                void (*cb)(void *, int), void *arg) {
  backtrace();
  printf("IOAESAccelerator::performAES(this=%p,inDesc=%p,outDesc=%p,size=%#llx,"
         "iv=%p,op=%x,key_data=%p,unk=%#llx,unk2=%#llx,cb=%p)\n",
         aesAcc, memDescIn, memDescOut, size, iv, operation, key_data, unk,
         unk2, cb);
  return 0;
}

struct IOBufferMemoryDescriptor *
IOBufferMemoryDescriptor_inTaskWithOptions(uint32_t task, uint32_t options,
                                           vm_size_t capacity,
                                           vm_offset_t alignment) {
  struct IOBufferMemoryDescriptor *descriptor;
  backtrace();

  descriptor = malloc(sizeof(struct IOBufferMemoryDescriptor));
  descriptor->vtable = malloc(IOBUFFMEM_DESC_VTABLE_COUNT * 8);
  for (uint32_t i = 0; i < IOBUFFMEM_DESC_VTABLE_COUNT; i++) {
    descriptor->vtable[i] = (uint64_t)unhandled_vtable;
  }
  descriptor->vtable[0x218 / 8] = IOBufferMemoryDescriptor_prepare;
  descriptor->vtable[0x308 / 8] = IOBufferMemoryDescriptor_getVirtualAddress;

  descriptor->capacity = capacity;
  descriptor->buff = malloc(capacity);

  printf("IOBufferMemoryDescriptor::inTaskWithOptions(%x,%x,capacity=%#lx,"
         "alignment=%#lx) => %p\n",
         task, options, capacity, alignment, descriptor);
  return descriptor;
}

uint32_t IOBufferMemoryDescriptor_prepare(struct IOBufferMemoryDescriptor *desc,
                                          uint32_t direction) {
  backtrace();
  bzero(desc->buff, desc->capacity);
  printf("IOBufferMemoryDescriptor::prepare(desc=%p,direction=%#x)\n", desc,
         direction);
  return 0;
}

void *IOBufferMemoryDescriptor_getVirtualAddress(
    struct IOBufferMemoryDescriptor *desc) {
  backtrace();
  printf("IOBufferMemoryDescriptor::getVirtualAddress(%p) => %p\n", desc,
         desc->buff);
  return desc->buff;
}
