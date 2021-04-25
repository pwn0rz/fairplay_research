#include "krt.h"
#include "ulinker.h"
#include <assert.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <machine/endian.h>
#include <stdbool.h>

struct symbol_register {
  const char *symbol;
  const void *func;
};

#define SYM_REG_COUNT_MAX 4096
uint64_t g_image_slide;

void no_op() {
  void *pc = __builtin_return_address(0);

  fprintf(stderr, "hit no-op function, pc = %p\n",
          (uint8_t *)pc - g_image_slide - 4);
}

struct symbol_register sym_regs[SYM_REG_COUNT_MAX] = {

    {"_memcpy", (void *)fp_memcpy},
    {"_memset", (void *)fp_memset},
    {"_read_random", (void *)fp_read_random},
    {"_strlen", (void *)fp_strlen},

    {"_sysctlbyname", (void *)fp_sysctlbyname},
    {"_clock_get_calendar_microtime", (void *)clock_get_calendar_microtime},

    {"_host_priv_self", (void *)fp_host_priv_self},
    {"_host_get_special_port", (void *)fp_host_get_special_port},
    {"_mig_get_reply_port", (void *)fp_mig_get_reply_port},
    {"_mach_msg_rpc_from_kernel_proper",
     (void *)mach_msg_rpc_from_kernel_proper},
    {"_mach_msg_destroy_from_kernel_proper",
     (void *)mach_msg_destroy_from_kernel_proper},
    {"_ipc_port_release_send", (void *)ipc_port_release_send},
    {"_kmem_alloc", (void *)kmem_alloc},
    {"_kmem_free", (void *)kmem_free},
    {"_vm_map_copyin", (void *)vm_map_copyin},
    {"_vm_map_copyout",(void*)vm_map_copyout},
    {"_vm_map_copy_discard",(void*)vm_map_copy_discard},
    {"_vm_map_wire",(void *)vm_map_wire},
    {"_vm_map_unwire",(void*)vm_map_unwire},
    {"_vm_deallocate",(void*)fp_vm_deallocate},

    {"_aes_decrypt_key",(void*)aes_decrypt_key},
    {"_aes_decrypt_cbc",(void*)aes_decrypt_cbc},

    {"_IOMalloc", (void *)IOMalloc},
    {"_IOMallocAligned", (void *)IOMallocAligned},
    {"_IOFree", (void *)IOFree},
    {"_IOFreeAligned", (void *)IOFreeAligned},
    {"_IOLog", (void *)IOLog},

    {"_IORWLockAlloc", (void *)IORWLockAlloc},
    {"_IORWLockWrite", (void *)IORWLockWrite},
    {"_IORWLockRead", (void *)IORWLockRead},
    {"_IORWLockUnlock", (void *)IORWLockUnlock},
    {"_IORWLockFree", (void *)IORWLockFree},

    {"_IOLockAlloc", (void *)IOLockAlloc},
    {"_IOLockLock", (void *)IOLockLock},
    {"_IOLockUnlock", (void *)IOUnlock},
    {"_IOLockFree", (void *)IOLockFree},

    {"__ZN9IOService15serviceMatchingEPKcP12OSDictionary",
     (void *)IOService_serviceMatching},
    {"__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec",
     (void *)IOService_waitForService},
    {"_kernel_task", (void *)&kernel_task},
    {"_PAGE_SHIFT_CONST", (void *)&PAGE_SHIFT_CONST},
    {"__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm",
     (void *)IOBufferMemoryDescriptor_inTaskWithOptions},
    {NULL, NULL},
};

void unhandled_imports(uint64_t tagged_id) {
  void *pc = __builtin_return_address(0);

  assert(tagged_id & 0xdeadbeef00000000);

  uint32_t id = tagged_id & UINT32_MAX;
  fprintf(stderr, "unhandled import function %s, pc = %p\n",
          sym_regs[id].symbol, (uint8_t *)pc - g_image_slide);
  uint32_t *branch = (uint32_t *)pc - 1;
  // getchar();
  __asm__("BRK #0");
}

const char *kext_path = "/System/Library/Extensions/FairPlayIOKit.kext/Contents/MacOS/FairPlayIOKit";

int fairplay_init(struct mach_header_64 *kext){
  // service start stuff
  void (*LSKDKext_start)() =
  macho_loaded_resolve_sym(kext, "__Z14LSKDKext_startv");
  int (*cmam7f)() = macho_loaded_resolve_sym(kext, "_cmam7f");

  // runversiond
  int (*UeFdbi)(uint32_t task, uint32_t unk1, uint32_t unk2, uint32_t unk3,
                uint8_t * in_sec1, uint8_t * in_sec2, size_t in_size,
                uint8_t * out_sec1, uint8_t * out_se2) =
  macho_loaded_resolve_sym(kext, "_UeFdbi");

  printf(">>> calling LSKDKext_start() @%p...\n",LSKDKext_start);
  LSKDKext_start();

  printf(">>> calling cmam7f()...\n");
  int ret = cmam7f();
  if (ret) {
    fprintf(stderr, "*** cmam7f failed : %d\n", ret);
    return -1;
  }

  return 0;
}

uint32_t fairplay_open(struct mach_header_64 *kext,const char *exec_file){
  uint32_t fp_handle;
  // fairplay open
  int (*fcHfFIGhsx)(const char *path, uint32_t cputype, uint32_t cpusubtype,
                    void *handle) =
  macho_loaded_resolve_sym(kext, "_fcHfFIGhsx");

  printf(">>> calling fairplay open : %p\n", fcHfFIGhsx);
  int ret =
      fcHfFIGhsx(exec_file,
                 CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, &fp_handle);

  if (ret) {
    printf("*** fairplay open failed, status %d\n", ret);
    return -1;
  }
  printf(">>> fairplay open success, handle = %#x\n",fp_handle);

  return fp_handle;
}

int fairplay_decrypt_macho64(struct mach_header_64 *kext, uint32_t fp_handle, const struct mach_header_64 *mh_in, struct mach_header_64 *mh_out){
  // decrypt page
  int (*EQlZPp)(uint32_t handle, uint64_t offset, const char *src, char *dst) =
  macho_loaded_resolve_sym(kext, "_EQlZPp");


  struct encryption_info_command_64 *lc_enc_in =
      (struct encryption_info_command_64 *)macho64_get_lc(
          mh_in, LC_ENCRYPTION_INFO_64);

  uint32_t cryptoff = macho_swap_endian_32(mh_in,lc_enc_in->cryptoff);
  uint32_t cryptsize = macho_swap_endian_32(mh_in,lc_enc_in->cryptsize);
  uint32_t cryptid = macho_swap_endian_32(mh_in,lc_enc_in->cryptid);
  if(cryptid != 1) {
    printf("not fairplay encrypted executable\n");
    return 0;
  }

  char *encrypted = NULL;
  char *decrypted = malloc(4096);

  for(uint32_t pos =0; pos < cryptsize; pos +=4096){
    encrypted = (char *)mh_in + cryptoff + pos;
    printf(">>> calling fairplay decrypt page : EQlZPp(handle=%#x,off=%#x,src=%p,dst=%p)\n", fp_handle,cryptoff + pos,encrypted,decrypted);
    int ret = EQlZPp(fp_handle, cryptoff + pos, encrypted,decrypted);
    if (ret) {
      printf("*** fairplay decrypt failed, status %d\n", ret);
      return -1;
    }
    memcpy((char *)mh_out + cryptoff + pos, decrypted, 4096);
  }

  struct encryption_info_command_64 *lc_enc_out =
      (struct encryption_info_command_64 *)
          macho64_get_lc(mh_out, LC_ENCRYPTION_INFO_64);
  lc_enc_out->cryptid = macho_swap_endian_32(mh_out,0);
  return 0;
}

int fairplay_decrypt_macho32(struct mach_header_64 *kext, uint32_t fp_handle, const struct mach_header *mh_in, struct mach_header *mh_out){
  // decrypt page
  int (*EQlZPp)(uint32_t handle, uint64_t offset, const char *src, char *dst) =
  macho_loaded_resolve_sym(kext, "_EQlZPp");

  struct encryption_info_command *lc_enc_in =
      (struct encryption_info_command *)macho32_get_lc(
          mh_in, LC_ENCRYPTION_INFO);

  uint32_t cryptoff = macho_swap_endian_32(mh_in,lc_enc_in->cryptoff);
  uint32_t cryptsize = macho_swap_endian_32(mh_in,lc_enc_in->cryptsize);
  uint32_t cryptid = macho_swap_endian_32(mh_in,lc_enc_in->cryptid);
  if(cryptid != 1) {
    printf("not fairplay encrypted executable\n");
    return 0;
  }

  char *encrypted = NULL;
  char *decrypted = malloc(4096);

  for(uint32_t pos =0; pos < cryptsize; pos +=4096){
    encrypted = (char *)mh_in + cryptoff + pos;
    printf(">>> calling fairplay decrypt page : %p\n", EQlZPp);
    int ret = EQlZPp(fp_handle, cryptoff,encrypted,decrypted);
    if (ret) {
      printf("*** fairplay decrypt failed, status %d\n", ret);
      return -1;
    }
    memcpy((char *)mh_out + cryptoff + pos, decrypted, 4096);
  }

  struct encryption_info_command *lc_enc_out =
      (struct encryption_info_command *)
          macho64_get_lc(mh_out, LC_ENCRYPTION_INFO_64);
  lc_enc_out->cryptid = macho_swap_endian_32(mh_out,0);
  return 0;
}

int fairplay_decrypt(struct mach_header_64 *kext, const char *filename_in,const char  *filename_out){

  uint32_t handle = fairplay_open(kext,filename_in);
  if(handle == -1){
    return -1;
  }

  // mmaping macho into memory
  int fd_in = open(filename_in, O_RDONLY);
  if (fd_in < 0) {
    perror("open macho");
    return -1;
  }

  struct stat st = {0};
  int ret = fstat(fd_in, &st);
  if (ret) {
    perror("fstat macho");
    return -1;
  }

  struct mach_header_64 *mh_in = (struct mach_header_64 *)mmap(
      NULL, st.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd_in, 0);

  if (mh_in == MAP_FAILED) {
    perror("mmap macho");
    return -1;
  }

  //create output file
  int fd_out = open(filename_out,O_RDWR | O_CREAT | O_TRUNC, (mode_t)0777);
  if(fd_out < 0){
    perror("create decrypted file");
    return -1;
  }

  assert(ftruncate(fd_out,st.st_size) == 0);
  struct mach_header_64 *mh_out = (struct mach_header_64 *)mmap(
      NULL,st.st_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd_out, 0);
  if (mh_out == MAP_FAILED) {
    perror("mmap decrypted macho");
    return -1;
  }
  memcpy((void*)mh_out,(void*)mh_in,st.st_size);

  macho_fat_for_each_macho(mh_in,^int(struct mach_header_64 *macho,uint64_t size){
    printf("[*] decrypting macho image[%s] at %p\n",macho_arch_string(macho),macho);
    size_t offset = (uint8_t*)macho - (uint8_t*)mh_in;
    struct mach_header_64 *macho_dec = (struct mach_header_64*)((uint8_t*)mh_out + offset);
    if(macho_is_macho32(macho)){
//      fairplay_decrypt_macho32(kext,handle, (const struct mach_header *)macho,
//                               (struct mach_header *)macho_dec);
    }else if(macho_is_macho64(macho)){
      fairplay_decrypt_macho64(kext,handle, (const struct mach_header_64 *)macho,
                                 (struct mach_header_64 *)macho_dec);
    }
    return 0;
  });

  assert(msync(mh_out,st.st_size, MS_SYNC) == 0);
  munmap(mh_out,st.st_size);
  munmap(mh_in,st.st_size);
  close(fd_in);
  close(fd_out);
  return 0;
}

int main() {
  // allocate a stub space
  mach_vm_address_t stub_code_start;
  mach_vm_size_t stub_code_size = mach_vm_round_page(SYM_REG_COUNT_MAX * 32);
  kern_return_t kr = mach_vm_allocate(mach_task_self(), &stub_code_start,
                                      stub_code_size, VM_FLAGS_ANYWHERE);
  assert(kr == KERN_SUCCESS);

  printf("stub_code start at %#llx\n", stub_code_start);

  struct mach_header_64 *kext = macho_load_file(
      kext_path,
      &g_image_slide, ^const void *(const char *sym, const uint64_t *addr) {
        // binding for registered symbols
        uint32_t i = 0;
        for (; i < SYM_REG_COUNT_MAX; i++) {
          if (!sym_regs[i].symbol) {
            break;
          }
          if (strcmp(sym_regs[i].symbol, sym) == 0) {
            return (void *)sym_regs[i].func;
          }
        }

        // no registration for this symbol, stub function just call
        // unhandled_imports(0xdeadbeef00000000 | i);
        assert(i + 1 < (SYM_REG_COUNT_MAX - 1));
        sym_regs[i].symbol = sym;
        uint8_t stub_code[32] =
            "\x80\x00\x00\x58" // LDR X0, #16
            "\xa8\x00\x00\x58" // LDR X8, #20
            //"\x00\x00\x20\xd4" //BRK #0
            "\x00\x01\x1f\xd6" // BR X8
            "\x1f\x20\x03\xd5" // NOP
            "SYM_REG_"         // qword : 0xdeadbeef00000000 | sym_reg_id
            "HAN_DLR_";        // qword : handle function

        uint64_t *stub_datas = (uint64_t *)((uint8_t *)stub_code + 16);
        stub_datas[0] = 0xdeadbeef00000000 | i;
        stub_datas[1] = (uint64_t)unhandled_imports;

        // copy stub code
        memcpy((void *)(stub_code_start + i * 32), (void *)stub_code, 32);
        sym_regs[i].func = (const void *)(stub_code_start + i * 32);

        sym_regs[i + 1].symbol = NULL;
        sym_regs[i + 1].func = NULL;

        return sym_regs[i].func;
      });

  macho_loaded_add_to_all_images(kext,kext_path);

  kr = mach_vm_protect(mach_task_self(), stub_code_start, stub_code_size, false,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  assert(kr == KERN_SUCCESS);

  krt_init((uint64_t)kext);

  printf("[*] press any key to start fairplay\n");
  //getchar();

  int ret = fairplay_init(kext);
  if(ret){
    return -1;
  }

  // "/Applications/Bilibili HD.app/WrappedBundle/bili-hd2" for 4096 bytes encrypted Mach-O
  // "/Applications/F5 Access.app/Wrapper/F5 Access.app/F5 Access" for Mach-O FAT
  //"/Applications/COVID-19.app/WrappedBundle/COVID-19" for iOS Mach-O
  return fairplay_decrypt(
      kext,  "/Applications/COVID-19.app/WrappedBundle/COVID-19" ,
      "/tmp/decrypted");
}
