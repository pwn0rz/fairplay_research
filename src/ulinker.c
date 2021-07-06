#include "ulinker.h"

#include <assert.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <machine/endian.h>
#include <stdbool.h>

void perm_to_str(uint32_t proto, char out_str[4]){
  out_str[0] = proto & VM_PROT_READ ? 'r' : '-';
  out_str[1] = proto & VM_PROT_WRITE ? 'w' : '-';
  out_str[2] = proto & VM_PROT_EXECUTE ? 'x' : '-';
  out_str[3] = 0;
}

uint16_t macho_swap_endian_16(struct mach_header_64* mh,uint16_t v){
  switch (mh->magic) {
    case MH_MAGIC_64:
    case MH_MAGIC:
      return v;
      break;
    case MH_CIGAM_64:
    case MH_CIGAM:
      return __DARWIN_OSSwapConstInt16(v);
      break;
    default:
      fprintf(stderr,"invalid magic");
      abort();
    }
}

uint32_t macho_swap_endian_32(struct mach_header_64* mh,uint32_t v){
  switch (mh->magic) {
  case FAT_MAGIC_64:
  case FAT_MAGIC:
  case MH_MAGIC_64:
  case MH_MAGIC:
    return v;
    break;
  case FAT_CIGAM_64:
  case FAT_CIGAM:
  case MH_CIGAM_64:
  case MH_CIGAM:
    return __DARWIN_OSSwapConstInt32(v);
    break;
  default:
    fprintf(stderr,"invalid magic");
    abort();
  }
}

uint64_t macho_swap_endian_64(struct mach_header_64* mh,uint64_t v){
  switch (mh->magic) {
  case MH_MAGIC_64:
  case MH_MAGIC:
    return v;
    break;
  case MH_CIGAM_64:
  case MH_CIGAM:
    return __DARWIN_OSSwapConstInt64(v);
    break;
  default:
    fprintf(stderr,"invalid magic");
    abort();
  }
}

const char *macho_arch_string(struct mach_header_64 *mh){
  uint32_t cputype = macho_swap_endian_32(mh,mh->cputype);
  uint32_t subtype = macho_swap_endian_32(mh,mh->cpusubtype);

  switch (cputype) {
  case CPU_TYPE_ARM64:
  case CPU_TYPE_ARM:
    if(subtype == CPU_SUBTYPE_ARM64E){
      return "arm64e";
    }else if(subtype == CPU_SUBTYPE_ARM_V7){
      return "arm_v7";
    }else if(subtype == CPU_SUBTYPE_ARM_V6){
      return "arm_v6";
    }else if(subtype == CPU_SUBTYPE_ARM64_ALL){
      return "arm64";
    }
    break;
  case CPU_TYPE_X86:
    return "x86";
  case CPU_TYPE_X86_64:
    return "x64";
  default:
    break;
  }
  return "unknown";
}

struct mach_header_64 *
macho_load_file(
  const char *file,
  uint64_t  *image_slide_result,
  const void* (^imp_provider)(const char *, const uint64_t *))
{
  // mmaping macho into memory
  int fd = open(file, O_RDONLY);
  if (fd < 0) {
    perror("open macho");
    return NULL;
  }

  struct stat st = {0};
  int ret = fstat(fd, &st);
  if (ret) {
    perror("fstat macho");
    return NULL;
  }

  struct mach_header_64 *mh = (struct mach_header_64 *)mmap(
      NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0);
  if (mh == MAP_FAILED) {
    perror("mmap macho");
    return NULL;
  }
  close(fd);

  assert(mh->magic == MH_MAGIC_64);

  // find first and last seg
  __block struct segment_command_64 *first_seg =
      (struct segment_command_64 *)(mh + 1);
  __block struct segment_command_64 *last_seg = first_seg;
  macho64_for_each_seg(mh, ^int(struct segment_command_64 *seg) {
    if (seg->vmaddr < first_seg->vmaddr) {
      first_seg = seg;
    }
    if (seg->vmaddr > last_seg->vmaddr) {
      last_seg = seg;
    }
    return 0;
  });

  // allocate space for loaded images
  __block kern_return_t kr = KERN_SUCCESS;
  mach_vm_address_t image_start = first_seg->vmaddr;
  mach_vm_size_t image_size =
      last_seg->vmaddr + last_seg->vmsize - first_seg->vmaddr;

  kr = mach_vm_allocate(mach_task_self(), &image_start, image_size,
                        VM_PROT_READ | VM_PROT_WRITE);
  assert(kr == KERN_SUCCESS);

  mach_vm_address_t image_slide = image_start - first_seg->vmaddr;
  struct mach_header_64 *image = (struct mach_header_64 *)image_start;

  // copy segments to pre-allocated space according to macho file
  macho64_for_each_seg(mh, ^int(struct segment_command_64 *seg) {
    assert(seg->vmsize >= seg->filesize);
    assert(seg->vmaddr + image_slide + seg->vmsize <=
           image_start + image_size); // oob check
    kr = mach_vm_copy(mach_task_self(), (mach_vm_address_t)mh + seg->fileoff,
                      seg->filesize, seg->vmaddr + image_slide);
    assert(kr == KERN_SUCCESS);
    return 0;
  });

  // do fix-ups, for import binding and local pointer rebase
  macho_loaded_for_each_chained_fixup(
      image,

      ^int(uint64_t *addr, const char *sym)
      {
        //printf("bind address %p with %s\n",addr,sym);
        *addr = (uint64_t)imp_provider(sym,addr);
        return 0;
      }, ^int(uint64_t* addr, const uint64_t value)
      {
        //printf("rebase address %p with %#llx\n",addr,value);
        *addr = value + image_slide;
        return 0;
  });

  // lock down: change image protection
  macho64_for_each_seg(image, ^int(struct segment_command_64 *seg) {
    char initproto[4];
    char maxproto[4];
    perm_to_str(seg->initprot, initproto);
    perm_to_str(seg->maxprot, maxproto);
    printf("segment %16s @ %#010llx mapped into %#llx, %s => %s\n",
           seg->segname, seg->fileoff, seg->vmaddr + image_slide, initproto,
           maxproto);
    kr = mach_vm_protect(mach_task_self(), seg->vmaddr + image_slide,
                         seg->vmsize, false, seg->maxprot);

    assert(kr == KERN_SUCCESS);
    return 0;
  });

  image_slide_result && (*image_slide_result = image_slide);
  return image;
}

int macho_is_macho64(const struct mach_header_64 *mh){
  return mh->magic == MH_MAGIC_64 || mh->magic == MH_CIGAM_64;
}

int macho_is_macho32(const struct mach_header_64 *mh){
  return mh->magic == MH_MAGIC || mh->magic == MH_CIGAM;
}

int macho_is_macho(const struct mach_header_64 *mh){
  return macho_is_macho32(mh) || macho_is_macho64(mh);
}


int macho_is_fat64(const struct mach_header_64 *mh){
  return mh->magic == FAT_MAGIC_64 || mh->magic == FAT_CIGAM_64;
}

int macho_is_fat32(const struct mach_header_64 *mh){
  return mh->magic == FAT_MAGIC || mh->magic == FAT_CIGAM;
}

int macho_is_fat(const struct mach_header_64 *mh){
  return macho_is_fat32(mh) || macho_is_fat64(mh);
}

int macho_fat64_for_each_macho(struct fat_header *fat,int (^cb)(struct mach_header_64*,uint64_t)){
  assert(macho_is_fat64((const struct mach_header_64 *)fat));
  uint32_t narch = macho_swap_endian_32((struct mach_header_64 *)fat,fat->nfat_arch);
  struct fat_arch_64 *arch = (struct fat_arch_64*)(fat + 1);
  for(int i=0;i<narch;i++){
    uint64_t offset = macho_swap_endian_64((struct mach_header_64 *)fat,arch->offset);
    uint64_t size = macho_swap_endian_64((struct mach_header_64 *)fat,arch->size);

    struct mach_header_64*macho = (struct mach_header_64*)((uint8_t*)fat + offset);
    if(cb(macho,size)){
      break;
    }
  }
  return 0;
}

int macho_fat32_for_each_macho(struct fat_header *fat,int (^cb)(struct mach_header_64*,uint64_t)){
  assert(macho_is_fat32((const struct mach_header_64 *)fat));
  uint32_t narch = macho_swap_endian_32((struct mach_header_64 *)fat,fat->nfat_arch);
  struct fat_arch *arch = (struct fat_arch*)(fat + 1);
  for(int i=0;i<narch;i++){
    uint32_t offset = macho_swap_endian_32((struct mach_header_64 *)fat,arch[i].offset);
    uint32_t size = macho_swap_endian_32((struct mach_header_64 *)fat,arch[i].size);

    struct mach_header_64 *macho = (struct mach_header_64*)((uint8_t*)fat + offset);
    if(cb(macho,size)){
      break;
    }
  }
  return 0;
}

int macho_fat_for_each_macho(struct mach_header_64 *mh,int (^cb)(struct mach_header_64*,uint64_t)){
  if(macho_is_fat32(mh)){
    return macho_fat32_for_each_macho((struct fat_header *)mh,cb);
  }else if(macho_is_fat64(mh)){
    return macho_fat64_for_each_macho((struct fat_header *)mh,cb);
  }else{
    assert(macho_is_macho(mh));
    cb(mh,-1);
  }
  return 0;
};


int macho64_for_each_lc(struct mach_header_64 *mh, int (^cb)(struct load_command *lc))
{
  assert(mh->magic == MH_MAGIC_64 || mh->magic == MH_CIGAM_64);

  int ret = 0;
  struct load_command *lc = (struct load_command *)(mh + 1);

  uint32_t ncmds = macho_swap_endian_32(mh,mh->ncmds);
  uint32_t sizeofcmds = macho_swap_endian_32(mh,mh->sizeofcmds);

  for (uint32_t i = 0; i < ncmds; i++) {
    uint32_t cmdsize = macho_swap_endian_32(mh,lc->cmdsize);
    assert((uint8_t *)lc + cmdsize <= (uint8_t *)(mh + 1) + sizeofcmds);
    ret = cb(lc);
    if (ret) {
      break;
    }
    lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
  }
  return ret;
}

int macho32_for_each_lc(struct mach_header *mh, int (^cb)(struct load_command *lc))
{
  assert(mh->magic == MH_MAGIC || mh->magic == MH_CIGAM);

  int ret = 0;
  struct load_command *lc = (struct load_command *)(mh + 1);

  uint32_t ncmds = macho_swap_endian_32((struct mach_header_64*)mh,mh->ncmds);
  uint32_t sizeofcmds = macho_swap_endian_32((struct mach_header_64*)mh,mh->sizeofcmds);

  for (uint32_t i = 0; i < ncmds; i++) {
    uint32_t cmdsize = macho_swap_endian_32((struct mach_header_64*)mh,lc->cmdsize);
    assert((uint8_t *)lc + cmdsize <= (uint8_t *)(mh + 1) + sizeofcmds);
    ret = cb(lc);
    if (ret) {
      break;
    }
    lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
  }
  return ret;
}

struct load_command *macho64_get_lc(struct mach_header_64 *mh, uint32_t cmd) {
  __block struct load_command *found = NULL;
  macho64_for_each_lc(mh, ^int(struct load_command *lc) {
    uint32_t cur_cmd = macho_swap_endian_32(mh, lc->cmd);
    if (cur_cmd == cmd) {
      found = lc;
      return 1;
    }
    return 0;
  });

  return found;
}

struct load_command *macho32_get_lc(struct mach_header *mh, uint32_t cmd) {
  __block struct load_command *found = NULL;
  macho32_for_each_lc(mh, ^int(struct load_command *lc) {
    uint32_t cur_cmd = macho_swap_endian_32((struct mach_header_64 *)mh, lc->cmd);
    if (cur_cmd == cmd) {
      found = lc;
      return 1;
    }
    return 0;
  });

  return found;
}

int macho64_for_each_seg(
  struct mach_header_64 *mh,
  int (^cb)(struct segment_command_64 *seg))
{
  return macho64_for_each_lc(mh, ^int(struct load_command *lc) {
    if (lc->cmd == LC_SEGMENT_64) {
      struct segment_command_64 *seg = (struct segment_command_64 *)lc;
      return cb(seg);
    }
    return 0;
  });
}

struct segment_command_64*macho64_get_seg(
  struct mach_header_64 *mh,
  char *segname)
{
  __block struct segment_command_64 *found = NULL;
  macho64_for_each_seg(mh, ^int(struct segment_command_64 *seg) {
    if (strncmp(seg->segname, segname, sizeof(seg->segname)) == 0) {
      found = seg;
      return 1;
    }
    return 0;
  });
  return found;
}

struct segment_command_64*macho64_get_seg_by_id(
  struct mach_header_64*mh,
  uint32_t seg_id)
{
  __block struct segment_command_64 *found = NULL;
  __block uint32_t cur_id = 0;
  macho64_for_each_seg(mh, ^int(struct segment_command_64 *seg) {
    if (seg_id == cur_id) {
      found = seg;
      return 1;
    }
    cur_id += 1;
    return 0;
  });
  return found;
}

int macho64_seg_for_each_sec(struct segment_command_64 *seg,
                           int (^cb)(struct section_64 *sec)) {
  struct section_64 *sec = (struct section_64 *)(seg + 1);
  int ret = 0;
  for (uint32_t i = 0; i < seg->nsects; i++) {
    ret = cb(&sec[i]);
    if (ret) {
      break;
    }
  }
  return ret;
}

struct section_64 *macho64_get_sec(struct mach_header_64 *mh, char *segname,
                                 char *secname) {
  struct segment_command_64 *seg = macho64_get_seg(mh, segname);
  if (!seg) {
    return NULL;
  }

  __block struct section_64 *found = NULL;
  macho64_seg_for_each_sec(seg, ^int(struct section_64 *sec) {
    if (strncmp(sec->sectname, secname, sizeof(sec->sectname)) == 0) {
      found = sec;
      return 1;
    }
    return 0;
  });

  return found;
}

int macho_loaded_for_each_sym(struct mach_header_64 *mh,
                       int (^cb)(const char *sym, struct nlist_64 *nl)) {
  struct symtab_command *symtab =
      (struct symtab_command *)macho64_get_lc(mh, LC_SYMTAB);
  assert(symtab != NULL);

  struct segment_command_64 *linkedit = macho64_get_seg(mh, SEG_LINKEDIT);
  assert(linkedit != NULL);

  struct nlist_64 *nls = (struct nlist_64 *)((uint8_t*)mh + linkedit->vmaddr + symtab->symoff -
                                             linkedit->fileoff);
  const char *strings =
      (const char *)((uint8_t*)mh + linkedit->vmaddr + symtab->stroff - linkedit->fileoff);

  int ret = 0;
  for (uint32_t i = 0; i < symtab->nsyms; i++) {
    assert(nls[i].n_un.n_strx < symtab->strsize);
    ret = cb(strings + nls[i].n_un.n_strx, &nls[i]);
    if (ret) {
      break;
    }
  }

  return ret;
}

int macho_loaded_for_each_local_sym(struct mach_header_64 *mh,
                             int (^cb)(const char *, struct nlist_64 *)) {
  struct dysymtab_command *dysymtab =
      (struct dysymtab_command *)macho64_get_lc(mh, LC_DYSYMTAB);
  struct symtab_command *symtab =
      (struct symtab_command *)macho64_get_lc(mh, LC_SYMTAB);
  struct segment_command_64 *linkedit = macho64_get_seg(mh, SEG_LINKEDIT);

  struct nlist_64 *nls = (struct nlist_64 *)((uint8_t*)mh + linkedit->vmaddr + symtab->symoff -
                                             linkedit->fileoff);
  const char *strings =
      (const char *)((uint8_t*)mh + linkedit->vmaddr + symtab->stroff - linkedit->fileoff);

  int ret = 0;
  for (uint32_t i = dysymtab->ilocalsym;
       i < dysymtab->ilocalsym + dysymtab->nlocalsym; i++) {
    assert(i < symtab->nsyms);
    assert(nls[i].n_un.n_strx < symtab->strsize);
    ret = cb(strings + nls[i].n_un.n_strx, &nls[i]);
    if (ret) {
      break;
    }
  }

  return ret;
}

// aka exports
int macho_loaded_for_each_ext_def_sym(struct mach_header_64 *mh,
                               int (^cb)(const char *sym,
                                         struct nlist_64 *nl)) {
  struct dysymtab_command *dysymtab =
      (struct dysymtab_command *)macho64_get_lc(mh, LC_DYSYMTAB);
  struct symtab_command *symtab =
      (struct symtab_command *)macho64_get_lc(mh, LC_SYMTAB);
  struct segment_command_64 *linkedit = macho64_get_seg(mh, SEG_LINKEDIT);

  struct nlist_64 *nls = (struct nlist_64 *)((uint8_t*)mh + linkedit->vmaddr + symtab->symoff -
                                             linkedit->fileoff);
  const char *strings =
      (const char *)((uint8_t*)mh + linkedit->vmaddr + symtab->stroff - linkedit->fileoff);

  int ret = 0;
  for (uint32_t i = dysymtab->iextdefsym;
       i < dysymtab->iextdefsym + dysymtab->nextdefsym; i++) {
    assert(i < symtab->nsyms);

    assert(nls[i].n_un.n_strx < symtab->strsize);
    ret = cb(strings + nls[i].n_un.n_strx, &nls[i]);
    if (ret) {
      break;
    }
  }

  return ret;
}

int macho_loaded_for_each_local_reloc(struct mach_header_64 *mh,
                               int (^cb)(struct relocation_info *)) {
  struct dysymtab_command *dysymtab =
      (struct dysymtab_command *)macho64_get_lc(mh, LC_DYSYMTAB);
  struct segment_command_64 *linkedit = macho64_get_seg(mh, SEG_LINKEDIT);
  struct relocation_info *locrels =
      (struct relocation_info *)((uint8_t*)mh + linkedit->vmaddr +
                                 dysymtab->locreloff - linkedit->fileoff);

  int ret = 0;
  for (uint32_t i = 0; i < dysymtab->nlocrel; i++) {
    ret = cb(&locrels[i]);
    if (ret) {
      break;
    }
  }

  return ret;
}

int macho_loaded_for_each_external_reloc(struct mach_header_64 *mh,
                                  int (^cb)(const char *sym,
                                            struct relocation_info *reloc)) {
  struct dysymtab_command *dysymtab =
      (struct dysymtab_command *)macho64_get_lc(mh, LC_DYSYMTAB);
  struct symtab_command *symtab =
      (struct symtab_command *)macho64_get_lc(mh, LC_SYMTAB);
  struct segment_command_64 *linkedit = macho64_get_seg(mh, SEG_LINKEDIT);
  struct nlist_64 *nls = (struct nlist_64 *)((uint8_t*)mh + linkedit->vmaddr + symtab->symoff -
                                             linkedit->fileoff);
  const char *strings =
      (const char *)((uint8_t*)mh + linkedit->vmaddr + symtab->stroff - linkedit->fileoff);

  struct relocation_info *extrelocs =
      (struct relocation_info *)((uint8_t*)mh + linkedit->vmaddr + dysymtab->extreloff -
                                 linkedit->fileoff);

  int ret = 0;
  for (uint32_t i = 0; i < dysymtab->nextrel; i++) {
    assert(extrelocs[i].r_extern == 1);
    uint32_t sym_id = extrelocs[i].r_symbolnum;
    const char *sym = strings + nls[sym_id].n_un.n_strx;
    ret = cb(sym, &extrelocs[i]);
    if (ret) {
      break;
    }
  }

  return ret;
}

void* macho_loaded_resolve_sym(struct mach_header_64 *mh,const char *sym){
  __block uint64_t found = 0;
  macho_loaded_for_each_local_sym(mh,^int(const char *lsym, struct nlist_64 *nl){
    if(strcmp(lsym,sym) == 0){
      found = nl->n_value;
      return 1;
    }
    return 0;
  });
  if(found){
    return (uint8_t*)mh + found;
  }

  macho_loaded_for_each_ext_def_sym(mh,^int(const char *lsym, struct nlist_64 *nl){
    if(strcmp(lsym,sym) == 0){
      found = nl->n_value;
      return 1;
    }
    return 0;
  });

  if(found){
    return (uint8_t*)mh + found;
  }

  return NULL;
}


int macho_loaded_for_each_chained_fixup(struct mach_header_64 *mh, int (^bind_cb)(uint64_t *, const char *), int (^rebase_cb)(uint64_t *, const uint64_t )) {
  struct segment_command_64 *linkedit;

  struct linkedit_data_command *chained_fixups;
  struct dyld_chained_fixups_header *fixup_header;
  struct dyld_chained_starts_in_image *image_starts;
  struct dyld_chained_import *imports;
  struct symtab_command *symtab;
  const char *strings;

  symtab = (struct symtab_command*)macho64_get_lc(mh, LC_SYMTAB);
  linkedit = macho64_get_seg(mh, SEG_LINKEDIT);
  chained_fixups =
      (struct linkedit_data_command *)macho64_get_lc(
      mh, LC_DYLD_CHAINED_FIXUPS);
  if (!chained_fixups) {
    return -1;
  }

  // chained fix-ups is a payload embedded in linkedit
  fixup_header = (struct dyld_chained_fixups_header *)((uint8_t*)mh + linkedit->vmaddr +
                                                       chained_fixups->dataoff -
                                                       linkedit->fileoff);
  strings = (const char *)((uint8_t *)fixup_header + fixup_header->symbols_offset);
  image_starts = (struct dyld_chained_starts_in_image*)((uint8_t*)fixup_header + fixup_header->starts_offset);
  imports = (struct dyld_chained_import*)((uint8_t*)fixup_header + fixup_header->imports_offset);
  assert(fixup_header->imports_format == DYLD_CHAINED_IMPORT);

  //traverse segments
  /*
   *  +==============+
   *  +    Starts    +
   *  +   Seg Info   +
   *  +   Seg Info   +
   *  +==============+
   */
  for(uint32_t seg_id = 0; seg_id < image_starts->seg_count; seg_id++){
    struct dyld_chained_starts_in_segment *seg_info;
    struct segment_command_64 *seg = macho64_get_seg_by_id(mh, seg_id);
    uint32_t seg_info_off = image_starts->seg_info_offset[seg_id];
    if(!seg_info_off){
      continue;
    }
    seg_info = (struct dyld_chained_starts_in_segment*)((uint8_t*) image_starts + seg_info_off);

    for(uint32_t page_id = 0;page_id < seg_info->page_count;page_id++){
      uint16_t page_start = seg_info->page_start[page_id]; //chain_starts offset in page

      if(page_start == DYLD_CHAINED_PTR_START_NONE) {
        continue;
      }else if(page_start & DYLD_CHAINED_PTR_START_MULTI){
        fprintf(stderr,"unsupported chained ptr start");
        abort();
      }
      //we currently only support single chain at this time
      uint64_t ra = page_id * seg_info->page_size + page_start;
      uint64_t *chain = (uint64_t*)((uint8_t*)mh + seg->vmaddr + ra);
      struct dyld_chained_ptr_arm64e_bind *arm64e_bind;
      struct dyld_chained_ptr_arm64e_auth_bind *arm64e_auth_bind;
      struct dyld_chained_ptr_arm64e_rebase *arm64e_rebase;
      struct dyld_chained_ptr_arm64e_auth_rebase *arm64e_auth_rebase;
      struct dyld_chained_import *import_item;
      int ret = 0;
      switch (seg_info->pointer_format) {
      case DYLD_CHAINED_PTR_ARM64E_KERNEL:
        // arm64e kexts use this format, stide is 4 byte
        while (true){
          //process current chain
          //printf("processing chain at  %s + %#lx\n",seg->segname,(uint8_t*)chain - (uint8_t*)seg->vmaddr);
          arm64e_bind = (struct dyld_chained_ptr_arm64e_bind *)chain;
          arm64e_auth_bind = (struct dyld_chained_ptr_arm64e_auth_bind *)chain;
          arm64e_rebase = (struct dyld_chained_ptr_arm64e_rebase *)chain;
          arm64e_auth_rebase = (struct dyld_chained_ptr_arm64e_auth_rebase *)chain;

          //current chain should be PAC-ed
          uint64_t chain_next_id = arm64e_bind->next;
          if(arm64e_bind->auth){
            if(arm64e_bind->bind){
              //FIXME: we do not PAC value since we will compile it into ARM64 target
              assert(arm64e_auth_bind->ordinal < fixup_header->imports_count);
              import_item = &imports[arm64e_auth_bind->ordinal];
              assert(import_item->name_offset < symtab->strsize);
              ret = bind_cb((uint64_t *)arm64e_auth_bind,
                      strings + import_item->name_offset);
              if(ret){
                return ret;
              }
            }else{
              ret = rebase_cb((uint64_t *)arm64e_auth_rebase,
                        arm64e_auth_rebase->target);
              if(ret){
                return ret;
              }
            }
          }else{
            //current chain is non-PACed
            if(arm64e_bind->bind) {
              assert(arm64e_bind->ordinal < fixup_header->imports_count);
              import_item = &imports[arm64e_bind->ordinal];
              assert(import_item->name_offset < symtab->strsize);

              ret = bind_cb((uint64_t *)arm64e_bind,
                      strings + import_item->name_offset);
              if(ret){
                return ret;

              }

            }else{
              assert(arm64e_rebase->high8 == 0);
              int ret = rebase_cb((uint64_t *)arm64e_rebase, arm64e_rebase->target);
              if(ret){
                return ret;
              }
            }
          }

          //waring: after this call, field of chain might will be invalid
          //move to next chain
          if(chain_next_id){
            chain = (uint64_t*)((uint8_t*)chain + chain_next_id * 4);
          }else{
            break;
          }
        }
        break;
      default:
        fprintf(stderr,"unsupported dyld chained fix-ups, pointer format : %x\n",seg_info->pointer_format);
        abort();
      }

    }
  }
  return 0;
}


enum dyld_notify_mode { dyld_notify_adding=0, dyld_notify_removing=1, dyld_notify_remove_all=2 };


int macho_loaded_add_to_all_images(struct mach_header_64 *mh, const char *image_path){
  struct task_dyld_info dyld_info;
  uint32_t count = TASK_DYLD_INFO_COUNT;
  kern_return_t kr = task_info(mach_task_self(),TASK_DYLD_INFO,(task_info_t)&dyld_info,&count);
  assert(kr == KERN_SUCCESS);

  struct dyld_all_image_infos *all_image_infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
  struct mach_header_64* dyld = (struct mach_header_64*)all_image_infos->dyldImageLoadAddress;

  void (*dyld_debugger_notification)(enum dyld_notify_mode mode, unsigned long count, struct mach_header_64 *mh[]) = NULL;
  dyld_debugger_notification = macho_loaded_resolve_sym(dyld, "__dyld_debugger_notification");

  assert(dyld_debugger_notification != NULL);

  const struct dyld_image_info*  old_images = all_image_infos->infoArray;
  const uint32_t old_image_count = all_image_infos->infoArrayCount;
  all_image_infos->infoArray = NULL;

  struct dyld_image_info*  new_images = malloc(sizeof(struct dyld_image_info) * (old_image_count  + 1));
  memcpy(new_images, old_images, sizeof(struct dyld_image_info) * old_image_count);

  new_images[old_image_count].imageFileModDate = mach_absolute_time();
  new_images[old_image_count].imageFilePath = strdup(image_path);
  new_images[old_image_count].imageLoadAddress = (const struct mach_header*)mh;

  all_image_infos->infoArrayCount = old_image_count + 1;
  all_image_infos->infoArray = new_images;

  dyld_debugger_notification(dyld_notify_adding, 1, &mh);
  return 0;
}
