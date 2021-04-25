#ifndef _ULINKER_H_
#define _ULINKER_H_

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/fixup-chains.h>
#include <stdint.h>
#include <stdbool.h>

uint16_t macho_swap_endian_16(struct mach_header_64* mh,uint16_t v);
uint32_t macho_swap_endian_32(struct mach_header_64* mh,uint32_t v);
uint64_t macho_swap_endian_64(struct mach_header_64* mh,uint64_t v);

const char *macho_arch_string(struct mach_header_64 *mh);

struct mach_header_64* macho_load_file(const char *file,uint64_t *image_slide,const void* (^imp_provider)(const char *symbol,const uint64_t *addr));

int macho_is_macho64(const struct mach_header_64 *mh);
int macho_is_macho32(const struct mach_header_64 *mh);
int macho_is_macho(const struct mach_header_64 *mh);
int macho_is_fat64(const struct mach_header_64 *mh);
int macho_is_fat32(const struct mach_header_64 *mh);
int macho_is_fat(const struct mach_header_64 *mh);

int macho_fat_for_each_macho(struct mach_header_64  *mh,int (^cb)(struct mach_header_64 *macho, uint64_t size));

int macho64_for_each_lc(struct mach_header_64* mh, int (^cb)(struct load_command* lc));
int macho32_for_each_lc(struct mach_header *mh, int (^cb)(struct load_command *lc));

int macho64_for_each_seg(struct mach_header_64* mh,int (^cb)(struct segment_command_64 *seg));

int macho64_seg_for_each_sec(struct segment_command_64 *seg, int (^cb)(struct section_64 *sec));

struct load_command *macho64_get_lc(struct mach_header_64* mh, uint32_t cmd);
struct load_command *macho32_get_lc(struct mach_header *mh, uint32_t cmd);

struct segment_command_64 *macho64_get_seg(struct mach_header_64* mh, char *segname);
struct segment_command_64 *macho64_get_seg_by_id(struct mach_header_64*mh, uint32_t seg_id);
struct section_64 *macho64_get_sec(struct mach_header_64* mh,char *segname, char *secname);

//userspace program does not slide seg->vmaddr and nlist64->value

int macho_loaded_for_each_sym(struct mach_header_64 *mh,int (^cb)(const char *sym, struct nlist_64 *nl));

int macho_loaded_for_each_local_sym(struct mach_header_64 *mh, int (^cb)(const char *sym, struct nlist_64 *nl));
int macho_loaded_for_each_ext_def_sym(struct mach_header_64 *mh, int (^cb)(const char *sym, struct nlist_64 *nl));
void* macho_loaded_resolve_sym(struct mach_header_64 *mh,const char *sym);

int macho_loaded_for_each_local_reloc(struct mach_header_64 *mh, int (^cb)(struct relocation_info *reloc));
int macho_loaded_for_each_external_reloc(struct mach_header_64 *mh, int (^cb)(const char *sym, struct relocation_info *reloc));

int macho_loaded_for_each_chained_fixup(struct mach_header_64 *mh,int (^bind_cb)(uint64_t *addr, const char *symbol), int (^rebase_cb)(uint64_t *addr, const uint64_t value));


int macho_loaded_add_to_all_images(struct mach_header_64 *mh, const char *image_path);

#endif /*_ULINKER_H_*/