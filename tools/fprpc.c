#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <CommonCrypto/CommonCrypto.h>
#include <ctype.h>

void hexdump(void *ptr, int buflen) {
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


#pragma pack(push, 4)
struct FPRequest{
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t ool;
    NDR_record_t ndr;
    uint32_t size;
    uint64_t cpu_type;
    uint64_t cpu_subtype;
};

struct FPResponse{
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
#pragma pack(pop)

int fairplay_rpc(mach_port_t fp_port,const char *filepath,struct FPResponse *res){
    union Message
    {
        struct FPRequest In;
        struct FPResponse Out;
    };
    
    union Message msg;
    bzero(&msg,sizeof(msg));
    struct FPRequest *req = &msg.In;

    //make the checker happy
    req->header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND);
    req->header.msgh_size = 0x48;
    req->header.msgh_id = 502;
    req->header.msgh_remote_port = fp_port;
    req->header.msgh_local_port = mig_get_reply_port();
    req->header.msgh_voucher_port = MACH_PORT_NULL;
    req->body.msgh_descriptor_count = 1;

    req->size = strlen(filepath) + 1;
    req->ool.size = req->size;

    req->ool.address = strdup(filepath);
    req->ool.type = MACH_MSG_OOL_DESCRIPTOR;
    req->ool.copy = MACH_MSG_PHYSICAL_COPY;
    req->ool.deallocate = FALSE;

    req->ndr = NDR_record;

    req->cpu_type = 0x0100000c;
    req->cpu_subtype = 0x00000000;

    mach_error_t err;
    if( MACH_MSG_SUCCESS != (err =  mach_msg(&req->header,MACH_SEND_MSG | MACH_RCV_MSG | MACH_MSG_OPTION_NONE,req->header.msgh_size,sizeof(struct FPResponse),mig_get_reply_port(),MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL))){
        printf("[!] failed to send/recv unfreed mig requets : %s\n",mach_error_string(err));
        return -1;
    }

    memcpy(res,&msg.Out,sizeof(struct FPResponse));
    printf("[+] mig requests success\n");
    return 0;
}

int main(int argc,char *argv[])
{
    if(argc != 2){
        printf("[!] usage : %s : /path/to/executable",argv[0]);
        return 0;
    }

    printf("sizeof(struct FPRequest) = %#lx, sizeof(struct FPResponse) = %#lx\n",sizeof(struct FPRequest),sizeof(struct FPResponse));
    //printf("sizeof(mach_msg_header_t) = %#lx\n",sizeof(mach_msg_header_t));
    mach_port_t unfreed_port = 0xa03;
    if(KERN_SUCCESS != host_get_unfreed_port(mach_host_self(),&unfreed_port)){
        printf("[!]failed to get unfreed port\n");
        return -1;
    }

    printf("[+] got unfreed port : %#x\n",unfreed_port);

    struct FPResponse res;
    fairplay_rpc(unfreed_port,argv[1],&res);
    
    printf("size : %#x, id : %d, ool vm1 : %p, size = %#x, ool vm2 : %p, size = %#x\n",res.header.msgh_size,res.header.msgh_id,res.ool1.address,res.ool1.size,res.ool2.address,res.ool2.size);

    if(res.header.msgh_size <= 0x24){
        //invalid response
       printf("[!] mig response invalid\n");
        return -1;
    }
    CC_SHA1_CTX ctx;
    uint8_t hash[20];
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx,res.ool1.address,res.ool1.size);
    CC_SHA1_Final(hash,&ctx);

    printf("ool1: \n");
    hexdump(res.ool1.address,res.ool1.size);

    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx,res.ool2.address,res.ool2.size);
    CC_SHA1_Final(hash,&ctx);

    printf("ool2: \n");
    hexdump(res.ool2.address,res.ool2.size);


    printf("unk1: %#llx\n",res.unk1);

    printf("unk2: \n");
    hexdump(res.unk2,136);
    
    printf("unk3: \n");
    hexdump(res.unk3,84);
    
    printf("size1: %#x\n",res.size1);
    printf("size1: %#x\n",res.size2);


    printf("unk5: %#llx\n",res.unk5);
}
