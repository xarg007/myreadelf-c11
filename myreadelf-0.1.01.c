#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>

//=========================================================
#ifdef XLOG_PTHREAD_T
#include <pthread.h>
pthread_mutex_t     xlog_mutex_v = {0};
pthread_mutexattr_t xlog_attr_v  = {0};
#endif

void xlog_init()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_init(&xlog_mutex_v, NULL);
#endif

    return ;
}

void xlog_uninit()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_destroy(&xlog_mutex_v);
#endif

    return ;
}

void xlog_mutex_lock()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_lock(&xlog_mutex_v);
#endif

    return ;
}

void xlog_mutex_unlock()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_unlock(&xlog_mutex_v);
#endif

    return ;
}

//=========================================================
//typedef                   char    int8_t;
//typedef             short int     int16_t;
//typedef             long  int     int32_t;
//typedef        long long  int     int64_t;
typedef unsigned            char    uint8_t;
typedef unsigned      short int     uint16_t;
typedef unsigned      long  int     uint32_t;
typedef unsigned long long  int     uint64_t;
//=========================================================

int xlog_core(unsigned int ui_level, const char* fmt, va_list args)
{
    int iret = vprintf(fmt, args);
    fflush(stdout);
    return iret;
}

int xlog_info_x(const char* fmt, ...)
{
    int iret = 0;

    int log_switch = 1;

    if (log_switch)
    {
        va_list args = {0};
        va_start(args, fmt);
        iret = xlog_core(1, fmt, args);
        va_end(args);
    }
    
    return iret;
}

int xlog_hexdump(uint8_t* p_data, uint32_t i_len)
{
    int iret = 0;
    xlog_mutex_lock();
    if (p_data == NULL || i_len == 0)
    {
        xlog_mutex_unlock();
        return 0;
    }
    
    xlog_info_x("\n");
    xlog_info_x("%016p", p_data);
    xlog_info_x("|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|\n");
    xlog_info_x("      =============================================================================\n");
    
    unsigned int i_row = (i_len % 16 != 0 ? i_len / 16 + 1 : i_len / 16);
    for (unsigned int i = 0; i < i_row; i++)//逐行处理
    {
        //数据相对地址
        xlog_info_x("      0x%08x|", i * 16);
        
        //十六进制数据
        xlog_info_x("\e[32m");
        //当前行1~8列数据
        for (unsigned int j = 0; j < 8; j++)
        {
            if ((i * 16 + j) < i_len)
            {
                xlog_info_x("%02x ", *(p_data + i*16 + j));
            }
            else
            {
                xlog_info_x("** " );
            }
        }
        
        //在第8列与第9列中加空格列
        xlog_info_x(" ");
        
        //当前行前9~16列数据
        for (unsigned int j = 8; j < 16; j++)
        {
            if ((i * 16 + j) < i_len)
            {
                if (j < 15) xlog_info_x("%02x ", *(p_data + i*16 + j));
                else        xlog_info_x("%02x" , *(p_data + i*16 + j));
            }
            else
            {
                if (j < 15) xlog_info_x("** ");
                else        xlog_info_x("**" );
            }
        }
        
        xlog_info_x("\e[0m");
        
        //数据与字符边界
        xlog_info_x("|");
        
        //显示字符
        for (unsigned int j = 0; j < 16; j++)
        {
            if ((i * 16 + j) < i_len)
            {
                unsigned char test_char = *(p_data + i*16 + j);
                do
                {
                    if(isalpha(test_char)) break;
                    if(isdigit(test_char)) break;
                    if(ispunct(test_char)) break;
                    if(test_char == 0x20 ) break;
                    if(test_char == 0x0  ) break;
                    test_char = '.';
                }while(0);
                
                if(test_char == 0x0)
                {
                    xlog_info_x("\e[37m.\e[0m");
                }
                else
                {
                    xlog_info_x("%c", test_char);
                }
            }
            else
            {
                xlog_info_x("*");
            }
        }
        
        //行尾边界处理
        xlog_info_x("|");
        //换下一行
        xlog_info_x("\n");
    }
    xlog_info_x("      =============================================================================\n");
    xlog_info_x("\n");
    
    xlog_mutex_unlock();
    return iret;
}

int xlog_info(const char* fmt, ...)
{
    int iret = 0;
    xlog_mutex_lock();
    
    int log_switch = 1;

    if (log_switch)
    {
        va_list args = {0};
        va_start(args, fmt);
        iret = xlog_core(1, fmt, args);
        va_end(args);
    }
    
    xlog_mutex_unlock();
    return iret;
}

uint8_t* get_elf64_data(const char* filename, uint32_t* len)
{
    xlog_info("  >> get_elf64_data(\"%s\", len) entry;\n", filename);
    *len = 0x12;
    
    uint8_t* p_data         = NULL;
    struct stat statbuf     = {0};
    stat(filename, &statbuf);
    
    unsigned int iLen = statbuf.st_size;
    if(iLen > 0 && iLen < 10*1024*1024) //文件目前最大设为10M
    {
        FILE* hFile = fopen(filename, "rb");
        if(hFile == NULL) 
            return NULL;
        
        *len = iLen;
        p_data = (unsigned char*)calloc(iLen/4+2, sizeof(uint8_t)*4);
        
        size_t size_readok = fread(p_data, 1, iLen, hFile);
        fclose(hFile);
        
        if(size_readok != iLen)
        {
            free(p_data);
            return NULL;
        }
        
        return p_data;
    }
    
    xlog_info("  >> get_elf64_data() exit;\n");
    return NULL;
}

//===============================================================
/* 64-bit ELF base types. */
typedef unsigned long long  int Elf64_Addr  ;
typedef unsigned      short int Elf64_Half  ;
typedef   signed      short int Elf64_SHalf ;
typedef unsigned long long  int Elf64_Off   ;
typedef   signed            int Elf64_Sword ;
typedef unsigned            int Elf64_Word  ;
typedef unsigned long long  int Elf64_Xword ;
typedef   signed long long  int Elf64_Sxword;

struct S_ELF64_ELFHeader_t
{
    unsigned char e_ident[16]; /* ELF "magic number" */
    Elf64_Half    e_type     ;
    Elf64_Half    e_machine  ;
    Elf64_Word    e_version  ;
    Elf64_Addr    e_entry    ; /* Entry point virtual address */
    Elf64_Off     e_phoff    ; /* Program header table file offset */
    Elf64_Off     e_shoff    ; /* Section header table file offset */
    Elf64_Word    e_flags    ;
    Elf64_Half    e_ehsize   ;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum    ;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum    ;
    Elf64_Half    e_shstrndx ;
};

struct S_ELF64_ELFHeader_t* parse_elf64_elf_header(uint8_t* pElfData)
{
    xlog_info("  >> func{%s:(%05d)} is call.{pElfData=%p}.\n", __func__, __LINE__, pElfData);

    if(pElfData != NULL)
    {
        struct S_ELF64_ELFHeader_t* pElfHeader = (struct S_ELF64_ELFHeader_t*)pElfData;

        xlog_info("        struct S_ELF64_ELFHeader_t pElfHeader = {%p} \n", pElfHeader);
        xlog_info("        {\n");
        xlog_info("                 unsigned char e_ident[16] = {");
        for(int i=0; i<16; i++)
        {
            if(i<15)
            {
                xlog_info("%02x ", pElfHeader->e_ident[i]);
            }
            else
            {
                xlog_info("%02x", pElfHeader->e_ident[i]);
            }
        }
        xlog_info("};\n");
        xlog_info("                 Elf64_Half    e_type      = 0x%04x;\n", pElfHeader->e_type     );
        xlog_info("                 Elf64_Half    e_machine   = 0x%04x;\n", pElfHeader->e_machine  );
        xlog_info("                 Elf64_Word    e_version   = 0x%x  ;\n", pElfHeader->e_version  );
        xlog_info("                 Elf64_Addr    e_entry     = 0x%llx;\n", pElfHeader->e_entry    );
        xlog_info("                 Elf64_Off     e_phoff     = 0x%llx;\n", pElfHeader->e_phoff    );
        xlog_info("                 Elf64_Off     e_shoff     = 0x%llx;\n", pElfHeader->e_shoff    );
        xlog_info("                 Elf64_Word    e_flags     = 0x%x  ;\n", pElfHeader->e_flags    );
        xlog_info("                 Elf64_Half    e_ehsize    = 0x%04x;\n", pElfHeader->e_ehsize   );
        xlog_info("                 Elf64_Half    e_phentsize = 0x%04x;\n", pElfHeader->e_phentsize);
        xlog_info("                 Elf64_Half    e_phnum     = 0x%04x;\n", pElfHeader->e_phnum    );
        xlog_info("                 Elf64_Half    e_shentsize = 0x%04x;\n", pElfHeader->e_shentsize);
        xlog_info("                 Elf64_Half    e_shnum     = 0x%04x;\n", pElfHeader->e_shnum    );
        xlog_info("                 Elf64_Half    e_shstrndx  = 0x%04x;\n", pElfHeader->e_shstrndx );
        xlog_info("        };\n");

        return pElfHeader;
    }

    return NULL;
}

struct s_elf64_obj_t
{
    uint8_t*                    pElfData   ;
    struct S_ELF64_ELFHeader_t* pElfHeader ;
};

//===============================================================

struct s_elf64_obj_t* build_elf64_obj(uint8_t* p_elf64_data, uint32_t len)
{
    xlog_info("  >> build_elf64_obj(%p, %d) entry;\n", p_elf64_data, len);
    
    unsigned int elf64_obj_size = sizeof(struct s_elf64_obj_t);
    
    struct s_elf64_obj_t* p_elf64_obj = (struct s_elf64_obj_t*)calloc(elf64_obj_size/4+2, 4);
    
    p_elf64_obj->pElfData   = p_elf64_data;
    p_elf64_obj->pElfHeader = parse_elf64_elf_header(p_elf64_data);
    
    //
    
    xlog_info("  >> build_elf64_obj() exit;\n");
    return p_elf64_obj;
}

#if 0
$1 = {int (
            int, 
            char **
          )
     } 0x555555555d78 <main>
$2 = {int (
            int (*)(int, char **, char **), 
            int,
            char **,
            int (*)(int, char **, char **),
            void (*)(void), void (*)(void),
            void *
          )
     } 0x7ffff7ddbfc0 <__libc_start_main>
#endif

// 从ELF文件中取得十六进制数据，进行ELF Header分析
// gcc -std=c11 -g -Wall -O0 -DXLOG_PTHREAD_T=1 myreadelf-0.1.00.c -o myapp -pthread
int main(int argc, char* argv[])
{
    xlog_init();
    xlog_info("  >> the app starting ... ...\n");
    xlog_hexdump((uint8_t*)argv, 16*10+11);
    do
    {
        char* filename        = argv[0];
        uint32_t i_elf64_len  = 0;
        uint8_t* p_elf64_data = get_elf64_data(filename, &i_elf64_len); //取得数据；
        if(p_elf64_data==NULL || i_elf64_len==0)
        {
            xlog_info("   >>> \e[31mget_elf64_data(%s) ret(NULL).\e[0m\n", filename);
            break;
        }
        xlog_hexdump((uint8_t*)p_elf64_data, 16*20+5);
        
        struct s_elf64_obj_t* p_elf64_obj = build_elf64_obj(p_elf64_data, i_elf64_len);
        
        xlog_hexdump((uint8_t*)p_elf64_obj, 16*20+5);
        
        //printf_elf64_obj(p_elf64_obj);
        //
        //=============================================
        
        free(p_elf64_data);
        free(p_elf64_obj);
        
    }while(0);
    
    xlog_info("  >> the app exit.\n");
    xlog_uninit();
    return 0;
}

#if 0
xadmin@hw:~/xwks.git.1/myreadelf-c11$ gcc -std=c11 -g -Wall -O0  myreadelf-0.1.01.c -o myapp
xadmin@hw:~/xwks.git.1/myreadelf-c11$ ./myapp
  >> the app starting ... ...

0x007ffdbabbcee8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|60 d6 bb ba fd 7f 00 00  00 00 00 00 00 00 00 00|`...............|
      0x00000010|68 d6 bb ba fd 7f 00 00  78 d6 bb ba fd 7f 00 00|h.......x.......|
      0x00000020|90 d6 bb ba fd 7f 00 00  a7 d6 bb ba fd 7f 00 00|................|
      0x00000030|bb d6 bb ba fd 7f 00 00  d3 d6 bb ba fd 7f 00 00|................|
      0x00000040|fd d6 bb ba fd 7f 00 00  0c d7 bb ba fd 7f 00 00|................|
      0x00000050|21 d7 bb ba fd 7f 00 00  30 d7 bb ba fd 7f 00 00|!.......0.......|
      0x00000060|42 d7 bb ba fd 7f 00 00  57 d7 bb ba fd 7f 00 00|B.......W.......|
      0x00000070|68 d7 bb ba fd 7f 00 00  4a dd bb ba fd 7f 00 00|h.......J.......|
      0x00000080|7f dd bb ba fd 7f 00 00  a1 dd bb ba fd 7f 00 00|................|
      0x00000090|b8 dd bb ba fd 7f 00 00  d6 dd bb ba fd 7f 00 00|................|
      0x000000a0|e1 dd bb ba fd 7f 00 00  01 de bb ** ** ** ** **|...........*****|
      =============================================================================

  >> get_elf64_data(./myapp, len) entry;

0x0056147ca72890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  80 11 00 00 00 00 00 00|..>.............|
      0x00000020|40 00 00 00 00 00 00 00  e0 56 00 00 00 00 00 00|@........V......|
      0x00000030|00 00 00 00 40 00 38 00  0d 00 40 00 24 00 23 00|....@.8...@.$.#.|
      0x00000040|06 00 00 00 04 00 00 00  40 00 00 00 00 00 00 00|........@.......|
      0x00000050|40 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00|@.......@.......|
      0x00000060|d8 02 00 00 00 00 00 00  d8 02 00 00 00 00 00 00|................|
      0x00000070|08 00 00 00 00 00 00 00  03 00 00 00 04 00 00 00|................|
      0x00000080|18 03 00 00 00 00 00 00  18 03 00 00 00 00 00 00|................|
      0x00000090|18 03 00 00 00 00 00 00  1c 00 00 00 00 00 00 00|................|
      0x000000a0|1c 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00|................|
      0x000000b0|01 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000c0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000d0|78 08 00 00 00 00 00 00  78 08 00 00 00 00 00 00|x.......x.......|
      0x000000e0|00 10 00 00 00 00 00 00  01 00 00 00 05 00 00 00|................|
      0x000000f0|00 10 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000100|00 10 00 00 00 00 00 00  51 0f 00 00 00 00 00 00|........Q.......|
      0x00000110|51 0f 00 00 00 00 00 00  00 10 00 00 00 00 00 00|Q...............|
      0x00000120|01 00 00 00 04 00 00 00  00 20 00 00 00 00 00 00|......... ......|
      0x00000130|00 20 00 00 00 00 00 00  00 20 00 00 00 00 00 00|. ....... ......|
      0x00000140|d0 08 00 00 00 ** ** **  ** ** ** ** ** ** ** **|.....***********|
      =============================================================================

  >> build_elf64_obj(0x56147ca72890, 24544) entry;
  >> func{parse_elf64_elf_header:(00268)} is call.{pElfData=0x56147ca72890}.
        struct S_ELF64_ELFHeader_t pElfHeader = {0x56147ca72890} 
        {
                 unsigned char e_ident[16] = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00};
                 Elf64_Half    e_type      = 0x0003;
                 Elf64_Half    e_machine   = 0x003e;
                 Elf64_Word    e_version   = 0x1  ;
                 Elf64_Addr    e_entry     = 0x1180;
                 Elf64_Off     e_phoff     = 0x40;
                 Elf64_Off     e_shoff     = 0x56e0;
                 Elf64_Word    e_flags     = 0x0  ;
                 Elf64_Half    e_ehsize    = 0x0040;
                 Elf64_Half    e_phentsize = 0x0038;
                 Elf64_Half    e_phnum     = 0x000d;
                 Elf64_Half    e_shentsize = 0x0040;
                 Elf64_Half    e_shnum     = 0x0024;
                 Elf64_Half    e_shstrndx  = 0x0023;
        };
  >> build_elf64_obj() exit;

0x0056147ca78880|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|90 28 a7 7c 14 56 00 00  90 28 a7 7c 14 56 00 00|.(.|.V...(.|.V..|
      0x00000010|00 00 00 00 00 00 00 00  71 a7 01 00 00 00 00 00|........q.......|
      0x00000020|00 00 00 00 00 00 00 00  7b 02 00 00 12 00 10 00|........{.......|
      0x00000030|69 12 00 00 00 00 00 00  0b 00 00 00 00 00 00 00|i...............|
      0x00000040|85 02 00 00 12 00 10 00  b0 1e 00 00 00 00 00 00|................|
      0x00000050|65 00 00 00 00 00 00 00  95 02 00 00 12 00 00 00|e...............|
      0x00000060|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000070|a9 02 00 00 12 00 10 00  ff 1c 00 00 00 00 00 00|................|
      0x00000080|79 00 00 00 00 00 00 00  b9 02 00 00 12 00 10 00|y...............|
      0x00000090|74 12 00 00 00 00 00 00  0b 00 00 00 00 00 00 00|t...............|
      0x000000a0|d3 00 00 00 10 00 1a 00  20 40 00 00 00 00 00 00|........ @......|
      0x000000b0|00 00 00 00 00 00 00 00  c5 02 00 00 12 00 00 00|................|
      0x000000c0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000d0|34 02 00 00 12 00 10 00  80 11 00 00 00 00 00 00|4...............|
      0x000000e0|2f 00 00 00 00 00 00 00  da 02 00 00 12 00 10 00|/...............|
      0x000000f0|d3 18 00 00 00 00 00 00  a3 01 00 00 00 00 00 00|................|
      0x00000100|e9 02 00 00 10 00 1a 00  10 40 00 00 00 00 00 00|.........@......|
      0x00000110|00 00 00 00 00 00 00 00  f5 02 00 00 12 00 10 00|................|
      0x00000120|78 1d 00 00 00 00 00 00  29 01 00 00 00 00 00 00|x.......).......|
      0x00000130|fa 02 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000140|00 00 00 00 00 ** ** **  ** ** ** ** ** ** ** **|.....***********|
      =============================================================================

  >> the app exit.
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 

#endif
