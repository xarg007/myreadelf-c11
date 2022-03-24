#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

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

struct S_ELF64_SectHeader_t
{
	Elf64_Word    sh_name     ; /* Section name, index in string tbl */
	Elf64_Word    sh_type     ; /* Type of section */
	Elf64_Xword   sh_flags    ; /* Miscellaneous section attributes */
	Elf64_Addr    sh_addr     ; /* Section virtual addr at execution */
	Elf64_Off     sh_offset   ; /* Section file offset */
	Elf64_Xword   sh_size     ; /* Size of section in bytes */
	Elf64_Word    sh_link     ; /* Index of another section */
	Elf64_Word    sh_info     ; /* Additional section information */
	Elf64_Xword   sh_addralign; /* Section alignment */
	Elf64_Xword   sh_entsize  ; /* Entry size if section holds table */
};

int PrtSectHeader(int idx, struct S_ELF64_SectHeader_t* pSectHeader)
{
	xlog_info("        No.[%02d]--------------------------------------------\n", idx);
	xlog_info("        struct S_ELF64_SectHeader_t * pSectHeader = %p\n", pSectHeader);
	xlog_info("        {\n");
	xlog_info("             Elf64_Word    sh_name      = 0x%x;\n"  , pSectHeader->sh_name     );
	xlog_info("             Elf64_Word    sh_type      = 0x%x;\n"  , pSectHeader->sh_type     );
	xlog_info("             Elf64_Xword   sh_flags     = 0x%llx;\n", pSectHeader->sh_flags    );
	xlog_info("             Elf64_Addr    sh_addr      = 0x%llx;\n", pSectHeader->sh_addr     );
	xlog_info("             Elf64_Off     sh_offset    = 0x%llx;\n", pSectHeader->sh_offset   );
	xlog_info("             Elf64_Xword   sh_size      = 0x%llx;\n", pSectHeader->sh_size     );
	xlog_info("             Elf64_Word    sh_link      = 0x%x;\n"  , pSectHeader->sh_link     );
	xlog_info("             Elf64_Word    sh_info      = 0x%x;\n"  , pSectHeader->sh_info     );
	xlog_info("             Elf64_Xword   sh_addralign = 0x%llx;\n", pSectHeader->sh_addralign);
	xlog_info("             Elf64_Xword   sh_entsize   = 0x%llx;\n", pSectHeader->sh_entsize  );
	xlog_info("        }\n\n");
	
	return 0;
}

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

struct S_ELF64_SectHeader_t*
parse_elf64_sect_header(
    struct S_ELF64_ELFHeader_t* pElfHeader,
    unsigned char*              pSectHeaderData,
    int                         idx,
    unsigned char*              pSHName)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);

    struct S_ELF64_SectHeader_t* pSectHeader = (struct S_ELF64_SectHeader_t*)pSectHeaderData;
    
    if(0)
    {
        xlog_info("        SectionHeader[%02d] ----------------------------------------\n", idx);
        xlog_info("        struct S_ELF64_SectHeader_t * pSectHeader = %p\n", pSectHeader);
        xlog_info("        {\n");
        xlog_info("                 Elf64_Word    sh_name     = {0x%x|\"%s\"};\n" , pSectHeader->sh_name, (char*)(pSHName+pSectHeader->sh_name));
        xlog_info("                 Elf64_Word    sh_type     = 0x%x;         \n" , pSectHeader->sh_type     );
        xlog_info("                 Elf64_Xword   sh_flags    = 0x%llx;       \n" , pSectHeader->sh_flags    );
        xlog_info("                 Elf64_Addr    sh_addr     = 0x%llx;       \n" , pSectHeader->sh_addr     );
        xlog_info("                 Elf64_Off     sh_offset   = 0x%llx;       \n" , pSectHeader->sh_offset   );
        xlog_info("                 Elf64_Xword   sh_size     = 0x%llx;       \n" , pSectHeader->sh_size     );
        xlog_info("                 Elf64_Word    sh_link     = 0x%x;         \n" , pSectHeader->sh_link     );
        xlog_info("                 Elf64_Word    sh_info     = 0x%x;         \n" , pSectHeader->sh_info     );
        xlog_info("                 Elf64_Xword   sh_addralign= 0x%llx;       \n" , pSectHeader->sh_addralign);
        xlog_info("                 Elf64_Xword   sh_entsize  = 0x%llx;       \n" , pSectHeader->sh_entsize  );
        xlog_info("        };\n");
    }
    
    return pSectHeader;
}

struct S_ELF64_SectHeader_t** 
parse_elf64_sect_headers(
    struct S_ELF64_ELFHeader_t* pElfHeader,
    unsigned char* pSectHeadersData,
    unsigned char* pSHName
    )
{
    xlog_info("  >> func{%s:(%05d)} is call .\n", __func__, __LINE__);

    struct S_ELF64_SectHeader_t** ppSectHeaders = calloc(pElfHeader->e_shnum+1, sizeof(struct S_ELF64_SectHeader_t*));
    
    for(int i=0; i<pElfHeader->e_shnum; i++)
    {
        //xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
        struct S_ELF64_SectHeader_t* pSectHeader = parse_elf64_sect_header(pElfHeader, (pSectHeadersData + pElfHeader->e_shentsize*i), i, pSHName);
        assert(pSectHeader != NULL);
        if(pSectHeader != NULL)
        {
            //xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
        }
        
        *(ppSectHeaders+i) = pSectHeader;
    }
    
    xlog_info("  >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    xlog_info("\n\n");
    xlog_info("\e[1m----------------------------------------------------------------\e[0m\n");
    xlog_info("Section Headers:  \n");
    xlog_info("  [Nr] Name            Type      Address     Offset  Size    EntSize Flags  Link   Info   Align\n");
    for(int i=0; i<pElfHeader->e_shnum; i++)
    {
        //            Nr     name type   addr   offset    size  ent_sz    flags   link   info addr_lig
        printf("  [%02d] %-15.15s %08x  %010llx  %6.6lld  %6.6lld  %6.6lld  0x%04llx 0x%04x 0x%04x 0x%04llx\n", i,
                        pSHName+(*(ppSectHeaders+i))->sh_name,
                        (*(ppSectHeaders+i))->sh_type,
                            ppSectHeaders[i]->sh_addr,
                          (*ppSectHeaders[i]).sh_offset,
                        (*(ppSectHeaders+i))->sh_size,
                        (*(ppSectHeaders+i))->sh_entsize,
                        (*(ppSectHeaders+i))->sh_flags,
                        (*(ppSectHeaders+i))->sh_link,
                        (*(ppSectHeaders+i))->sh_info,
                        (*(ppSectHeaders+i))->sh_addralign);
    }
    xlog_info("\e[1m----------------------------------------------------------------\e[0m\n");
    
    xlog_info("  >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    xlog_info("\n\n");
    
    return ppSectHeaders;
}

//===============================================================
struct s_elf64_obj_t
{
    uint8_t*                      pElfData      ;
    struct S_ELF64_ELFHeader_t*   pElfHeader    ;
    struct S_ELF64_ELFHeader_t    ElfHeaderObj  ;
    struct S_ELF64_SectHeader_t** ppSectHeaders ;
    struct S_ELF64_SectHeader_t   SectHeaderObjs[0x30];
};

struct s_elf64_obj_t* build_elf64_obj(uint8_t* p_elf64_data, uint32_t len)
{
    xlog_info("  >> build_elf64_obj(%p, %d) entry;\n", p_elf64_data, len);
    
    unsigned int elf64_obj_size = sizeof(struct s_elf64_obj_t);
    
    struct s_elf64_obj_t* p_elf64_obj = (struct s_elf64_obj_t*)calloc(elf64_obj_size/4+6, 4);
    
    p_elf64_obj->pElfData     = p_elf64_data;
    p_elf64_obj->pElfHeader   = parse_elf64_elf_header(p_elf64_data);
    p_elf64_obj->ElfHeaderObj = *p_elf64_obj->pElfHeader;
    
    struct S_ELF64_ELFHeader_t* pElfHeader = p_elf64_obj->pElfHeader;
    
    uint8_t* pElfData = p_elf64_data;
    //=================================================================
    //e_shstrndx String Table Index,
    //在节区表中有一个存储各节区名称的节区(通常是最后一个),
    //这里表示名称表在第几个节区。

    //先取得节区名称表对应的节头数据；
    struct S_ELF64_SectHeader_t* pSect_ShStrTab_Header = 
               (struct S_ELF64_SectHeader_t*)((pElfData+pElfHeader->e_shoff) + pElfHeader->e_shentsize*pElfHeader->e_shstrndx);
    //                                        |<-sect header start   addr->|  |<-每sect header size->| |<-    偏移单元个数 ->|
    
    PrtSectHeader(pElfHeader->e_shstrndx, pSect_ShStrTab_Header);

    //进一步分析节区名称数据；
    unsigned char* pSectNames = pElfData+pSect_ShStrTab_Header->sh_offset;
    
    xlog_hexdump(pSectNames, pSect_ShStrTab_Header->sh_size);

    p_elf64_obj->ppSectHeaders = parse_elf64_sect_headers(pElfHeader, (unsigned char*)(pElfData+pElfHeader->e_shoff), pSectNames);
    
    for(int i=0; i<p_elf64_obj->pElfHeader->e_shnum; i++)
    {
        p_elf64_obj->SectHeaderObjs[i] = *p_elf64_obj->ppSectHeaders[i];
    }
    
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

#define x_lnx 1
#if x_lnx
void __attribute__((constructor)) before_main_func(void)
{
    xlog_info("\e[1;32m################################################{"
        "}##################################################\e[0m\n");
    xlog_info("  \e[1;31m#====>>>>\e[0m\n");
    xlog_info("  >> func{%s:(%05d)@(%s)} is call .\n", __func__, __LINE__, __FILE__);
    return;
}

void __attribute__((destructor))  after_main_func(void)
{
    xlog_info("  >> func{%s:(%05d)@(%s)} is call .\n", __func__, __LINE__, __FILE__);
    xlog_info("  \e[1;31m#<<<<====\e[0m\n");
    return;
}

void my_init01(void) __attribute__((constructor));
void my_fini01(void) __attribute__((destructor ));
void my_init02(void) __attribute__((constructor));
void my_fini02(void) __attribute__((destructor ));
void my_init03(void) __attribute__((constructor));
void my_fini03(void) __attribute__((destructor ));

void my_init01(void)
{
    xlog_info("  \e[1;31m#====>>>>\e[0m\n");
    xlog_info("  >> func{%s:(%05d)@(%s)} is call .\n", __func__, __LINE__, __FILE__);
    return;
}
void my_fini01(void)
{
    xlog_info("  >> func{%s:(%05d)@(%s)} is call .\n", __func__, __LINE__, __FILE__);
    xlog_info("  \e[1;31m#<<<<====\e[0m\n");
    return;
}
void my_init02(void)
{
    xlog_info("  \e[1;31m#====>>>>\e[0m\n");
    xlog_info("  >> func{%s:(%05d)@(%s)} is call .\n", __func__, __LINE__, __FILE__);
    return;
}
void my_fini02(void)
{
    xlog_info("  >> func{%s:(%05d)@(%s)} is call .\n", __func__, __LINE__, __FILE__);
    xlog_info("  \e[1;31m#<<<<====\e[0m\n");
    return;
}
void my_init03(void)
{
    xlog_info("  \e[1;31m#====>>>>\e[0m\n");
    xlog_info("  >> func{%s:(%05d)@(%s)} is call .\n", __func__, __LINE__, __FILE__);
    return;
}
void my_fini03(void)
{
    xlog_info("  >> func{%s:(%05d)@(%s)} is call .\n", __func__, __LINE__, __FILE__);
    xlog_info("  \e[1;31m#<<<<====\e[0m\n");
    return;
}
#endif

int parse_args(int argc, char* argv[])
{
    xlog_info("  >> func:%s(%d, %p) is called. (@file:%s,line:%04d).\n",
            __func__, argc, argv, __FILE__, __LINE__);
    xlog_info("\n");
    for(int i=0; i<argc; i++)
    {
        xlog_info("    >>> argv[%02d](addr=%p) = {\"%s\"}.\n", i, argv[i], argv[i]);
    }
    xlog_info("\n");
    xlog_info("  >> func:%s() is called. @line:(%04d).\n", __func__, __LINE__);
    
    return 0;
}

// 解析节头表数据
// gcc -std=c11 -g -Wall -O0 -DXLOG_PTHREAD_T=1 myreadelf-0.1.0x.c -o myapp -pthread
int main(int argc, char* argv[])
{
    xlog_init();
    xlog_info("  >> the app starting ... ...\n");
    xlog_hexdump((uint8_t*)argv   , 16*5+11);
    xlog_hexdump((uint8_t*)argv[0], 16*5+11);
    parse_args(argc, argv);
    
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
xadmin@hw:~/xwks.git.1/myreadelf-c11$ gcc -std=c11 -g -Wall -O0  myreadelf-0.1.03.c -o myapp
xadmin@hw:~/xwks.git.1/myreadelf-c11$ ./myapp
################################################{}##################################################
  #====>>>>
  >> func{before_main_func:(00511)@(myreadelf-0.1.03.c)} is call .
  #====>>>>
  >> func{my_init01:(00532)@(myreadelf-0.1.03.c)} is call .
  #====>>>>
  >> func{my_init02:(00544)@(myreadelf-0.1.03.c)} is call .
  #====>>>>
  >> func{my_init03:(00556)@(myreadelf-0.1.03.c)} is call .
  >> the app starting ... ...

0x007ffcde54a1a8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|60 b6 54 de fc 7f 00 00  00 00 00 00 00 00 00 00|`.T.............|
      0x00000010|68 b6 54 de fc 7f 00 00  78 b6 54 de fc 7f 00 00|h.T.....x.T.....|
      0x00000020|90 b6 54 de fc 7f 00 00  a7 b6 54 de fc 7f 00 00|..T.......T.....|
      0x00000030|bb b6 54 de fc 7f 00 00  d3 b6 54 de fc 7f 00 00|..T.......T.....|
      0x00000040|fd b6 54 de fc 7f 00 00  0c b7 54 de fc 7f 00 00|..T.......T.....|
      0x00000050|21 b7 54 de fc 7f 00 00  30 b7 54 ** ** ** ** **|!.T.....0.T*****|
      =============================================================================


0x007ffcde54b660|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2e 2f 6d 79 61 70 70 00  53 48 45 4c 4c 3d 2f 62|./myapp.SHELL=/b|
      0x00000010|69 6e 2f 62 61 73 68 00  4c 41 4e 47 55 41 47 45|in/bash.LANGUAGE|
      0x00000020|3d 7a 68 5f 43 4e 3a 65  6e 5f 55 53 3a 65 6e 00|=zh_CN:en_US:en.|
      0x00000030|4c 43 5f 41 44 44 52 45  53 53 3d 7a 68 5f 43 4e|LC_ADDRESS=zh_CN|
      0x00000040|2e 55 54 46 2d 38 00 4c  43 5f 4e 41 4d 45 3d 7a|.UTF-8.LC_NAME=z|
      0x00000050|68 5f 43 4e 2e 55 54 46  2d 38 00 ** ** ** ** **|h_CN.UTF-8.*****|
      =============================================================================

  >> func:parse_args(1, 0x7ffcde54a1a8) is called. (@file:myreadelf-0.1.03.c,line:0570).

    >>> argv[00](addr=0x7ffcde54b660) = {"./myapp"}.

  >> func:parse_args() is called. @line:(0577).
  >> get_elf64_data("./myapp", len) entry;

0x0055edf0586890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  c0 11 00 00 00 00 00 00|..>.............|
      0x00000020|40 00 00 00 00 00 00 00  68 85 00 00 00 00 00 00|@.......h.......|
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
      0x000000d0|b0 09 00 00 00 00 00 00  b0 09 00 00 00 00 00 00|................|
      0x000000e0|00 10 00 00 00 00 00 00  01 00 00 00 05 00 00 00|................|
      0x000000f0|00 10 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000100|00 10 00 00 00 00 00 00  81 1a 00 00 00 00 00 00|................|
      0x00000110|81 1a 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000120|01 00 00 00 04 00 00 00  00 30 00 00 00 00 00 00|.........0......|
      0x00000130|00 30 00 00 00 00 00 00  00 30 00 00 00 00 00 00|.0.......0......|
      0x00000140|28 14 00 00 00 ** ** **  ** ** ** ** ** ** ** **|(....***********|
      =============================================================================

  >> build_elf64_obj(0x55edf0586890, 36456) entry;
  >> func{parse_elf64_elf_header:(00307)} is call.{pElfData=0x55edf0586890}.
        struct S_ELF64_ELFHeader_t pElfHeader = {0x55edf0586890} 
        {
                 unsigned char e_ident[16] = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00};
                 Elf64_Half    e_type      = 0x0003;
                 Elf64_Half    e_machine   = 0x003e;
                 Elf64_Word    e_version   = 0x1  ;
                 Elf64_Addr    e_entry     = 0x11c0;
                 Elf64_Off     e_phoff     = 0x40;
                 Elf64_Off     e_shoff     = 0x8568;
                 Elf64_Word    e_flags     = 0x0  ;
                 Elf64_Half    e_ehsize    = 0x0040;
                 Elf64_Half    e_phentsize = 0x0038;
                 Elf64_Half    e_phnum     = 0x000d;
                 Elf64_Half    e_shentsize = 0x0040;
                 Elf64_Half    e_shnum     = 0x0024;
                 Elf64_Half    e_shstrndx  = 0x0023;
        };
        No.[35]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f6b8
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0x8408;
             Elf64_Xword   sh_size      = 0x15a;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }


0x0055edf058ec98|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 2e 73 79 6d 74 61 62  00 2e 73 74 72 74 61 62|..symtab..strtab|
      0x00000010|00 2e 73 68 73 74 72 74  61 62 00 2e 69 6e 74 65|..shstrtab..inte|
      0x00000020|72 70 00 2e 6e 6f 74 65  2e 67 6e 75 2e 70 72 6f|rp..note.gnu.pro|
      0x00000030|70 65 72 74 79 00 2e 6e  6f 74 65 2e 67 6e 75 2e|perty..note.gnu.|
      0x00000040|62 75 69 6c 64 2d 69 64  00 2e 6e 6f 74 65 2e 41|build-id..note.A|
      0x00000050|42 49 2d 74 61 67 00 2e  67 6e 75 2e 68 61 73 68|BI-tag..gnu.hash|
      0x00000060|00 2e 64 79 6e 73 79 6d  00 2e 64 79 6e 73 74 72|..dynsym..dynstr|
      0x00000070|00 2e 67 6e 75 2e 76 65  72 73 69 6f 6e 00 2e 67|..gnu.version..g|
      0x00000080|6e 75 2e 76 65 72 73 69  6f 6e 5f 72 00 2e 72 65|nu.version_r..re|
      0x00000090|6c 61 2e 64 79 6e 00 2e  72 65 6c 61 2e 70 6c 74|la.dyn..rela.plt|
      0x000000a0|00 2e 69 6e 69 74 00 2e  70 6c 74 2e 67 6f 74 00|..init..plt.got.|
      0x000000b0|2e 70 6c 74 2e 73 65 63  00 2e 74 65 78 74 00 2e|.plt.sec..text..|
      0x000000c0|66 69 6e 69 00 2e 72 6f  64 61 74 61 00 2e 65 68|fini..rodata..eh|
      0x000000d0|5f 66 72 61 6d 65 5f 68  64 72 00 2e 65 68 5f 66|_frame_hdr..eh_f|
      0x000000e0|72 61 6d 65 00 2e 69 6e  69 74 5f 61 72 72 61 79|rame..init_array|
      0x000000f0|00 2e 66 69 6e 69 5f 61  72 72 61 79 00 2e 64 79|..fini_array..dy|
      0x00000100|6e 61 6d 69 63 00 2e 64  61 74 61 00 2e 62 73 73|namic..data..bss|
      0x00000110|00 2e 63 6f 6d 6d 65 6e  74 00 2e 64 65 62 75 67|..comment..debug|
      0x00000120|5f 61 72 61 6e 67 65 73  00 2e 64 65 62 75 67 5f|_aranges..debug_|
      0x00000130|69 6e 66 6f 00 2e 64 65  62 75 67 5f 61 62 62 72|info..debug_abbr|
      0x00000140|65 76 00 2e 64 65 62 75  67 5f 6c 69 6e 65 00 2e|ev..debug_line..|
      0x00000150|64 65 62 75 67 5f 73 74  72 00 ** ** ** ** ** **|debug_str.******|
      =============================================================================

  >> func{parse_elf64_sect_headers:(00388)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[00] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058edf8
        {
                 Elf64_Word    sh_name     = {0x0|""};
                 Elf64_Word    sh_type     = 0x0;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x0;       
                 Elf64_Xword   sh_size     = 0x0;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x0;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[01] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058ee38
        {
                 Elf64_Word    sh_name     = {0x1b|".interp"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x318;       
                 Elf64_Off     sh_offset   = 0x318;       
                 Elf64_Xword   sh_size     = 0x1c;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[02] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058ee78
        {
                 Elf64_Word    sh_name     = {0x23|".note.gnu.property"};
                 Elf64_Word    sh_type     = 0x7;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x338;       
                 Elf64_Off     sh_offset   = 0x338;       
                 Elf64_Xword   sh_size     = 0x20;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[03] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058eeb8
        {
                 Elf64_Word    sh_name     = {0x36|".note.gnu.build-id"};
                 Elf64_Word    sh_type     = 0x7;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x358;       
                 Elf64_Off     sh_offset   = 0x358;       
                 Elf64_Xword   sh_size     = 0x24;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x4;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[04] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058eef8
        {
                 Elf64_Word    sh_name     = {0x49|".note.ABI-tag"};
                 Elf64_Word    sh_type     = 0x7;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x37c;       
                 Elf64_Off     sh_offset   = 0x37c;       
                 Elf64_Xword   sh_size     = 0x20;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x4;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[05] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058ef38
        {
                 Elf64_Word    sh_name     = {0x57|".gnu.hash"};
                 Elf64_Word    sh_type     = 0x6ffffff6;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x3a0;       
                 Elf64_Off     sh_offset   = 0x3a0;       
                 Elf64_Xword   sh_size     = 0x28;       
                 Elf64_Word    sh_link     = 0x6;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[06] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058ef78
        {
                 Elf64_Word    sh_name     = {0x61|".dynsym"};
                 Elf64_Word    sh_type     = 0xb;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x3c8;       
                 Elf64_Off     sh_offset   = 0x3c8;       
                 Elf64_Xword   sh_size     = 0x1c8;       
                 Elf64_Word    sh_link     = 0x7;         
                 Elf64_Word    sh_info     = 0x1;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x18;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[07] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058efb8
        {
                 Elf64_Word    sh_name     = {0x69|".dynstr"};
                 Elf64_Word    sh_type     = 0x3;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x590;       
                 Elf64_Off     sh_offset   = 0x590;       
                 Elf64_Xword   sh_size     = 0xfb;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[08] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058eff8
        {
                 Elf64_Word    sh_name     = {0x71|".gnu.version"};
                 Elf64_Word    sh_type     = 0x6fffffff;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x68c;       
                 Elf64_Off     sh_offset   = 0x68c;       
                 Elf64_Xword   sh_size     = 0x26;       
                 Elf64_Word    sh_link     = 0x6;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x2;       
                 Elf64_Xword   sh_entsize  = 0x2;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[09] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f038
        {
                 Elf64_Word    sh_name     = {0x7e|".gnu.version_r"};
                 Elf64_Word    sh_type     = 0x6ffffffe;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x6b8;       
                 Elf64_Off     sh_offset   = 0x6b8;       
                 Elf64_Xword   sh_size     = 0x40;       
                 Elf64_Word    sh_link     = 0x7;         
                 Elf64_Word    sh_info     = 0x1;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[10] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f078
        {
                 Elf64_Word    sh_name     = {0x8d|".rela.dyn"};
                 Elf64_Word    sh_type     = 0x4;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x6f8;       
                 Elf64_Off     sh_offset   = 0x6f8;       
                 Elf64_Xword   sh_size     = 0x198;       
                 Elf64_Word    sh_link     = 0x6;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x18;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[11] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f0b8
        {
                 Elf64_Word    sh_name     = {0x97|".rela.plt"};
                 Elf64_Word    sh_type     = 0x4;         
                 Elf64_Xword   sh_flags    = 0x42;       
                 Elf64_Addr    sh_addr     = 0x890;       
                 Elf64_Off     sh_offset   = 0x890;       
                 Elf64_Xword   sh_size     = 0x120;       
                 Elf64_Word    sh_link     = 0x6;         
                 Elf64_Word    sh_info     = 0x18;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x18;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[12] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f0f8
        {
                 Elf64_Word    sh_name     = {0xa1|".init"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x1000;       
                 Elf64_Off     sh_offset   = 0x1000;       
                 Elf64_Xword   sh_size     = 0x1b;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x4;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[13] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f138
        {
                 Elf64_Word    sh_name     = {0x9c|".plt"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x1020;       
                 Elf64_Off     sh_offset   = 0x1020;       
                 Elf64_Xword   sh_size     = 0xd0;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x10;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[14] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f178
        {
                 Elf64_Word    sh_name     = {0xa7|".plt.got"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x10f0;       
                 Elf64_Off     sh_offset   = 0x10f0;       
                 Elf64_Xword   sh_size     = 0x10;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x10;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[15] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f1b8
        {
                 Elf64_Word    sh_name     = {0xb0|".plt.sec"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x1100;       
                 Elf64_Off     sh_offset   = 0x1100;       
                 Elf64_Xword   sh_size     = 0xc0;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x10;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[16] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f1f8
        {
                 Elf64_Word    sh_name     = {0xb9|".text"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x11c0;       
                 Elf64_Off     sh_offset   = 0x11c0;       
                 Elf64_Xword   sh_size     = 0x18b4;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[17] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f238
        {
                 Elf64_Word    sh_name     = {0xbf|".fini"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x2a74;       
                 Elf64_Off     sh_offset   = 0x2a74;       
                 Elf64_Xword   sh_size     = 0xd;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x4;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[18] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f278
        {
                 Elf64_Word    sh_name     = {0xc5|".rodata"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x3000;       
                 Elf64_Off     sh_offset   = 0x3000;       
                 Elf64_Xword   sh_size     = 0xf1b;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[19] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f2b8
        {
                 Elf64_Word    sh_name     = {0xcd|".eh_frame_hdr"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x3f1c;       
                 Elf64_Off     sh_offset   = 0x3f1c;       
                 Elf64_Xword   sh_size     = 0x104;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x4;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[20] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f2f8
        {
                 Elf64_Word    sh_name     = {0xdb|".eh_frame"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x4020;       
                 Elf64_Off     sh_offset   = 0x4020;       
                 Elf64_Xword   sh_size     = 0x408;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[21] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f338
        {
                 Elf64_Word    sh_name     = {0xe5|".init_array"};
                 Elf64_Word    sh_type     = 0xe;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x5d20;       
                 Elf64_Off     sh_offset   = 0x4d20;       
                 Elf64_Xword   sh_size     = 0x28;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x8;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[22] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f378
        {
                 Elf64_Word    sh_name     = {0xf1|".fini_array"};
                 Elf64_Word    sh_type     = 0xf;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x5d48;       
                 Elf64_Off     sh_offset   = 0x4d48;       
                 Elf64_Xword   sh_size     = 0x28;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x8;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[23] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f3b8
        {
                 Elf64_Word    sh_name     = {0xfd|".dynamic"};
                 Elf64_Word    sh_type     = 0x6;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x5d70;       
                 Elf64_Off     sh_offset   = 0x4d70;       
                 Elf64_Xword   sh_size     = 0x1f0;       
                 Elf64_Word    sh_link     = 0x7;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x10;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[24] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f3f8
        {
                 Elf64_Word    sh_name     = {0xab|".got"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x5f60;       
                 Elf64_Off     sh_offset   = 0x4f60;       
                 Elf64_Xword   sh_size     = 0xa0;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x8;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[25] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f438
        {
                 Elf64_Word    sh_name     = {0x106|".data"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x6000;       
                 Elf64_Off     sh_offset   = 0x5000;       
                 Elf64_Xword   sh_size     = 0x10;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[26] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f478
        {
                 Elf64_Word    sh_name     = {0x10c|".bss"};
                 Elf64_Word    sh_type     = 0x8;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x6010;       
                 Elf64_Off     sh_offset   = 0x5010;       
                 Elf64_Xword   sh_size     = 0x10;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[27] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f4b8
        {
                 Elf64_Word    sh_name     = {0x111|".comment"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x30;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x5010;       
                 Elf64_Xword   sh_size     = 0x2b;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x1;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[28] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f4f8
        {
                 Elf64_Word    sh_name     = {0x11a|".debug_aranges"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x503b;       
                 Elf64_Xword   sh_size     = 0x30;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[29] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f538
        {
                 Elf64_Word    sh_name     = {0x129|".debug_info"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x506b;       
                 Elf64_Xword   sh_size     = 0x112f;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[30] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f578
        {
                 Elf64_Word    sh_name     = {0x135|".debug_abbrev"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x619a;       
                 Elf64_Xword   sh_size     = 0x24a;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[31] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f5b8
        {
                 Elf64_Word    sh_name     = {0x143|".debug_line"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x63e4;       
                 Elf64_Xword   sh_size     = 0x760;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[32] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f5f8
        {
                 Elf64_Word    sh_name     = {0x14f|".debug_str"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x30;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x6b44;       
                 Elf64_Xword   sh_size     = 0x87a;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x1;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[33] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f638
        {
                 Elf64_Word    sh_name     = {0x1|".symtab"};
                 Elf64_Word    sh_type     = 0x2;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x73c0;       
                 Elf64_Xword   sh_size     = 0xb40;       
                 Elf64_Word    sh_link     = 0x22;         
                 Elf64_Word    sh_info     = 0x41;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x18;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[34] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f678
        {
                 Elf64_Word    sh_name     = {0x9|".strtab"};
                 Elf64_Word    sh_type     = 0x3;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x7f00;       
                 Elf64_Xword   sh_size     = 0x508;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00356)} is call .
        SectionHeader[35] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55edf058f6b8
        {
                 Elf64_Word    sh_name     = {0x11|".shstrtab"};
                 Elf64_Word    sh_type     = 0x3;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x8408;       
                 Elf64_Xword   sh_size     = 0x15a;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
  >> func{parse_elf64_sect_headers:(00405)} is call .


----------------------------------------------------------------
Section Headers:  
  [Nr] Name            Type      Address     Offset  Size    EntSize Flags  Link   Info   Align
  [00]                 00000000  0000000000  000000  000000  000000  0x0000 0x0000 0x0000 0x0000
  [01] .interp         00000001  0000000318  000792  000028  000000  0x0002 0x0000 0x0000 0x0001
  [02] .note.gnu.prope 00000007  0000000338  000824  000032  000000  0x0002 0x0000 0x0000 0x0008
  [03] .note.gnu.build 00000007  0000000358  000856  000036  000000  0x0002 0x0000 0x0000 0x0004
  [04] .note.ABI-tag   00000007  000000037c  000892  000032  000000  0x0002 0x0000 0x0000 0x0004
  [05] .gnu.hash       6ffffff6  00000003a0  000928  000040  000000  0x0002 0x0006 0x0000 0x0008
  [06] .dynsym         0000000b  00000003c8  000968  000456  000024  0x0002 0x0007 0x0001 0x0008
  [07] .dynstr         00000003  0000000590  001424  000251  000000  0x0002 0x0000 0x0000 0x0001
  [08] .gnu.version    6fffffff  000000068c  001676  000038  000002  0x0002 0x0006 0x0000 0x0002
  [09] .gnu.version_r  6ffffffe  00000006b8  001720  000064  000000  0x0002 0x0007 0x0001 0x0008
  [10] .rela.dyn       00000004  00000006f8  001784  000408  000024  0x0002 0x0006 0x0000 0x0008
  [11] .rela.plt       00000004  0000000890  002192  000288  000024  0x0042 0x0006 0x0018 0x0008
  [12] .init           00000001  0000001000  004096  000027  000000  0x0006 0x0000 0x0000 0x0004
  [13] .plt            00000001  0000001020  004128  000208  000016  0x0006 0x0000 0x0000 0x0010
  [14] .plt.got        00000001  00000010f0  004336  000016  000016  0x0006 0x0000 0x0000 0x0010
  [15] .plt.sec        00000001  0000001100  004352  000192  000016  0x0006 0x0000 0x0000 0x0010
  [16] .text           00000001  00000011c0  004544  006324  000000  0x0006 0x0000 0x0000 0x0010
  [17] .fini           00000001  0000002a74  010868  000013  000000  0x0006 0x0000 0x0000 0x0004
  [18] .rodata         00000001  0000003000  012288  003867  000000  0x0002 0x0000 0x0000 0x0010
  [19] .eh_frame_hdr   00000001  0000003f1c  016156  000260  000000  0x0002 0x0000 0x0000 0x0004
  [20] .eh_frame       00000001  0000004020  016416  001032  000000  0x0002 0x0000 0x0000 0x0008
  [21] .init_array     0000000e  0000005d20  019744  000040  000008  0x0003 0x0000 0x0000 0x0008
  [22] .fini_array     0000000f  0000005d48  019784  000040  000008  0x0003 0x0000 0x0000 0x0008
  [23] .dynamic        00000006  0000005d70  019824  000496  000016  0x0003 0x0007 0x0000 0x0008
  [24] .got            00000001  0000005f60  020320  000160  000008  0x0003 0x0000 0x0000 0x0008
  [25] .data           00000001  0000006000  020480  000016  000000  0x0003 0x0000 0x0000 0x0008
  [26] .bss            00000008  0000006010  020496  000016  000000  0x0003 0x0000 0x0000 0x0008
  [27] .comment        00000001  0000000000  020496  000043  000001  0x0030 0x0000 0x0000 0x0001
  [28] .debug_aranges  00000001  0000000000  020539  000048  000000  0x0000 0x0000 0x0000 0x0001
  [29] .debug_info     00000001  0000000000  020587  004399  000000  0x0000 0x0000 0x0000 0x0001
  [30] .debug_abbrev   00000001  0000000000  024986  000586  000000  0x0000 0x0000 0x0000 0x0001
  [31] .debug_line     00000001  0000000000  025572  001888  000000  0x0000 0x0000 0x0000 0x0001
  [32] .debug_str      00000001  0000000000  027460  002170  000001  0x0030 0x0000 0x0000 0x0001
  [33] .symtab         00000002  0000000000  029632  002880  000024  0x0000 0x0022 0x0041 0x0008
  [34] .strtab         00000003  0000000000  032512  001288  000000  0x0000 0x0000 0x0000 0x0001
  [35] .shstrtab       00000003  0000000000  033800  000346  000000  0x0000 0x0000 0x0000 0x0001
----------------------------------------------------------------
  >> func{parse_elf64_sect_headers:(00428)} is call .


  >> build_elf64_obj() exit;

0x0055edf058f710|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|90 68 58 f0 ed 55 00 00  90 68 58 f0 ed 55 00 00|.hX..U...hX..U..|
      0x00000010|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000020|03 00 3e 00 01 00 00 00  c0 11 00 00 00 00 00 00|..>.............|
      0x00000030|40 00 00 00 00 00 00 00  68 85 00 00 00 00 00 00|@.......h.......|
      0x00000040|00 00 00 00 40 00 38 00  0d 00 40 00 24 00 23 00|....@.8...@.$.#.|
      0x00000050|90 03 59 f0 ed 55 00 00  00 00 00 00 00 00 00 00|..Y..U..........|
      0x00000060|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000070|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000080|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000090|00 00 00 00 00 00 00 00  1b 00 00 00 01 00 00 00|................|
      0x000000a0|02 00 00 00 00 00 00 00  18 03 00 00 00 00 00 00|................|
      0x000000b0|18 03 00 00 00 00 00 00  1c 00 00 00 00 00 00 00|................|
      0x000000c0|00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00|................|
      0x000000d0|00 00 00 00 00 00 00 00  23 00 00 00 07 00 00 00|........#.......|
      0x000000e0|02 00 00 00 00 00 00 00  38 03 00 00 00 00 00 00|........8.......|
      0x000000f0|38 03 00 00 00 00 00 00  20 00 00 00 00 00 00 00|8....... .......|
      0x00000100|00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000110|00 00 00 00 00 00 00 00  36 00 00 00 07 00 00 00|........6.......|
      0x00000120|02 00 00 00 00 00 00 00  58 03 00 00 00 00 00 00|........X.......|
      0x00000130|58 03 00 00 00 00 00 00  24 00 00 00 00 00 00 00|X.......$.......|
      0x00000140|00 00 00 00 00 ** ** **  ** ** ** ** ** ** ** **|.....***********|
      =============================================================================

  >> the app exit.
  >> func{my_fini03:(00561)@(myreadelf-0.1.03.c)} is call .
  #<<<<====
  >> func{my_fini02:(00549)@(myreadelf-0.1.03.c)} is call .
  #<<<<====
  >> func{my_fini01:(00537)@(myreadelf-0.1.03.c)} is call .
  #<<<<====
  >> func{after_main_func:(00517)@(myreadelf-0.1.03.c)} is call .
  #<<<<====
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 

#endif

#if 0
xadmin@hw:~/xwks.git.1/myreadelf-c11$ gcc -std=c11 -g -Wall -O0  myreadelf-0.1.03.c -o myapp
xadmin@hw:~/xwks.git.1/myreadelf-c11$ valgrind --tool=memcheck --leak-check=full --track-origins=yes -s ./myapp
==189534== Memcheck, a memory error detector
==189534== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==189534== Using Valgrind-3.15.0 and LibVEX; rerun with -h for copyright info
==189534== Command: ./myapp
==189534== 
################################################{}##################################################
  #====>>>>
  >> func{before_main_func:(00511)@(myreadelf-0.1.03.c)} is call .
  #====>>>>
  >> func{my_init01:(00532)@(myreadelf-0.1.03.c)} is call .
  #====>>>>
  >> func{my_init02:(00544)@(myreadelf-0.1.03.c)} is call .
  #====>>>>
  >> func{my_init03:(00556)@(myreadelf-0.1.03.c)} is call .
  >> the app starting ... ...

0x00001fff0002c8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|6b 05 00 ff 1f 00 00 00  00 00 00 00 00 00 00 00|k...............|
      0x00000010|73 05 00 ff 1f 00 00 00  93 05 00 ff 1f 00 00 00|s...............|
      0x00000020|ab 05 00 ff 1f 00 00 00  b7 05 00 ff 1f 00 00 00|................|
      0x00000030|da 05 00 ff 1f 00 00 00  ee 05 00 ff 1f 00 00 00|................|
      0x00000040|03 06 00 ff 1f 00 00 00  0b 06 00 ff 1f 00 00 00|................|
      0x00000050|2a 06 00 ff 1f 00 00 00  39 06 00 ** ** ** ** **|*.......9..*****|
      =============================================================================


0x00001fff00056b|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2e 2f 6d 79 61 70 70 00  4c 45 53 53 4f 50 45 4e|./myapp.LESSOPEN|
      0x00000010|3d 7c 20 2f 75 73 72 2f  62 69 6e 2f 6c 65 73 73|=| /usr/bin/less|
      0x00000020|70 69 70 65 20 25 73 00  4c 41 4e 47 55 41 47 45|pipe %s.LANGUAGE|
      0x00000030|3d 7a 68 5f 43 4e 3a 65  6e 5f 55 53 3a 65 6e 00|=zh_CN:en_US:en.|
      0x00000040|55 53 45 52 3d 78 61 64  6d 69 6e 00 53 53 48 5f|USER=xadmin.SSH_|
      0x00000050|43 4c 49 45 4e 54 3d 31  39 32 2e ** ** ** ** **|CLIENT=192.*****|
      =============================================================================

  >> func:parse_args(1, 0x1fff0002c8) is called. (@file:myreadelf-0.1.03.c,line:0570).

    >>> argv[00](addr=0x1fff00056b) = {"./myapp"}.

  >> func:parse_args() is called. @line:(0577).
  >> get_elf64_data("./myapp", len) entry;

0x00000004a5c6a0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  c0 11 00 00 00 00 00 00|..>.............|
      0x00000020|40 00 00 00 00 00 00 00  48 85 00 00 00 00 00 00|@.......H.......|
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
      0x000000d0|b0 09 00 00 00 00 00 00  b0 09 00 00 00 00 00 00|................|
      0x000000e0|00 10 00 00 00 00 00 00  01 00 00 00 05 00 00 00|................|
      0x000000f0|00 10 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000100|00 10 00 00 00 00 00 00  11 19 00 00 00 00 00 00|................|
      0x00000110|11 19 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000120|01 00 00 00 04 00 00 00  00 30 00 00 00 00 00 00|.........0......|
      0x00000130|00 30 00 00 00 00 00 00  00 30 00 00 00 00 00 00|.0.......0......|
      0x00000140|68 11 00 00 00 ** ** **  ** ** ** ** ** ** ** **|h....***********|
      =============================================================================

  >> build_elf64_obj(0x4a5c6a0, 36424) entry;
  >> func{parse_elf64_elf_header:(00307)} is call.{pElfData=0x4a5c6a0}.
        struct S_ELF64_ELFHeader_t pElfHeader = {0x4a5c6a0} 
        {
                 unsigned char e_ident[16] = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00};
                 Elf64_Half    e_type      = 0x0003;
                 Elf64_Half    e_machine   = 0x003e;
                 Elf64_Word    e_version   = 0x1  ;
                 Elf64_Addr    e_entry     = 0x11c0;
                 Elf64_Off     e_phoff     = 0x40;
                 Elf64_Off     e_shoff     = 0x8548;
                 Elf64_Word    e_flags     = 0x0  ;
                 Elf64_Half    e_ehsize    = 0x0040;
                 Elf64_Half    e_phentsize = 0x0038;
                 Elf64_Half    e_phnum     = 0x000d;
                 Elf64_Half    e_shentsize = 0x0040;
                 Elf64_Half    e_shnum     = 0x0024;
                 Elf64_Half    e_shstrndx  = 0x0023;
        };
        No.[35]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x4a654a8
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0x83e8;
             Elf64_Xword   sh_size      = 0x15a;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }


0x00000004a64a88|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 2e 73 79 6d 74 61 62  00 2e 73 74 72 74 61 62|..symtab..strtab|
      0x00000010|00 2e 73 68 73 74 72 74  61 62 00 2e 69 6e 74 65|..shstrtab..inte|
      0x00000020|72 70 00 2e 6e 6f 74 65  2e 67 6e 75 2e 70 72 6f|rp..note.gnu.pro|
      0x00000030|70 65 72 74 79 00 2e 6e  6f 74 65 2e 67 6e 75 2e|perty..note.gnu.|
      0x00000040|62 75 69 6c 64 2d 69 64  00 2e 6e 6f 74 65 2e 41|build-id..note.A|
      0x00000050|42 49 2d 74 61 67 00 2e  67 6e 75 2e 68 61 73 68|BI-tag..gnu.hash|
      0x00000060|00 2e 64 79 6e 73 79 6d  00 2e 64 79 6e 73 74 72|..dynsym..dynstr|
      0x00000070|00 2e 67 6e 75 2e 76 65  72 73 69 6f 6e 00 2e 67|..gnu.version..g|
      0x00000080|6e 75 2e 76 65 72 73 69  6f 6e 5f 72 00 2e 72 65|nu.version_r..re|
      0x00000090|6c 61 2e 64 79 6e 00 2e  72 65 6c 61 2e 70 6c 74|la.dyn..rela.plt|
      0x000000a0|00 2e 69 6e 69 74 00 2e  70 6c 74 2e 67 6f 74 00|..init..plt.got.|
      0x000000b0|2e 70 6c 74 2e 73 65 63  00 2e 74 65 78 74 00 2e|.plt.sec..text..|
      0x000000c0|66 69 6e 69 00 2e 72 6f  64 61 74 61 00 2e 65 68|fini..rodata..eh|
      0x000000d0|5f 66 72 61 6d 65 5f 68  64 72 00 2e 65 68 5f 66|_frame_hdr..eh_f|
      0x000000e0|72 61 6d 65 00 2e 69 6e  69 74 5f 61 72 72 61 79|rame..init_array|
      0x000000f0|00 2e 66 69 6e 69 5f 61  72 72 61 79 00 2e 64 79|..fini_array..dy|
      0x00000100|6e 61 6d 69 63 00 2e 64  61 74 61 00 2e 62 73 73|namic..data..bss|
      0x00000110|00 2e 63 6f 6d 6d 65 6e  74 00 2e 64 65 62 75 67|..comment..debug|
      0x00000120|5f 61 72 61 6e 67 65 73  00 2e 64 65 62 75 67 5f|_aranges..debug_|
      0x00000130|69 6e 66 6f 00 2e 64 65  62 75 67 5f 61 62 62 72|info..debug_abbr|
      0x00000140|65 76 00 2e 64 65 62 75  67 5f 6c 69 6e 65 00 2e|ev..debug_line..|
      0x00000150|64 65 62 75 67 5f 73 74  72 00 ** ** ** ** ** **|debug_str.******|
      =============================================================================

  >> func{parse_elf64_sect_headers:(00388)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
    >> func{parse_elf64_sect_header:(00356)} is call .
  >> func{parse_elf64_sect_headers:(00405)} is call .


----------------------------------------------------------------
Section Headers:  
  [Nr] Name            Type      Address     Offset  Size    EntSize Flags  Link   Info   Align
  [00]                 00000000  0000000000  000000  000000  000000  0x0000 0x0000 0x0000 0x0000
  [01] .interp         00000001  0000000318  000792  000028  000000  0x0002 0x0000 0x0000 0x0001
  [02] .note.gnu.prope 00000007  0000000338  000824  000032  000000  0x0002 0x0000 0x0000 0x0008
  [03] .note.gnu.build 00000007  0000000358  000856  000036  000000  0x0002 0x0000 0x0000 0x0004
  [04] .note.ABI-tag   00000007  000000037c  000892  000032  000000  0x0002 0x0000 0x0000 0x0004
  [05] .gnu.hash       6ffffff6  00000003a0  000928  000040  000000  0x0002 0x0006 0x0000 0x0008
  [06] .dynsym         0000000b  00000003c8  000968  000456  000024  0x0002 0x0007 0x0001 0x0008
  [07] .dynstr         00000003  0000000590  001424  000251  000000  0x0002 0x0000 0x0000 0x0001
  [08] .gnu.version    6fffffff  000000068c  001676  000038  000002  0x0002 0x0006 0x0000 0x0002
  [09] .gnu.version_r  6ffffffe  00000006b8  001720  000064  000000  0x0002 0x0007 0x0001 0x0008
  [10] .rela.dyn       00000004  00000006f8  001784  000408  000024  0x0002 0x0006 0x0000 0x0008
  [11] .rela.plt       00000004  0000000890  002192  000288  000024  0x0042 0x0006 0x0018 0x0008
  [12] .init           00000001  0000001000  004096  000027  000000  0x0006 0x0000 0x0000 0x0004
  [13] .plt            00000001  0000001020  004128  000208  000016  0x0006 0x0000 0x0000 0x0010
  [14] .plt.got        00000001  00000010f0  004336  000016  000016  0x0006 0x0000 0x0000 0x0010
  [15] .plt.sec        00000001  0000001100  004352  000192  000016  0x0006 0x0000 0x0000 0x0010
  [16] .text           00000001  00000011c0  004544  005956  000000  0x0006 0x0000 0x0000 0x0010
  [17] .fini           00000001  0000002904  010500  000013  000000  0x0006 0x0000 0x0000 0x0004
  [18] .rodata         00000001  0000003000  012288  003163  000000  0x0002 0x0000 0x0000 0x0010
  [19] .eh_frame_hdr   00000001  0000003c5c  015452  000260  000000  0x0002 0x0000 0x0000 0x0004
  [20] .eh_frame       00000001  0000003d60  015712  001032  000000  0x0002 0x0000 0x0000 0x0008
  [21] .init_array     0000000e  0000005d20  019744  000040  000008  0x0003 0x0000 0x0000 0x0008
  [22] .fini_array     0000000f  0000005d48  019784  000040  000008  0x0003 0x0000 0x0000 0x0008
  [23] .dynamic        00000006  0000005d70  019824  000496  000016  0x0003 0x0007 0x0000 0x0008
  [24] .got            00000001  0000005f60  020320  000160  000008  0x0003 0x0000 0x0000 0x0008
  [25] .data           00000001  0000006000  020480  000016  000000  0x0003 0x0000 0x0000 0x0008
  [26] .bss            00000008  0000006010  020496  000016  000000  0x0003 0x0000 0x0000 0x0008
  [27] .comment        00000001  0000000000  020496  000043  000001  0x0030 0x0000 0x0000 0x0001
  [28] .debug_aranges  00000001  0000000000  020539  000048  000000  0x0000 0x0000 0x0000 0x0001
  [29] .debug_info     00000001  0000000000  020587  004399  000000  0x0000 0x0000 0x0000 0x0001
  [30] .debug_abbrev   00000001  0000000000  024986  000586  000000  0x0000 0x0000 0x0000 0x0001
  [31] .debug_line     00000001  0000000000  025572  001851  000000  0x0000 0x0000 0x0000 0x0001
  [32] .debug_str      00000001  0000000000  027423  002170  000001  0x0030 0x0000 0x0000 0x0001
  [33] .symtab         00000002  0000000000  029600  002880  000024  0x0000 0x0022 0x0041 0x0008
  [34] .strtab         00000003  0000000000  032480  001288  000000  0x0000 0x0000 0x0000 0x0001
  [35] .shstrtab       00000003  0000000000  033768  000346  000000  0x0000 0x0000 0x0000 0x0001
----------------------------------------------------------------
  >> func{parse_elf64_sect_headers:(00428)} is call .


  >> build_elf64_obj() exit;

0x00000004a66570|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|a0 c6 a5 04 00 00 00 00  a0 c6 a5 04 00 00 00 00|................|
      0x00000010|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000020|03 00 3e 00 01 00 00 00  c0 11 00 00 00 00 00 00|..>.............|
      0x00000030|40 00 00 00 00 00 00 00  48 85 00 00 00 00 00 00|@.......H.......|
      0x00000040|00 00 00 00 40 00 38 00  0d 00 40 00 24 00 23 00|....@.8...@.$.#.|
      0x00000050|20 72 a6 04 00 00 00 00  00 00 00 00 00 00 00 00| r..............|
      0x00000060|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000070|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000080|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000090|00 00 00 00 00 00 00 00  1b 00 00 00 01 00 00 00|................|
      0x000000a0|02 00 00 00 00 00 00 00  18 03 00 00 00 00 00 00|................|
      0x000000b0|18 03 00 00 00 00 00 00  1c 00 00 00 00 00 00 00|................|
      0x000000c0|00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00|................|
      0x000000d0|00 00 00 00 00 00 00 00  23 00 00 00 07 00 00 00|........#.......|
      0x000000e0|02 00 00 00 00 00 00 00  38 03 00 00 00 00 00 00|........8.......|
      0x000000f0|38 03 00 00 00 00 00 00  20 00 00 00 00 00 00 00|8....... .......|
      0x00000100|00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000110|00 00 00 00 00 00 00 00  36 00 00 00 07 00 00 00|........6.......|
      0x00000120|02 00 00 00 00 00 00 00  58 03 00 00 00 00 00 00|........X.......|
      0x00000130|58 03 00 00 00 00 00 00  24 00 00 00 00 00 00 00|X.......$.......|
      0x00000140|00 00 00 00 00 ** ** **  ** ** ** ** ** ** ** **|.....***********|
      =============================================================================

  >> the app exit.
  >> func{my_fini03:(00561)@(myreadelf-0.1.03.c)} is call .
  #<<<<====
  >> func{my_fini02:(00549)@(myreadelf-0.1.03.c)} is call .
  #<<<<====
  >> func{my_fini01:(00537)@(myreadelf-0.1.03.c)} is call .
  #<<<<====
  >> func{after_main_func:(00517)@(myreadelf-0.1.03.c)} is call .
  #<<<<====
==189534== 
==189534== HEAP SUMMARY:
==189534==     in use at exit: 296 bytes in 1 blocks
==189534==   total heap usage: 6 allocs, 5 frees, 45,504 bytes allocated
==189534== 
==189534== 296 bytes in 1 blocks are definitely lost in loss record 1 of 1
==189534==    at 0x483DD99: calloc (in /usr/lib/x86_64-linux-gnu/valgrind/vgpreload_memcheck-amd64-linux.so)
==189534==    by 0x109F60: parse_elf64_sect_headers (myreadelf-0.1.03.c:390)
==189534==    by 0x10A374: build_elf64_obj (myreadelf-0.1.03.c:476)
==189534==    by 0x10A808: main (myreadelf-0.1.03.c:603)
==189534== 
==189534== LEAK SUMMARY:
==189534==    definitely lost: 296 bytes in 1 blocks
==189534==    indirectly lost: 0 bytes in 0 blocks
==189534==      possibly lost: 0 bytes in 0 blocks
==189534==    still reachable: 0 bytes in 0 blocks
==189534==         suppressed: 0 bytes in 0 blocks
==189534== 
==189534== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 

#endif

