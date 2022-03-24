#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
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

/* Values for section header, sh_type field.  */
#define SHT_NULL          0           /* Section header table entry unused */
#define SHT_PROGBITS      1           /* Program specific (private) data */
#define SHT_SYMTAB        2           /* Link editing symbol table */
#define SHT_STRTAB        3           /* A string table */
#define SHT_RELA          4           /* Relocation entries with addends */
#define SHT_HASH          5           /* A symbol hash table */
#define SHT_DYNAMIC       6           /* Information for dynamic linking */
#define SHT_NOTE          7           /* Information that marks file */
#define SHT_NOBITS        8           /* Section occupies no space in file */
#define SHT_REL           9           /* Relocation entries, no addends */
#define SHT_SHLIB         10          /* Reserved, unspecified semantics */
#define SHT_DYNSYM        11          /* Dynamic linking symbol table */
#define SHT_INIT_ARRAY    14          /* Array of ptrs to init functions */
#define SHT_FINI_ARRAY    15          /* Array of ptrs to finish functions */
#define SHT_PREINIT_ARRAY 16          /* Array of ptrs to pre-init funcs */
#define SHT_GROUP         17          /* Section contains a section group */
#define SHT_SYMTAB_SHNDX  18          /* Indices for SHN_XINDEX entries */
#define SHT_LOOS          0x60000000  /* First of OS specific semantics */
#define SHT_HIOS          0x6fffffff  /* Last of OS specific semantics */

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

struct S_ELF64_ProgHeader_t
{
    Elf64_Word    p_type      ; /* Type of segment */
    Elf64_Word    p_flags     ; /* Segment attributes */
    Elf64_Off     p_offset    ; /* Offset in file */
    Elf64_Addr    p_vaddr     ; /* Virtual address in memory */
    Elf64_Addr    p_paddr     ; /* Reserved */
    Elf64_Xword   p_filesz    ; /* Size of segment in file */
    Elf64_Xword   p_memsz     ; /* Size of segment in memory */
    Elf64_Xword   p_align     ; /* Alignment of segment */
};

struct S_Elf64_SymEnt_t
{
    Elf64_Word      st_name;
    unsigned char   st_info;
    unsigned char   st_other;
    Elf64_Half      st_shndx;
    Elf64_Addr      st_value;
    Elf64_Xword     st_size;
};

#define ELF64_ST_BIND(i)       ((i)>>4)
#define ELF64_ST_TYPE(i)       ((i)&0xf)
#define ELF64_ST_INFO(b,t)     (((b)<<4)+((t)&0xf))
#define ELF64_ST_VISIBILITY(o) ((o)&0x3)

struct s_elf64_obj_t
{
    uint8_t*                      pElfData      ;
    struct S_ELF64_ELFHeader_t*   pElfHeader    ;
    struct S_ELF64_ELFHeader_t    ElfHeaderObj  ;
    struct S_ELF64_SectHeader_t** ppSectHeaders ;
    struct S_ELF64_SectHeader_t   SectHeaderObjs[0x30];
    struct S_ELF64_ProgHeader_t** ppProgHeaders ;
    struct S_ELF64_ProgHeader_t   ProgHeaderObjs[0x10];
    
    //=================================================
    char*                         pDynStrData   ;
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
    xlog_info("        }\n");
    
    return 0;
}

int PrtProgHeader(int idx, struct S_ELF64_ProgHeader_t* pProgHeader)
{
    xlog_info("        No.[%02d]--------------------------------------------\n", idx);
    xlog_info("        struct S_ELF64_ProgHeader_t \n");
    xlog_info("        {\n");
    xlog_info("             Elf64_Word    p_type    = 0x%x;  \n", pProgHeader->p_type  );
    xlog_info("             Elf64_Word    p_flags   = 0x%x;  \n", pProgHeader->p_flags );
    xlog_info("             Elf64_Off     p_offset  = 0x%llx;\n", pProgHeader->p_offset);
    xlog_info("             Elf64_Addr    p_vaddr   = 0x%llx;\n", pProgHeader->p_vaddr );
    xlog_info("             Elf64_Addr    p_paddr   = 0x%llx;\n", pProgHeader->p_paddr );
    xlog_info("             Elf64_Xword   p_filesz  = 0x%llx;\n", pProgHeader->p_filesz);
    xlog_info("             Elf64_Xword   p_memsz   = 0x%llx;\n", pProgHeader->p_memsz );
    xlog_info("             Elf64_Xword   p_align   = 0x%llx;\n", pProgHeader->p_align );
    xlog_info("        }\n");
    
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
    //xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);

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
    //xlog_info("\n\n");
    
    return ppSectHeaders;
}

struct S_ELF64_ProgHeader_t* 
parse_elf64_prog_header(struct S_ELF64_ELFHeader_t* pElfHeader, unsigned char* pProgHeaderData, int idx)
{
    //xlog_info("  >> func\e[1m{%s:(%05d)}\e[0m is call .\n", __func__, __LINE__);
    
    struct S_ELF64_ProgHeader_t* pProgHeader = (struct S_ELF64_ProgHeader_t*)pProgHeaderData;
    if(0)
    {
        xlog_info("        ProgramHeader[%02d] ----------------------------------------\n", idx);
        xlog_info("        struct S_ELF64_ProgHeader_t \n");
        xlog_info("        {\n");
        xlog_info("             Elf64_Word    p_type    = 0x%x;  \n", pProgHeader->p_type  );
        xlog_info("             Elf64_Word    p_flags   = 0x%x;  \n", pProgHeader->p_flags );
        xlog_info("             Elf64_Off     p_offset  = 0x%llx;\n", pProgHeader->p_offset);
        xlog_info("             Elf64_Addr    p_vaddr   = 0x%llx;\n", pProgHeader->p_vaddr );
        xlog_info("             Elf64_Addr    p_paddr   = 0x%llx;\n", pProgHeader->p_paddr );
        xlog_info("             Elf64_Xword   p_filesz  = 0x%llx;\n", pProgHeader->p_filesz);
        xlog_info("             Elf64_Xword   p_memsz   = 0x%llx;\n", pProgHeader->p_memsz );
        xlog_info("             Elf64_Xword   p_align   = 0x%llx;\n", pProgHeader->p_align );
        xlog_info("        }\n");
        xlog_info("\n");
    }
    
    return pProgHeader;
}

struct S_ELF64_ProgHeader_t** 
parse_elf64_prog_headers(struct S_ELF64_ELFHeader_t* pElfHeader, unsigned char* pProgHeadersData, unsigned char* pSHName)
{
    xlog_info("  >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    struct S_ELF64_ProgHeader_t** ppProgHeaders = calloc(pElfHeader->e_phnum+1, sizeof(struct S_ELF64_ProgHeader_t*));
    
    for(int i=0; i<pElfHeader->e_phnum; i++)
    {
        struct S_ELF64_ProgHeader_t* pProgHeader = parse_elf64_prog_header(pElfHeader, pProgHeadersData + pElfHeader->e_phentsize*i, i);
        assert(pProgHeader != NULL);
        if(pProgHeader != NULL)
        {
            //xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
        }
        
        *(ppProgHeaders+i) = pProgHeader;
    }
    
    xlog_info("\n");
    xlog_info("    \e[1m----------------------------------------------------------------\e[0m\n");
    xlog_info("    Program Headers:\n");
    xlog_info("    [No] Type     Offset   VirtAddr   PhysAddr   FileSiz  MemSiz   Flags    Align\n");
    for(int i=0; i<pElfHeader->e_phnum; i++)
    {
        //       no    type ofset vaddr paddr file_sz memsize  flags   align
        xlog_info("    [%02d] %08x %08llx %010llx %010llx 0x%06llx 0x%06llx 0x%06x 0x%06llx\n",
                    i,
                    (*(ppProgHeaders+i))->p_type,
                    (*(ppProgHeaders+i))->p_offset,
                    (*(ppProgHeaders+i))->p_vaddr,
                    (*(ppProgHeaders+i))->p_paddr,
                    (*(ppProgHeaders+i))->p_filesz,
                    (*(ppProgHeaders+i))->p_memsz,
                    (*(ppProgHeaders+i))->p_flags,
                    (*(ppProgHeaders+i))->p_align
                    );
    }
    xlog_info("    \e[1m----------------------------------------------------------------\e[0m\n");
    
    //xlog_info("\n\n");
    
    return ppProgHeaders;
}

#if 1
int func_process               (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_interp           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_note_gnu_prope   (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_note_gnu_build   (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_note_ABI_tag     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_note_gnu_build_id(int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_gnu_hash         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_dynsym           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_dynstr           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_gnu_version      (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_gnu_version_r    (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_rela_dyn         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_rela_plt         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_init             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_plt              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_plt_got          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_text             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_fini             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_rodata           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_eh_frame_hdr     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_eh_frame         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_init_array       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_fini_array       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_dynamic          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_got              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_got_plt          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_data             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_bss              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_comment          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_debug_aranges    (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_debug_info       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_debug_abbrev     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_debug_line       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_debug_str        (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_symtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_strtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
int func_sect_shstrtab         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
#endif

#if 1
//int func_process             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_interp         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_note_gnu_prope   (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_note_gnu_build   (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_note_ABI_tag     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_note_gnu_build_id(int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_gnu_hash         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_dynsym         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_dynstr         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_gnu_version      (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_gnu_version_r    (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_rela_dyn         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_rela_plt         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_init             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_plt              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_plt_got          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_text             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_fini             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_rodata           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_eh_frame_hdr     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_eh_frame         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_init_array       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_fini_array       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_dynamic          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_got              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_got_plt          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_data             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_bss              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_comment          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_debug_aranges    (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_debug_info       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_debug_abbrev     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_debug_line       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_debug_str      (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_symtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_strtab         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_shstrtab       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
#endif

#if 1
//int func_process             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_interp           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    //.interp：保存 ELF 程序解释器的路径名。
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    if (pSectHeader->sh_type == SHT_PROGBITS)
    {
        xlog_info("      \e[1m------------------------------------------------------------\n");
        xlog_info("      ");
        for(int i=0; i<pSectHeader->sh_size; i++)
        {
            xlog_info("%c", *(pData+i));
        }
        xlog_info("\n");
        xlog_info("      ------------------------------------------------------------\e[0m\n");
        
    }
    
    return 0;
}

//int func_sect_note_gnu_prope   (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_note_gnu_build   (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_note_ABI_tag     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_note_gnu_build_id(int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_gnu_hash         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}

int func_sect_dynsym             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    do
    {
        unsigned char* pDynsymData = pData;
        
        struct S_Elf64_SymEnt_t** ppSymEnt = (struct S_Elf64_SymEnt_t**)malloc(sizeof(struct S_Elf64_SymEnt_t*) * (pSectHeader->sh_size/pSectHeader->sh_entsize+1));
        xlog_info("      Symbol table '.dynsym' contains %d entries:\n", (int)(pSectHeader->sh_size/pSectHeader->sh_entsize));
        xlog_info("         Num:    Value          Size Type    Bind   Vis      Ndx  Name  NameStr\n");
        for(int i=0; i<(pSectHeader->sh_size/pSectHeader->sh_entsize); i++)
        {
            struct S_Elf64_SymEnt_t* pSymEnt = (struct S_Elf64_SymEnt_t*)malloc( sizeof(struct S_Elf64_SymEnt_t));
            *pSymEnt = *(struct S_Elf64_SymEnt_t*)(pDynsymData + sizeof(struct S_Elf64_SymEnt_t)*i);
            if(1)
            {
                xlog_info("         \e[1m%03d: %16llx %5llx  %02x      %02x    %02x       %04x %04x \e[0m\n", i, 
                                            pSymEnt->st_value, 
                                            pSymEnt->st_size, 
                                            (ELF64_ST_TYPE(pSymEnt->st_info)), 
                                            (ELF64_ST_BIND(pSymEnt->st_info)), 
                                            (ELF64_ST_VISIBILITY(pSymEnt->st_other)), 
                                            pSymEnt->st_shndx,
                                            pSymEnt->st_name
                        );
            }
            
            *(ppSymEnt+i) = pSymEnt;
        }
    }while(0);
    
    return 0;
}

//测试输出，指定地址的数据以指针的方式显示
void DumpPtr2Str(unsigned char* pDataStart, unsigned int iCnt, unsigned int iPtrMaxCnt)
{
    xlog_info("      ===========================================================\n");
    
    for (unsigned int i=0,j=0; i<iPtrMaxCnt && j<iCnt; i++)
    {
        while (*(char*)pDataStart == '\0')
        {
            j++;
            pDataStart++;
        }

        xlog_info("      >> ptr[%03d]=%016p; str={\"%s\"};\n", i, pDataStart, (char*)pDataStart);

        while (*(char*)pDataStart != '\0')
        {
            j++;
            pDataStart++;
        }
    }
    
    xlog_info("      ===========================================================\n");
    xlog_info("\n");

    return;
}

int func_sect_dynstr             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    DumpPtr2Str(pData, iLen, 30);
    
    return 0;
}

//int func_sect_gnu_version      (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_gnu_version_r    (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_rela_dyn         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_rela_plt         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_init             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_plt              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_plt_got          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_text             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_fini             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_rodata           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_eh_frame_hdr     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_eh_frame         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_init_array       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_fini_array       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_dynamic          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_got              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_got_plt          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_data             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_bss              (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_comment          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_debug_aranges    (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_debug_info       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_debug_abbrev     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_debug_line       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}

int func_sect_debug_str          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    DumpPtr2Str(pData, iLen, 500);
    
    return 0;
}

//int func_sect_symtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}

int func_sect_strtab             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    DumpPtr2Str(pData, iLen, 500);
    
    return 0;
}

int func_sect_shstrtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    DumpPtr2Str(pData, iLen, 100);
    
    return 0;
}

#endif

struct S_Elf64_SectFunc_t
{
    //int          i_index;
    char*          pstr_name;
    int (*pfunc_process)(int, char*, unsigned char*, int, struct S_ELF64_SectHeader_t*);
};

struct S_Elf64_SectFunc_t sect_funcs[] = 
    {
        {NULL, NULL},
        {".interp"           , func_sect_interp           },
        {".note.gnu.prope"   , func_sect_note_gnu_prope   },
      //{".note.gnu.build"   , func_sect_note_gnu_build   },
        {".note.ABI-tag"     , func_sect_note_ABI_tag     },
        {".note.gnu.build-id", func_sect_note_gnu_build_id},
        {".gnu.hash"         , func_sect_gnu_hash         },
        {".dynsym"           , func_sect_dynsym           },
        {".dynstr"           , func_sect_dynstr           },
        {".gnu.version"      , func_sect_gnu_version      },
        {".gnu.version_r"    , func_sect_gnu_version_r    },
        {".rela.dyn"         , func_sect_rela_dyn         },
        {".rela.plt"         , func_sect_rela_plt         },
        {".init"             , func_sect_init             },
        {".plt"              , func_sect_plt              },
        {".plt.got"          , func_sect_plt_got          },
        {".text"             , func_sect_text             },
        {".fini"             , func_sect_fini             },
        {".rodata"           , func_sect_rodata           },
        {".eh_frame_hdr"     , func_sect_eh_frame_hdr     },
        {".eh_frame"         , func_sect_eh_frame         },
        {".init_array"       , func_sect_init_array       },
        {".fini_array"       , func_sect_fini_array       },
        {".dynamic"          , func_sect_dynamic          },
        {".got"              , func_sect_got              },
        {".got.plt"          , func_sect_got_plt          },
        {".data"             , func_sect_data             },
        {".bss"              , func_sect_bss              },
        {".comment"          , func_sect_comment          },
        {".debug_aranges"    , func_sect_debug_aranges    },
        {".debug_info"       , func_sect_debug_info       },
        {".debug_abbrev"     , func_sect_debug_abbrev     },
        {".debug_line"       , func_sect_debug_line       },
        {".debug_str"        , func_sect_debug_str        },
        {".symtab"           , func_sect_symtab           },
        {".strtab"           , func_sect_strtab           },
        {".shstrtab"         , func_sect_shstrtab         },
        {NULL, NULL}
    };

int func_process(int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    xlog_info("      >>> {idx=%d, name=\"%s\", pData=%p, iLen=%d, pSectHeader=%p}.", idx, name, pData, iLen, pSectHeader);
    xlog_info("\n");
    
    return 0;
}

void parse_elf64_sect_body(int idx, unsigned char* pSectName, unsigned char* pSectData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("  >> func{%s:(%05d)} is call. \n      \e[1m{idx=%02d,sect_name=\"%s\",pSectData=%p,iLen=0x%x}\e[0m\n", 
                        __func__, __LINE__, idx, pSectName, pSectData, iLen);
    
    char* pName = (char*)pSectName;
    
    int (*pfunc_process)(int, char*, unsigned char*, int, struct S_ELF64_SectHeader_t*);
    
    pfunc_process = func_process;
    
    for(int i = 0;i<(sizeof(sect_funcs)/sizeof(struct S_Elf64_SectFunc_t)); i++)
    {
    
        if(pName==NULL || sect_funcs[i].pstr_name==NULL)
        {
            continue;
        }
        
        if(strcmp(pName, sect_funcs[i].pstr_name) == 0)
        {
            pfunc_process = sect_funcs[i].pfunc_process;
            break;
        }
    }
    
    pfunc_process(idx, (char*)pName, pSectData, iLen, pSectHeader);
    
    xlog_info("\n");
    
    return ;
}

void parse_elf64_sect_bodys(struct S_ELF64_ELFHeader_t* pElfHeader, struct S_ELF64_SectHeader_t** ppSectHeaders, 
                unsigned char* pSectNames, unsigned char* pElfData)
{
    xlog_info("  >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    for(int i=0; i<pElfHeader->e_shnum; i++)
    {
        parse_elf64_sect_body(i, 
                            pSectNames+ppSectHeaders[i]->sh_name, 
                            pElfData+ppSectHeaders[i]->sh_offset, 
                            ppSectHeaders[i]->sh_size, 
                            ppSectHeaders[i]);
    }
    
    return ;
}

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
    //=====================================================
    //e_shstrndx String Table Index,
    //在节区表中有一个存储各节区名称的节区(通常是最后一个),
    //这里表示名称表在第几个节区。

    //取得节区名称表对应的节头数据；
    struct S_ELF64_SectHeader_t* pSect_ShStrTab_Header = 
               (struct S_ELF64_SectHeader_t*)((pElfData+pElfHeader->e_shoff) + pElfHeader->e_shentsize*pElfHeader->e_shstrndx);
    //                                        |<-sect header start   addr->|  |<-每sect header size->| |<-    偏移单元个数 ->|
    
    PrtSectHeader(pElfHeader->e_shstrndx, pSect_ShStrTab_Header);

    //分析节区名称数据；
    unsigned char* pSectNames = pElfData+pSect_ShStrTab_Header->sh_offset;
    
    xlog_hexdump(pSectNames, pSect_ShStrTab_Header->sh_size);

    //分析节头(section header)数据
    p_elf64_obj->ppSectHeaders = parse_elf64_sect_headers(pElfHeader, (unsigned char*)(pElfData+pElfHeader->e_shoff), pSectNames);
    for(int i=0; i<p_elf64_obj->pElfHeader->e_shnum; i++)
    {
        p_elf64_obj->SectHeaderObjs[i] = *p_elf64_obj->ppSectHeaders[i];
    }
    
    //分析程序头(program header)数据
    p_elf64_obj->ppProgHeaders = parse_elf64_prog_headers(pElfHeader, (unsigned char*)(pElfData+pElfHeader->e_phoff), pSectNames);
    for(int i=0; i<pElfHeader->e_phnum; i++)
    {
        //xlog_info("  >> func{%s:(%05d)} is call. {ppProgHeaders[%02d]=%p}.\n", __func__, __LINE__, i, p_elf64_obj->ppProgHeaders[i]);
        p_elf64_obj->ProgHeaderObjs[i] = *p_elf64_obj->ppProgHeaders[i];
    }
    
    //分析节数据组
    parse_elf64_sect_bodys(p_elf64_obj->pElfHeader, p_elf64_obj->ppSectHeaders, pSectNames, pElfData);
    
    xlog_info("  >> build_elf64_obj() exit;\n");
    return p_elf64_obj;
}

//=======================================================
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
//=======================================================

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

// gcc -std=c11 -g -Wall -O0 -DXLOG_PTHREAD_T=1 myreadelf-0.1.00.c -o myapp -pthread
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
        else
        {
            xlog_hexdump((uint8_t*)p_elf64_data, 16*5+5);
        }
        
        //基于从文件中读取的ELF数据，构建ELF对象；
        struct s_elf64_obj_t* p_elf64_obj = build_elf64_obj(p_elf64_data, i_elf64_len);
        
        //xlog_hexdump((uint8_t*)p_elf64_obj, 16*40+5);
        
        //printf_elf64_obj(p_elf64_obj);
        //
        //=============================================
        free(p_elf64_obj->ppSectHeaders);
        free(p_elf64_obj->ppProgHeaders);
        free(p_elf64_obj);
        free(p_elf64_data);
    }while(0);
    
    xlog_info("  >> the app exit.\n");
    xlog_uninit();
    return 0;
}

#if 0

#endif
