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

struct S_Elf64_Rel_t
{
    Elf64_Addr      r_offset;
    Elf64_Xword     r_info;
};

struct S_Elf64_Rela_t
{
    Elf64_Addr      r_offset;
    Elf64_Xword     r_info;
    Elf64_Sxword    r_addend;
};

#define ELF64_R_SYM(i)    ((i)>>32)
#define ELF64_R_TYPE(i)   ((i)&0xffffffffL)
#define ELF64_R_INFO(s,t) (((s)<<32)+((t)&0xffffffffL))

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
//int func_sect_rela_dyn       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
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

int func_sect_rela_dyn           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    do
    {
        struct S_Elf64_Rela_t** ppRelaEnt = (struct S_Elf64_Rela_t**)malloc(sizeof(struct S_Elf64_Rela_t*)*(pSectHeader->sh_size/pSectHeader->sh_entsize));
        unsigned char* pSecReladynBody = pData;
        
        xlog_info("    Relocation section '.rela.dyn' at offset ?? contains %d entries:\n", (int)(pSectHeader->sh_size/pSectHeader->sh_entsize));
        xlog_info("      Idx  Offset          Info         Type      Sym. Value Sym. Name + Addend\n");
        for(int i=0; i<(pSectHeader->sh_size/pSectHeader->sh_entsize); i++)
        {
            struct S_Elf64_Rela_t* pRelaEnt = (struct S_Elf64_Rela_t*)(pSecReladynBody + sizeof(struct S_Elf64_Rela_t)*i);
            if(1)
            {
                xlog_info("      [%02d]\e[1m %012llx %012llx 0x%08llx      test    sym.name  + %lld\e[0m\n", i, 
                                            pRelaEnt->r_offset, 
                                            pRelaEnt->r_info,
                                            (ELF64_R_TYPE(pRelaEnt->r_info)),
                                            pRelaEnt->r_addend );
            }
            *(ppRelaEnt+i) = pRelaEnt;
        }
    }while(0);
    
    return 0;
}

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
xadmin@hw:~/xwks.git.1/myreadelf-c11$ gcc -std=c11 -g -Wall -O0  myreadelf-0.1.07.c -o myapp
xadmin@hw:~/xwks.git.1/myreadelf-c11$ ./myapp
################################################{}##################################################
  #====>>>>
  >> func{before_main_func:(01081)@(myreadelf-0.1.07.c)} is call .
  #====>>>>
  >> func{my_init01:(01102)@(myreadelf-0.1.07.c)} is call .
  #====>>>>
  >> func{my_init02:(01114)@(myreadelf-0.1.07.c)} is call .
  #====>>>>
  >> func{my_init03:(01126)@(myreadelf-0.1.07.c)} is call .
  >> the app starting ... ...

0x007ffd7df17d58|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|60 96 f1 7d fd 7f 00 00  00 00 00 00 00 00 00 00|`..}............|
      0x00000010|68 96 f1 7d fd 7f 00 00  78 96 f1 7d fd 7f 00 00|h..}....x..}....|
      0x00000020|90 96 f1 7d fd 7f 00 00  a7 96 f1 7d fd 7f 00 00|...}.......}....|
      0x00000030|bb 96 f1 7d fd 7f 00 00  d3 96 f1 7d fd 7f 00 00|...}.......}....|
      0x00000040|fd 96 f1 7d fd 7f 00 00  0c 97 f1 7d fd 7f 00 00|...}.......}....|
      0x00000050|21 97 f1 7d fd 7f 00 00  30 97 f1 ** ** ** ** **|!..}....0..*****|
      =============================================================================


0x007ffd7df19660|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2e 2f 6d 79 61 70 70 00  53 48 45 4c 4c 3d 2f 62|./myapp.SHELL=/b|
      0x00000010|69 6e 2f 62 61 73 68 00  4c 41 4e 47 55 41 47 45|in/bash.LANGUAGE|
      0x00000020|3d 7a 68 5f 43 4e 3a 65  6e 5f 55 53 3a 65 6e 00|=zh_CN:en_US:en.|
      0x00000030|4c 43 5f 41 44 44 52 45  53 53 3d 7a 68 5f 43 4e|LC_ADDRESS=zh_CN|
      0x00000040|2e 55 54 46 2d 38 00 4c  43 5f 4e 41 4d 45 3d 7a|.UTF-8.LC_NAME=z|
      0x00000050|68 5f 43 4e 2e 55 54 46  2d 38 00 ** ** ** ** **|h_CN.UTF-8.*****|
      =============================================================================

  >> func:parse_args(1, 0x7ffd7df17d58) is called. (@file:myreadelf-0.1.07.c,line:1140).

    >>> argv[00](addr=0x7ffd7df19660) = {"./myapp"}.

  >> func:parse_args() is called. @line:(1147).
  >> get_elf64_data("./myapp", len) entry;

0x005611f5c0a890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  00 22 00 00 00 00 00 00|..>......"......|
      0x00000020|40 00 00 00 00 00 00 00  f0 eb 00 00 00 00 00 00|@...............|
      0x00000030|00 00 00 00 40 00 38 00  0d 00 40 00 24 00 23 00|....@.8...@.$.#.|
      0x00000040|06 00 00 00 04 00 00 00  40 00 00 00 00 00 00 00|........@.......|
      0x00000050|40 00 00 00 00 ** ** **  ** ** ** ** ** ** ** **|@....***********|
      =============================================================================

  >> build_elf64_obj(0x5611f5c0a890, 62704) entry;
  >> func{parse_elf64_elf_header:(00401)} is call.{pElfData=0x5611f5c0a890}.
        struct S_ELF64_ELFHeader_t pElfHeader = {0x5611f5c0a890} 
        {
                 unsigned char e_ident[16] = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00};
                 Elf64_Half    e_type      = 0x0003;
                 Elf64_Half    e_machine   = 0x003e;
                 Elf64_Word    e_version   = 0x1  ;
                 Elf64_Addr    e_entry     = 0x2200;
                 Elf64_Off     e_phoff     = 0x40;
                 Elf64_Off     e_shoff     = 0xebf0;
                 Elf64_Word    e_flags     = 0x0  ;
                 Elf64_Half    e_ehsize    = 0x0040;
                 Elf64_Half    e_phentsize = 0x0038;
                 Elf64_Half    e_phnum     = 0x000d;
                 Elf64_Half    e_shentsize = 0x0040;
                 Elf64_Half    e_shnum     = 0x0024;
                 Elf64_Half    e_shstrndx  = 0x0023;
        };
        No.[35]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x5611f5c19d40
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xea8f;
             Elf64_Xword   sh_size      = 0x15a;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x005611f5c1931f|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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

  >> func{parse_elf64_sect_headers:(00482)} is call .
  >> func{parse_elf64_sect_headers:(00499)} is call .


----------------------------------------------------------------
Section Headers:  
  [Nr] Name            Type      Address     Offset  Size    EntSize Flags  Link   Info   Align
  [00]                 00000000  0000000000  000000  000000  000000  0x0000 0x0000 0x0000 0x0000
  [01] .interp         00000001  0000000318  000792  000028  000000  0x0002 0x0000 0x0000 0x0001
  [02] .note.gnu.prope 00000007  0000000338  000824  000032  000000  0x0002 0x0000 0x0000 0x0008
  [03] .note.gnu.build 00000007  0000000358  000856  000036  000000  0x0002 0x0000 0x0000 0x0004
  [04] .note.ABI-tag   00000007  000000037c  000892  000032  000000  0x0002 0x0000 0x0000 0x0004
  [05] .gnu.hash       6ffffff6  00000003a0  000928  000040  000000  0x0002 0x0006 0x0000 0x0008
  [06] .dynsym         0000000b  00000003c8  000968  000504  000024  0x0002 0x0007 0x0001 0x0008
  [07] .dynstr         00000003  00000005c0  001472  000265  000000  0x0002 0x0000 0x0000 0x0001
  [08] .gnu.version    6fffffff  00000006ca  001738  000042  000002  0x0002 0x0006 0x0000 0x0002
  [09] .gnu.version_r  6ffffffe  00000006f8  001784  000064  000000  0x0002 0x0007 0x0001 0x0008
  [10] .rela.dyn       00000004  0000000738  001848  002088  000024  0x0002 0x0006 0x0000 0x0008
  [11] .rela.plt       00000004  0000000f60  003936  000336  000024  0x0042 0x0006 0x0018 0x0008
  [12] .init           00000001  0000002000  008192  000027  000000  0x0006 0x0000 0x0000 0x0004
  [13] .plt            00000001  0000002020  008224  000240  000016  0x0006 0x0000 0x0000 0x0010
  [14] .plt.got        00000001  0000002110  008464  000016  000016  0x0006 0x0000 0x0000 0x0010
  [15] .plt.sec        00000001  0000002120  008480  000224  000016  0x0006 0x0000 0x0000 0x0010
  [16] .text           00000001  0000002200  008704  011492  000000  0x0006 0x0000 0x0000 0x0010
  [17] .fini           00000001  0000004ee4  020196  000013  000000  0x0006 0x0000 0x0000 0x0004
  [18] .rodata         00000001  0000005000  020480  006283  000000  0x0002 0x0000 0x0000 0x0010
  [19] .eh_frame_hdr   00000001  000000688c  026764  000604  000000  0x0002 0x0000 0x0000 0x0004
  [20] .eh_frame       00000001  0000006ae8  027368  002408  000000  0x0002 0x0000 0x0000 0x0008
  [21] .init_array     0000000e  0000008d10  032016  000040  000008  0x0003 0x0000 0x0000 0x0008
  [22] .fini_array     0000000f  0000008d38  032056  000040  000008  0x0003 0x0000 0x0000 0x0008
  [23] .dynamic        00000006  0000008d60  032096  000496  000016  0x0003 0x0007 0x0000 0x0008
  [24] .got            00000001  0000008f50  032592  000176  000008  0x0003 0x0000 0x0000 0x0008
  [25] .data           00000001  0000009000  032768  000624  000000  0x0003 0x0000 0x0000 0x0020
  [26] .bss            00000008  0000009270  033392  000016  000000  0x0003 0x0000 0x0000 0x0008
  [27] .comment        00000001  0000000000  033392  000043  000001  0x0030 0x0000 0x0000 0x0001
  [28] .debug_aranges  00000001  0000000000  033435  000048  000000  0x0000 0x0000 0x0000 0x0001
  [29] .debug_info     00000001  0000000000  033483  011265  000000  0x0000 0x0000 0x0000 0x0001
  [30] .debug_abbrev   00000001  0000000000  044748  000670  000000  0x0000 0x0000 0x0000 0x0001
  [31] .debug_line     00000001  0000000000  045418  003531  000000  0x0000 0x0000 0x0000 0x0001
  [32] .debug_str      00000001  0000000000  048949  003418  000001  0x0030 0x0000 0x0000 0x0001
  [33] .symtab         00000002  0000000000  052368  004944  000024  0x0000 0x0022 0x0069 0x0008
  [34] .strtab         00000003  0000000000  057312  002735  000000  0x0000 0x0000 0x0000 0x0001
  [35] .shstrtab       00000003  0000000000  060047  000346  000000  0x0000 0x0000 0x0000 0x0001
----------------------------------------------------------------
  >> func{parse_elf64_sect_headers:(00522)} is call .
  >> func{parse_elf64_prog_headers:(00557)} is call .

    ----------------------------------------------------------------
    Program Headers:
    [No] Type     Offset   VirtAddr   PhysAddr   FileSiz  MemSiz   Flags    Align
    [00] 00000006 00000040 0000000040 0000000040 0x0002d8 0x0002d8 0x000004 0x000008
    [01] 00000003 00000318 0000000318 0000000318 0x00001c 0x00001c 0x000004 0x000001
    [02] 00000001 00000000 0000000000 0000000000 0x0010b0 0x0010b0 0x000004 0x001000
    [03] 00000001 00002000 0000002000 0000002000 0x002ef1 0x002ef1 0x000005 0x001000
    [04] 00000001 00005000 0000005000 0000005000 0x002450 0x002450 0x000004 0x001000
    [05] 00000001 00007d10 0000008d10 0000008d10 0x000560 0x000570 0x000006 0x001000
    [06] 00000002 00007d60 0000008d60 0000008d60 0x0001f0 0x0001f0 0x000006 0x000008
    [07] 00000004 00000338 0000000338 0000000338 0x000020 0x000020 0x000004 0x000008
    [08] 00000004 00000358 0000000358 0000000358 0x000044 0x000044 0x000004 0x000004
    [09] 6474e553 00000338 0000000338 0000000338 0x000020 0x000020 0x000004 0x000008
    [10] 6474e550 0000688c 000000688c 000000688c 0x00025c 0x00025c 0x000004 0x000004
    [11] 6474e551 00000000 0000000000 0000000000 0x000000 0x000000 0x000006 0x000010
    [12] 6474e552 00007d10 0000008d10 0000008d10 0x0002f0 0x0002f0 0x000004 0x000001
    ----------------------------------------------------------------
  >> func{parse_elf64_sect_bodys:(00987)} is call .
  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=00,sect_name="",pSectData=0x5611f5c0a890,iLen=0x0}
    >> func{func_process:(00944)} is call .
      >>> {idx=0, name="", pData=0x5611f5c0a890, iLen=0, pSectHeader=0x5611f5c19480}.

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=01,sect_name=".interp",pSectData=0x5611f5c0aba8,iLen=0x1c}
    >> func{func_sect_interp:(00683)} is call .
        No.[01]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x5611f5c194c0
        {
             Elf64_Word    sh_name      = 0x1b;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x318;
             Elf64_Off     sh_offset    = 0x318;
             Elf64_Xword   sh_size      = 0x1c;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x005611f5c0aba8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2f 6c 69 62 36 34 2f 6c  64 2d 6c 69 6e 75 78 2d|/lib64/ld-linux-|
      0x00000010|78 38 36 2d 36 34 2e 73  6f 2e 32 00 ** ** ** **|x86-64.so.2.****|
      =============================================================================

      ------------------------------------------------------------
      /lib64/ld-linux-x86-64.so.2
      ------------------------------------------------------------

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=02,sect_name=".note.gnu.property",pSectData=0x5611f5c0abc8,iLen=0x20}
    >> func{func_process:(00944)} is call .
      >>> {idx=2, name=".note.gnu.property", pData=0x5611f5c0abc8, iLen=32, pSectHeader=0x5611f5c19500}.

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=03,sect_name=".note.gnu.build-id",pSectData=0x5611f5c0abe8,iLen=0x24}
    >> func{func_sect_note_gnu_build_id:(00645)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=04,sect_name=".note.ABI-tag",pSectData=0x5611f5c0ac0c,iLen=0x20}
    >> func{func_sect_note_ABI_tag:(00644)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=05,sect_name=".gnu.hash",pSectData=0x5611f5c0ac30,iLen=0x28}
    >> func{func_sect_gnu_hash:(00646)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=06,sect_name=".dynsym",pSectData=0x5611f5c0ac58,iLen=0x1f8}
    >> func{func_sect_dynsym:(00714)} is call .
        No.[06]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x5611f5c19600
        {
             Elf64_Word    sh_name      = 0x61;
             Elf64_Word    sh_type      = 0xb;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x3c8;
             Elf64_Off     sh_offset    = 0x3c8;
             Elf64_Xword   sh_size      = 0x1f8;
             Elf64_Word    sh_link      = 0x7;
             Elf64_Word    sh_info      = 0x1;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x18;
        }

0x005611f5c0ac58|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000010|00 00 00 00 00 00 00 00  97 00 00 00 12 00 00 00|................|
      0x00000020|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000030|c4 00 00 00 20 00 00 00  00 00 00 00 00 00 00 00|.... ...........|
      0x00000040|00 00 00 00 00 00 00 00  69 00 00 00 12 00 00 00|........i.......|
      0x00000050|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000060|45 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|E...............|
      0x00000070|00 00 00 00 00 00 00 00  18 00 00 00 12 00 00 00|................|
      0x00000080|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000090|4d 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|M...............|
      0x000000a0|00 00 00 00 00 00 00 00  29 00 00 00 12 00 00 00|........).......|
      0x000000b0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000c0|85 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000d0|00 00 00 00 00 00 00 00  37 00 00 00 12 00 00 00|........7.......|
      0x000000e0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000f0|7e 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|~...............|
      0x00000100|00 00 00 00 00 00 00 00  e0 00 00 00 20 00 00 00|............ ...|
      0x00000110|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000120|9c 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000130|00 00 00 00 00 00 00 00  54 00 00 00 12 00 00 00|........T.......|
      0x00000140|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000150|0b 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000160|00 00 00 00 00 00 00 00  4c 00 00 00 12 00 00 00|........L.......|
      0x00000170|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000180|12 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000190|00 00 00 00 00 00 00 00  ef 00 00 00 20 00 00 00|............ ...|
      0x000001a0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000001b0|5b 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|[...............|
      0x000001c0|00 00 00 00 00 00 00 00  3e 00 00 00 11 00 1a 00|........>.......|
      0x000001d0|70 92 00 00 00 00 00 00  08 00 00 00 00 00 00 00|p...............|
      0x000001e0|6f 00 00 00 22 00 00 00  00 00 00 00 00 00 00 00|o..."...........|
      0x000001f0|00 00 00 00 00 00 00 00  ** ** ** ** ** ** ** **|........********|
      =============================================================================

      Symbol table '.dynsym' contains 21 entries:
         Num:    Value          Size Type    Bind   Vis      Ndx  Name  NameStr
         000:                0     0  00      00    00       0000 0000 
         001:                0     0  02      01    00       0000 0097 
         002:                0     0  00      02    00       0000 00c4 
         003:                0     0  02      01    00       0000 0069 
         004:                0     0  02      01    00       0000 0045 
         005:                0     0  02      01    00       0000 0018 
         006:                0     0  02      01    00       0000 004d 
         007:                0     0  02      01    00       0000 0029 
         008:                0     0  02      01    00       0000 0085 
         009:                0     0  02      01    00       0000 0037 
         010:                0     0  02      01    00       0000 007e 
         011:                0     0  00      02    00       0000 00e0 
         012:                0     0  02      01    00       0000 009c 
         013:                0     0  02      01    00       0000 0054 
         014:                0     0  02      01    00       0000 000b 
         015:                0     0  02      01    00       0000 004c 
         016:                0     0  02      01    00       0000 0012 
         017:                0     0  00      02    00       0000 00ef 
         018:                0     0  02      01    00       0000 005b 
         019:             9270     8  01      01    00       001a 003e 
         020:                0     0  02      02    00       0000 006f 

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=07,sect_name=".dynstr",pSectData=0x5611f5c0ae50,iLen=0x109}
    >> func{func_sect_dynstr:(00781)} is call .
        No.[07]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x5611f5c19640
        {
             Elf64_Word    sh_name      = 0x69;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x5c0;
             Elf64_Off     sh_offset    = 0x5c0;
             Elf64_Xword   sh_size      = 0x109;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x005611f5c0ae50|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 6c 69 62 63 2e 73 6f  2e 36 00 66 66 6c 75 73|.libc.so.6.fflus|
      0x00000010|68 00 66 6f 70 65 6e 00  5f 5f 73 74 61 63 6b 5f|h.fopen.__stack_|
      0x00000020|63 68 6b 5f 66 61 69 6c  00 5f 5f 61 73 73 65 72|chk_fail.__asser|
      0x00000030|74 5f 66 61 69 6c 00 63  61 6c 6c 6f 63 00 73 74|t_fail.calloc.st|
      0x00000040|64 6f 75 74 00 66 63 6c  6f 73 65 00 76 70 72 69|dout.fclose.vpri|
      0x00000050|6e 74 66 00 6d 61 6c 6c  6f 63 00 5f 5f 63 74 79|ntf.malloc.__cty|
      0x00000060|70 65 5f 62 5f 6c 6f 63  00 66 72 65 61 64 00 5f|pe_b_loc.fread._|
      0x00000070|5f 63 78 61 5f 66 69 6e  61 6c 69 7a 65 00 73 74|_cxa_finalize.st|
      0x00000080|72 63 6d 70 00 5f 5f 6c  69 62 63 5f 73 74 61 72|rcmp.__libc_star|
      0x00000090|74 5f 6d 61 69 6e 00 66  72 65 65 00 5f 5f 78 73|t_main.free.__xs|
      0x000000a0|74 61 74 00 47 4c 49 42  43 5f 32 2e 33 00 47 4c|tat.GLIBC_2.3.GL|
      0x000000b0|49 42 43 5f 32 2e 34 00  47 4c 49 42 43 5f 32 2e|IBC_2.4.GLIBC_2.|
      0x000000c0|32 2e 35 00 5f 49 54 4d  5f 64 65 72 65 67 69 73|2.5._ITM_deregis|
      0x000000d0|74 65 72 54 4d 43 6c 6f  6e 65 54 61 62 6c 65 00|terTMCloneTable.|
      0x000000e0|5f 5f 67 6d 6f 6e 5f 73  74 61 72 74 5f 5f 00 5f|__gmon_start__._|
      0x000000f0|49 54 4d 5f 72 65 67 69  73 74 65 72 54 4d 43 6c|ITM_registerTMCl|
      0x00000100|6f 6e 65 54 61 62 6c 65  00 ** ** ** ** ** ** **|oneTable.*******|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x005611f5c0ae51; str={"libc.so.6"};
      >> ptr[001]=0x005611f5c0ae5b; str={"fflush"};
      >> ptr[002]=0x005611f5c0ae62; str={"fopen"};
      >> ptr[003]=0x005611f5c0ae68; str={"__stack_chk_fail"};
      >> ptr[004]=0x005611f5c0ae79; str={"__assert_fail"};
      >> ptr[005]=0x005611f5c0ae87; str={"calloc"};
      >> ptr[006]=0x005611f5c0ae8e; str={"stdout"};
      >> ptr[007]=0x005611f5c0ae95; str={"fclose"};
      >> ptr[008]=0x005611f5c0ae9c; str={"vprintf"};
      >> ptr[009]=0x005611f5c0aea4; str={"malloc"};
      >> ptr[010]=0x005611f5c0aeab; str={"__ctype_b_loc"};
      >> ptr[011]=0x005611f5c0aeb9; str={"fread"};
      >> ptr[012]=0x005611f5c0aebf; str={"__cxa_finalize"};
      >> ptr[013]=0x005611f5c0aece; str={"strcmp"};
      >> ptr[014]=0x005611f5c0aed5; str={"__libc_start_main"};
      >> ptr[015]=0x005611f5c0aee7; str={"free"};
      >> ptr[016]=0x005611f5c0aeec; str={"__xstat"};
      >> ptr[017]=0x005611f5c0aef4; str={"GLIBC_2.3"};
      >> ptr[018]=0x005611f5c0aefe; str={"GLIBC_2.4"};
      >> ptr[019]=0x005611f5c0af08; str={"GLIBC_2.2.5"};
      >> ptr[020]=0x005611f5c0af14; str={"_ITM_deregisterTMCloneTable"};
      >> ptr[021]=0x005611f5c0af30; str={"__gmon_start__"};
      >> ptr[022]=0x005611f5c0af3f; str={"_ITM_registerTMCloneTable"};
      >> ptr[023]=0x005611f5c0af5c; str={""};
      ===========================================================


  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=08,sect_name=".gnu.version",pSectData=0x5611f5c0af5a,iLen=0x2a}
    >> func{func_sect_gnu_version:(00649)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=09,sect_name=".gnu.version_r",pSectData=0x5611f5c0af88,iLen=0x40}
    >> func{func_sect_gnu_version_r:(00650)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=10,sect_name=".rela.dyn",pSectData=0x5611f5c0afc8,iLen=0x828}
    >> func{func_sect_rela_dyn:(00797)} is call .
        No.[10]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x5611f5c19700
        {
             Elf64_Word    sh_name      = 0x8d;
             Elf64_Word    sh_type      = 0x4;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x738;
             Elf64_Off     sh_offset    = 0x738;
             Elf64_Xword   sh_size      = 0x828;
             Elf64_Word    sh_link      = 0x6;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x18;
        }

0x005611f5c0afc8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|10 8d 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000010|e0 22 00 00 00 00 00 00  18 8d 00 00 00 00 00 00|."..............|
      0x00000020|08 00 00 00 00 00 00 00  f3 49 00 00 00 00 00 00|.........I......|
      0x00000030|20 8d 00 00 00 00 00 00  08 00 00 00 00 00 00 00| ...............|
      0x00000040|84 4a 00 00 00 00 00 00  28 8d 00 00 00 00 00 00|.J......(.......|
      0x00000050|08 00 00 00 00 00 00 00  04 4b 00 00 00 00 00 00|.........K......|
      0x00000060|30 8d 00 00 00 00 00 00  08 00 00 00 00 00 00 00|0...............|
      0x00000070|84 4b 00 00 00 00 00 00  38 8d 00 00 00 00 00 00|.K......8.......|
      0x00000080|08 00 00 00 00 00 00 00  a0 22 00 00 00 00 00 00|........."......|
      0x00000090|40 8d 00 00 00 00 00 00  08 00 00 00 00 00 00 00|@...............|
      0x000000a0|44 4a 00 00 00 00 00 00  48 8d 00 00 00 00 00 00|DJ......H.......|
      0x000000b0|08 00 00 00 00 00 00 00  c4 4a 00 00 00 00 00 00|.........J......|
      0x000000c0|50 8d 00 00 00 00 00 00  08 00 00 00 00 00 00 00|P...............|
      0x000000d0|44 4b 00 00 00 00 00 00  58 8d 00 00 00 00 00 00|DK......X.......|
      0x000000e0|08 00 00 00 00 00 00 00  c4 4b 00 00 00 00 00 00|.........K......|
      0x000000f0|08 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000100|08 90 00 00 00 00 00 00  30 90 00 00 00 00 00 00|........0.......|
      0x00000110|08 00 00 00 00 00 00 00  cd 5e 00 00 00 00 00 00|.........^......|
      0x00000120|38 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|8...............|
      0x00000130|56 3d 00 00 00 00 00 00  40 90 00 00 00 00 00 00|V=......@.......|
      0x00000140|08 00 00 00 00 00 00 00  d5 5e 00 00 00 00 00 00|.........^......|
      0x00000150|48 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|H...............|
      0x00000160|dc 35 00 00 00 00 00 00  50 90 00 00 00 00 00 00|.5......P.......|
      0x00000170|08 00 00 00 00 00 00 00  e5 5e 00 00 00 00 00 00|.........^......|
      0x00000180|58 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|X...............|
      0x00000190|60 36 00 00 00 00 00 00  60 90 00 00 00 00 00 00|`6......`.......|
      0x000001a0|08 00 00 00 00 00 00 00  f3 5e 00 00 00 00 00 00|.........^......|
      0x000001b0|68 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|h...............|
      0x000001c0|a2 36 00 00 00 00 00 00  70 90 00 00 00 00 00 00|.6......p.......|
      0x000001d0|08 00 00 00 00 00 00 00  06 5f 00 00 00 00 00 00|........._......|
      0x000001e0|78 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|x...............|
      0x000001f0|e4 36 00 00 00 00 00 00  80 90 00 00 00 00 00 00|.6..............|
      0x00000200|08 00 00 00 00 00 00 00  10 5f 00 00 00 00 00 00|........._......|
      0x00000210|88 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000220|58 3e 00 00 00 00 00 00  90 90 00 00 00 00 00 00|X>..............|
      0x00000230|08 00 00 00 00 00 00 00  18 5f 00 00 00 00 00 00|........._......|
      0x00000240|98 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000250|f7 40 00 00 00 00 00 00  a0 90 00 00 00 00 00 00|.@..............|
      0x00000260|08 00 00 00 00 00 00 00  20 5f 00 00 00 00 00 00|........ _......|
      0x00000270|a8 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000280|26 37 00 00 00 00 00 00  b0 90 00 00 00 00 00 00|&7..............|
      0x00000290|08 00 00 00 00 00 00 00  2d 5f 00 00 00 00 00 00|........-_......|
      0x000002a0|b8 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000002b0|68 37 00 00 00 00 00 00  c0 90 00 00 00 00 00 00|h7..............|
      0x000002c0|08 00 00 00 00 00 00 00  3c 5f 00 00 00 00 00 00|........<_......|
      0x000002d0|c8 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000002e0|75 41 00 00 00 00 00 00  d0 90 00 00 00 00 00 00|uA..............|
      0x000002f0|08 00 00 00 00 00 00 00  46 5f 00 00 00 00 00 00|........F_......|
      0x00000300|d8 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000310|aa 37 00 00 00 00 00 00  e0 90 00 00 00 00 00 00|.7..............|
      0x00000320|08 00 00 00 00 00 00 00  50 5f 00 00 00 00 00 00|........P_......|
      0x00000330|e8 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000340|ec 37 00 00 00 00 00 00  f0 90 00 00 00 00 00 00|.7..............|
      0x00000350|08 00 00 00 00 00 00 00  56 5f 00 00 00 00 00 00|........V_......|
      0x00000360|f8 90 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000370|2e 38 00 00 00 00 00 00  00 91 00 00 00 00 00 00|.8..............|
      0x00000380|08 00 00 00 00 00 00 00  5b 5f 00 00 00 00 00 00|........[_......|
      0x00000390|08 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000003a0|70 38 00 00 00 00 00 00  10 91 00 00 00 00 00 00|p8..............|
      0x000003b0|08 00 00 00 00 00 00 00  64 5f 00 00 00 00 00 00|........d_......|
      0x000003c0|18 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000003d0|b2 38 00 00 00 00 00 00  20 91 00 00 00 00 00 00|.8...... .......|
      0x000003e0|08 00 00 00 00 00 00 00  6a 5f 00 00 00 00 00 00|........j_......|
      0x000003f0|28 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|(...............|
      0x00000400|f4 38 00 00 00 00 00 00  30 91 00 00 00 00 00 00|.8......0.......|
      0x00000410|08 00 00 00 00 00 00 00  70 5f 00 00 00 00 00 00|........p_......|
      0x00000420|38 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|8...............|
      0x00000430|36 39 00 00 00 00 00 00  40 91 00 00 00 00 00 00|69......@.......|
      0x00000440|08 00 00 00 00 00 00 00  78 5f 00 00 00 00 00 00|........x_......|
      0x00000450|48 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|H...............|
      0x00000460|78 39 00 00 00 00 00 00  50 91 00 00 00 00 00 00|x9......P.......|
      0x00000470|08 00 00 00 00 00 00 00  86 5f 00 00 00 00 00 00|........._......|
      0x00000480|58 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|X...............|
      0x00000490|ba 39 00 00 00 00 00 00  60 91 00 00 00 00 00 00|.9......`.......|
      0x000004a0|08 00 00 00 00 00 00 00  90 5f 00 00 00 00 00 00|........._......|
      0x000004b0|68 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|h...............|
      0x000004c0|fc 39 00 00 00 00 00 00  70 91 00 00 00 00 00 00|.9......p.......|
      0x000004d0|08 00 00 00 00 00 00 00  9c 5f 00 00 00 00 00 00|........._......|
      0x000004e0|78 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|x...............|
      0x000004f0|3e 3a 00 00 00 00 00 00  80 91 00 00 00 00 00 00|>:..............|
      0x00000500|08 00 00 00 00 00 00 00  a8 5f 00 00 00 00 00 00|........._......|
      0x00000510|88 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000520|80 3a 00 00 00 00 00 00  90 91 00 00 00 00 00 00|.:..............|
      0x00000530|08 00 00 00 00 00 00 00  b1 5f 00 00 00 00 00 00|........._......|
      0x00000540|98 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000550|c2 3a 00 00 00 00 00 00  a0 91 00 00 00 00 00 00|.:..............|
      0x00000560|08 00 00 00 00 00 00 00  b6 5f 00 00 00 00 00 00|........._......|
      0x00000570|a8 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000580|04 3b 00 00 00 00 00 00  b0 91 00 00 00 00 00 00|.;..............|
      0x00000590|08 00 00 00 00 00 00 00  bf 5f 00 00 00 00 00 00|........._......|
      0x000005a0|b8 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000005b0|46 3b 00 00 00 00 00 00  c0 91 00 00 00 00 00 00|F;..............|
      0x000005c0|08 00 00 00 00 00 00 00  c5 5f 00 00 00 00 00 00|........._......|
      0x000005d0|c8 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000005e0|88 3b 00 00 00 00 00 00  d0 91 00 00 00 00 00 00|.;..............|
      0x000005f0|08 00 00 00 00 00 00 00  ca 5f 00 00 00 00 00 00|........._......|
      0x00000600|d8 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000610|ca 3b 00 00 00 00 00 00  e0 91 00 00 00 00 00 00|.;..............|
      0x00000620|08 00 00 00 00 00 00 00  d3 5f 00 00 00 00 00 00|........._......|
      0x00000630|e8 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000640|0c 3c 00 00 00 00 00 00  f0 91 00 00 00 00 00 00|.<..............|
      0x00000650|08 00 00 00 00 00 00 00  e2 5f 00 00 00 00 00 00|........._......|
      0x00000660|f8 91 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000670|4e 3c 00 00 00 00 00 00  00 92 00 00 00 00 00 00|N<..............|
      0x00000680|08 00 00 00 00 00 00 00  ee 5f 00 00 00 00 00 00|........._......|
      0x00000690|08 92 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000006a0|90 3c 00 00 00 00 00 00  10 92 00 00 00 00 00 00|.<..............|
      0x000006b0|08 00 00 00 00 00 00 00  fc 5f 00 00 00 00 00 00|........._......|
      0x000006c0|18 92 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000006d0|d2 3c 00 00 00 00 00 00  20 92 00 00 00 00 00 00|.<...... .......|
      0x000006e0|08 00 00 00 00 00 00 00  08 60 00 00 00 00 00 00|.........`......|
      0x000006f0|28 92 00 00 00 00 00 00  08 00 00 00 00 00 00 00|(...............|
      0x00000700|f6 42 00 00 00 00 00 00  30 92 00 00 00 00 00 00|.B......0.......|
      0x00000710|08 00 00 00 00 00 00 00  13 60 00 00 00 00 00 00|.........`......|
      0x00000720|38 92 00 00 00 00 00 00  08 00 00 00 00 00 00 00|8...............|
      0x00000730|14 3d 00 00 00 00 00 00  40 92 00 00 00 00 00 00|.=......@.......|
      0x00000740|08 00 00 00 00 00 00 00  1b 60 00 00 00 00 00 00|.........`......|
      0x00000750|48 92 00 00 00 00 00 00  08 00 00 00 00 00 00 00|H...............|
      0x00000760|74 43 00 00 00 00 00 00  50 92 00 00 00 00 00 00|tC......P.......|
      0x00000770|08 00 00 00 00 00 00 00  23 60 00 00 00 00 00 00|........#`......|
      0x00000780|58 92 00 00 00 00 00 00  08 00 00 00 00 00 00 00|X...............|
      0x00000790|f2 43 00 00 00 00 00 00  d8 8f 00 00 00 00 00 00|.C..............|
      0x000007a0|06 00 00 00 02 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000007b0|e0 8f 00 00 00 00 00 00  06 00 00 00 08 00 00 00|................|
      0x000007c0|00 00 00 00 00 00 00 00  e8 8f 00 00 00 00 00 00|................|
      0x000007d0|06 00 00 00 0b 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000007e0|f0 8f 00 00 00 00 00 00  06 00 00 00 11 00 00 00|................|
      0x000007f0|00 00 00 00 00 00 00 00  f8 8f 00 00 00 00 00 00|................|
      0x00000800|06 00 00 00 14 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000810|70 92 00 00 00 00 00 00  05 00 00 00 13 00 00 00|p...............|
      0x00000820|00 00 00 00 00 00 00 00  ** ** ** ** ** ** ** **|........********|
      =============================================================================

    Relocation section '.rela.dyn' at offset ?? contains 87 entries:
      Idx  Offset          Info         Type      Sym. Value Sym. Name + Addend
      [00] 000000008d10 000000000008 0x00000008      test    sym.name  + 8928
      [01] 000000008d18 000000000008 0x00000008      test    sym.name  + 18931
      [02] 000000008d20 000000000008 0x00000008      test    sym.name  + 19076
      [03] 000000008d28 000000000008 0x00000008      test    sym.name  + 19204
      [04] 000000008d30 000000000008 0x00000008      test    sym.name  + 19332
      [05] 000000008d38 000000000008 0x00000008      test    sym.name  + 8864
      [06] 000000008d40 000000000008 0x00000008      test    sym.name  + 19012
      [07] 000000008d48 000000000008 0x00000008      test    sym.name  + 19140
      [08] 000000008d50 000000000008 0x00000008      test    sym.name  + 19268
      [09] 000000008d58 000000000008 0x00000008      test    sym.name  + 19396
      [10] 000000009008 000000000008 0x00000008      test    sym.name  + 36872
      [11] 000000009030 000000000008 0x00000008      test    sym.name  + 24269
      [12] 000000009038 000000000008 0x00000008      test    sym.name  + 15702
      [13] 000000009040 000000000008 0x00000008      test    sym.name  + 24277
      [14] 000000009048 000000000008 0x00000008      test    sym.name  + 13788
      [15] 000000009050 000000000008 0x00000008      test    sym.name  + 24293
      [16] 000000009058 000000000008 0x00000008      test    sym.name  + 13920
      [17] 000000009060 000000000008 0x00000008      test    sym.name  + 24307
      [18] 000000009068 000000000008 0x00000008      test    sym.name  + 13986
      [19] 000000009070 000000000008 0x00000008      test    sym.name  + 24326
      [20] 000000009078 000000000008 0x00000008      test    sym.name  + 14052
      [21] 000000009080 000000000008 0x00000008      test    sym.name  + 24336
      [22] 000000009088 000000000008 0x00000008      test    sym.name  + 15960
      [23] 000000009090 000000000008 0x00000008      test    sym.name  + 24344
      [24] 000000009098 000000000008 0x00000008      test    sym.name  + 16631
      [25] 0000000090a0 000000000008 0x00000008      test    sym.name  + 24352
      [26] 0000000090a8 000000000008 0x00000008      test    sym.name  + 14118
      [27] 0000000090b0 000000000008 0x00000008      test    sym.name  + 24365
      [28] 0000000090b8 000000000008 0x00000008      test    sym.name  + 14184
      [29] 0000000090c0 000000000008 0x00000008      test    sym.name  + 24380
      [30] 0000000090c8 000000000008 0x00000008      test    sym.name  + 16757
      [31] 0000000090d0 000000000008 0x00000008      test    sym.name  + 24390
      [32] 0000000090d8 000000000008 0x00000008      test    sym.name  + 14250
      [33] 0000000090e0 000000000008 0x00000008      test    sym.name  + 24400
      [34] 0000000090e8 000000000008 0x00000008      test    sym.name  + 14316
      [35] 0000000090f0 000000000008 0x00000008      test    sym.name  + 24406
      [36] 0000000090f8 000000000008 0x00000008      test    sym.name  + 14382
      [37] 000000009100 000000000008 0x00000008      test    sym.name  + 24411
      [38] 000000009108 000000000008 0x00000008      test    sym.name  + 14448
      [39] 000000009110 000000000008 0x00000008      test    sym.name  + 24420
      [40] 000000009118 000000000008 0x00000008      test    sym.name  + 14514
      [41] 000000009120 000000000008 0x00000008      test    sym.name  + 24426
      [42] 000000009128 000000000008 0x00000008      test    sym.name  + 14580
      [43] 000000009130 000000000008 0x00000008      test    sym.name  + 24432
      [44] 000000009138 000000000008 0x00000008      test    sym.name  + 14646
      [45] 000000009140 000000000008 0x00000008      test    sym.name  + 24440
      [46] 000000009148 000000000008 0x00000008      test    sym.name  + 14712
      [47] 000000009150 000000000008 0x00000008      test    sym.name  + 24454
      [48] 000000009158 000000000008 0x00000008      test    sym.name  + 14778
      [49] 000000009160 000000000008 0x00000008      test    sym.name  + 24464
      [50] 000000009168 000000000008 0x00000008      test    sym.name  + 14844
      [51] 000000009170 000000000008 0x00000008      test    sym.name  + 24476
      [52] 000000009178 000000000008 0x00000008      test    sym.name  + 14910
      [53] 000000009180 000000000008 0x00000008      test    sym.name  + 24488
      [54] 000000009188 000000000008 0x00000008      test    sym.name  + 14976
      [55] 000000009190 000000000008 0x00000008      test    sym.name  + 24497
      [56] 000000009198 000000000008 0x00000008      test    sym.name  + 15042
      [57] 0000000091a0 000000000008 0x00000008      test    sym.name  + 24502
      [58] 0000000091a8 000000000008 0x00000008      test    sym.name  + 15108
      [59] 0000000091b0 000000000008 0x00000008      test    sym.name  + 24511
      [60] 0000000091b8 000000000008 0x00000008      test    sym.name  + 15174
      [61] 0000000091c0 000000000008 0x00000008      test    sym.name  + 24517
      [62] 0000000091c8 000000000008 0x00000008      test    sym.name  + 15240
      [63] 0000000091d0 000000000008 0x00000008      test    sym.name  + 24522
      [64] 0000000091d8 000000000008 0x00000008      test    sym.name  + 15306
      [65] 0000000091e0 000000000008 0x00000008      test    sym.name  + 24531
      [66] 0000000091e8 000000000008 0x00000008      test    sym.name  + 15372
      [67] 0000000091f0 000000000008 0x00000008      test    sym.name  + 24546
      [68] 0000000091f8 000000000008 0x00000008      test    sym.name  + 15438
      [69] 000000009200 000000000008 0x00000008      test    sym.name  + 24558
      [70] 000000009208 000000000008 0x00000008      test    sym.name  + 15504
      [71] 000000009210 000000000008 0x00000008      test    sym.name  + 24572
      [72] 000000009218 000000000008 0x00000008      test    sym.name  + 15570
      [73] 000000009220 000000000008 0x00000008      test    sym.name  + 24584
      [74] 000000009228 000000000008 0x00000008      test    sym.name  + 17142
      [75] 000000009230 000000000008 0x00000008      test    sym.name  + 24595
      [76] 000000009238 000000000008 0x00000008      test    sym.name  + 15636
      [77] 000000009240 000000000008 0x00000008      test    sym.name  + 24603
      [78] 000000009248 000000000008 0x00000008      test    sym.name  + 17268
      [79] 000000009250 000000000008 0x00000008      test    sym.name  + 24611
      [80] 000000009258 000000000008 0x00000008      test    sym.name  + 17394
      [81] 000000008fd8 000200000006 0x00000006      test    sym.name  + 0
      [82] 000000008fe0 000800000006 0x00000006      test    sym.name  + 0
      [83] 000000008fe8 000b00000006 0x00000006      test    sym.name  + 0
      [84] 000000008ff0 001100000006 0x00000006      test    sym.name  + 0
      [85] 000000008ff8 001400000006 0x00000006      test    sym.name  + 0
      [86] 000000009270 001300000005 0x00000005      test    sym.name  + 0

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=11,sect_name=".rela.plt",pSectData=0x5611f5c0b7f0,iLen=0x150}
    >> func{func_sect_rela_plt:(00652)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=12,sect_name=".init",pSectData=0x5611f5c0c890,iLen=0x1b}
    >> func{func_sect_init:(00653)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=13,sect_name=".plt",pSectData=0x5611f5c0c8b0,iLen=0xf0}
    >> func{func_sect_plt:(00654)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=14,sect_name=".plt.got",pSectData=0x5611f5c0c9a0,iLen=0x10}
    >> func{func_sect_plt_got:(00655)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=15,sect_name=".plt.sec",pSectData=0x5611f5c0c9b0,iLen=0xe0}
    >> func{func_process:(00944)} is call .
      >>> {idx=15, name=".plt.sec", pData=0x5611f5c0c9b0, iLen=224, pSectHeader=0x5611f5c19840}.

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=16,sect_name=".text",pSectData=0x5611f5c0ca90,iLen=0x2ce4}
    >> func{func_sect_text:(00656)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=17,sect_name=".fini",pSectData=0x5611f5c0f774,iLen=0xd}
    >> func{func_sect_fini:(00657)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=18,sect_name=".rodata",pSectData=0x5611f5c0f890,iLen=0x188b}
    >> func{func_sect_rodata:(00658)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=19,sect_name=".eh_frame_hdr",pSectData=0x5611f5c1111c,iLen=0x25c}
    >> func{func_sect_eh_frame_hdr:(00659)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=20,sect_name=".eh_frame",pSectData=0x5611f5c11378,iLen=0x968}
    >> func{func_sect_eh_frame:(00660)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=21,sect_name=".init_array",pSectData=0x5611f5c125a0,iLen=0x28}
    >> func{func_sect_init_array:(00661)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=22,sect_name=".fini_array",pSectData=0x5611f5c125c8,iLen=0x28}
    >> func{func_sect_fini_array:(00662)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=23,sect_name=".dynamic",pSectData=0x5611f5c125f0,iLen=0x1f0}
    >> func{func_sect_dynamic:(00663)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=24,sect_name=".got",pSectData=0x5611f5c127e0,iLen=0xb0}
    >> func{func_sect_got:(00664)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=25,sect_name=".data",pSectData=0x5611f5c12890,iLen=0x270}
    >> func{func_sect_data:(00666)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=26,sect_name=".bss",pSectData=0x5611f5c12b00,iLen=0x10}
    >> func{func_sect_bss:(00667)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=27,sect_name=".comment",pSectData=0x5611f5c12b00,iLen=0x2b}
    >> func{func_sect_comment:(00668)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=28,sect_name=".debug_aranges",pSectData=0x5611f5c12b2b,iLen=0x30}
    >> func{func_sect_debug_aranges:(00669)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=29,sect_name=".debug_info",pSectData=0x5611f5c12b5b,iLen=0x2c01}
    >> func{func_sect_debug_info:(00670)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=30,sect_name=".debug_abbrev",pSectData=0x5611f5c1575c,iLen=0x29e}
    >> func{func_sect_debug_abbrev:(00671)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=31,sect_name=".debug_line",pSectData=0x5611f5c159fa,iLen=0xdcb}
    >> func{func_sect_debug_line:(00672)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=32,sect_name=".debug_str",pSectData=0x5611f5c167c5,iLen=0xd5a}
    >> func{func_sect_debug_str:(00852)} is call .
        No.[32]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x5611f5c19c80
        {
             Elf64_Word    sh_name      = 0x14f;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x30;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xbf35;
             Elf64_Xword   sh_size      = 0xd5a;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x1;
        }

0x005611f5c167c5|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|45 6c 66 36 34 5f 41 64  64 72 00 70 61 72 73 65|Elf64_Addr.parse|
      0x00000010|5f 65 6c 66 36 34 5f 70  72 6f 67 5f 68 65 61 64|_elf64_prog_head|
      0x00000020|65 72 00 66 75 6e 63 5f  73 65 63 74 5f 6e 6f 74|er.func_sect_not|
      0x00000030|65 5f 67 6e 75 5f 62 75  69 6c 64 5f 69 64 00 67|e_gnu_build_id.g|
      0x00000040|65 74 5f 65 6c 66 36 34  5f 64 61 74 61 00 74 65|et_elf64_data.te|
      0x00000050|73 74 5f 63 68 61 72 00  5f 73 68 6f 72 74 62 75|st_char._shortbu|
      0x00000060|66 00 73 68 5f 6c 69 6e  6b 00 5f 49 4f 5f 6c 6f|f.sh_link._IO_lo|
      0x00000070|63 6b 5f 74 00 67 70 5f  6f 66 66 73 65 74 00 70|ck_t.gp_offset.p|
      0x00000080|61 72 73 65 5f 65 6c 66  36 34 5f 73 65 63 74 5f|arse_elf64_sect_|
      0x00000090|62 6f 64 79 00 73 74 64  65 72 72 00 5f 49 4f 5f|body.stderr._IO_|
      0x000000a0|62 75 66 5f 65 6e 64 00  69 43 6e 74 00 73 74 5f|buf_end.iCnt.st_|
      0x000000b0|61 74 69 6d 65 6e 73 65  63 00 65 5f 73 68 6f 66|atimensec.e_shof|
      0x000000c0|66 00 70 44 79 6e 73 79  6d 44 61 74 61 00 61 66|f.pDynsymData.af|
      0x000000d0|74 65 72 5f 6d 61 69 6e  5f 66 75 6e 63 00 66 75|ter_main_func.fu|
      0x000000e0|6e 63 5f 73 65 63 74 5f  66 69 6e 69 00 53 5f 45|nc_sect_fini.S_E|
      0x000000f0|4c 46 36 34 5f 53 65 63  74 48 65 61 64 65 72 5f|LF64_SectHeader_|
      0x00000100|74 00 5f 49 4f 5f 77 72  69 74 65 5f 65 6e 64 00|t._IO_write_end.|
      0x00000110|66 75 6e 63 5f 73 65 63  74 5f 64 79 6e 73 79 6d|func_sect_dynsym|
      0x00000120|00 66 75 6e 63 5f 73 65  63 74 5f 69 6e 74 65 72|.func_sect_inter|
      0x00000130|70 00 70 61 72 73 65 5f  65 6c 66 36 34 5f 70 72|p.parse_elf64_pr|
      0x00000140|6f 67 5f 68 65 61 64 65  72 73 00 5f 66 72 65 65|og_headers._free|
      0x00000150|72 65 73 5f 6c 69 73 74  00 73 74 5f 62 6c 6b 73|res_list.st_blks|
      0x00000160|69 7a 65 00 65 5f 76 65  72 73 69 6f 6e 00 69 72|ize.e_version.ir|
      0x00000170|65 74 00 53 5f 45 6c 66  36 34 5f 53 65 63 74 46|et.S_Elf64_SectF|
      0x00000180|75 6e 63 5f 74 00 65 6c  66 36 34 5f 6f 62 6a 5f|unc_t.elf64_obj_|
      0x00000190|73 69 7a 65 00 65 5f 70  68 6f 66 66 00 73 74 5f|size.e_phoff.st_|
      0x000001a0|69 6e 66 6f 00 5f 6d 61  72 6b 65 72 73 00 65 5f|info._markers.e_|
      0x000001b0|65 68 73 69 7a 65 00 5f  5f 6e 6c 69 6e 6b 5f 74|ehsize.__nlink_t|
      0x000001c0|00 66 75 6e 63 5f 73 65  63 74 5f 64 61 74 61 00|.func_sect_data.|
      0x000001d0|70 5f 65 6c 66 36 34 5f  6f 62 6a 00 53 5f 45 4c|p_elf64_obj.S_EL|
      0x000001e0|46 36 34 5f 45 4c 46 48  65 61 64 65 72 5f 74 00|F64_ELFHeader_t.|
      0x000001f0|66 75 6e 63 5f 73 65 63  74 5f 67 6f 74 00 75 69|func_sect_got.ui|
      0x00000200|5f 6c 65 76 65 6c 00 65  5f 73 68 65 6e 74 73 69|_level.e_shentsi|
      0x00000210|7a 65 00 66 75 6e 63 5f  73 65 63 74 5f 73 79 6d|ze.func_sect_sym|
      0x00000220|74 61 62 00 5f 5f 69 6e  6f 5f 74 00 66 75 6e 63|tab.__ino_t.func|
      0x00000230|5f 73 65 63 74 5f 64 65  62 75 67 5f 61 62 62 72|_sect_debug_abbr|
      0x00000240|65 76 00 62 75 69 6c 64  5f 65 6c 66 36 34 5f 6f|ev.build_elf64_o|
      0x00000250|62 6a 00 65 5f 65 6e 74  72 79 00 66 75 6e 63 5f|bj.e_entry.func_|
      0x00000260|73 65 63 74 5f 64 65 62  75 67 5f 73 74 72 00 75|sect_debug_str.u|
      0x00000270|69 6e 74 33 32 5f 74 00  6d 79 5f 69 6e 69 74 30|int32_t.my_init0|
      0x00000280|31 00 6d 79 5f 69 6e 69  74 30 32 00 6d 79 5f 69|1.my_init02.my_i|
      0x00000290|6e 69 74 30 33 00 73 74  64 6f 75 74 00 5f 49 4f|nit03.stdout._IO|
      0x000002a0|5f 73 61 76 65 5f 65 6e  64 00 70 5f 65 6c 66 36|_save_end.p_elf6|
      0x000002b0|34 5f 64 61 74 61 00 66  75 6e 63 5f 73 65 63 74|4_data.func_sect|
      0x000002c0|5f 67 6e 75 5f 76 65 72  73 69 6f 6e 00 70 70 53|_gnu_version.ppS|
      0x000002d0|79 6d 45 6e 74 00 70 5f  64 61 74 61 00 5f 49 4f|ymEnt.p_data._IO|
      0x000002e0|5f 63 6f 64 65 63 76 74  00 66 75 6e 63 5f 73 65|_codecvt.func_se|
      0x000002f0|63 74 5f 74 65 78 74 00  70 50 72 6f 67 48 65 61|ct_text.pProgHea|
      0x00000300|64 65 72 73 44 61 74 61  00 70 61 72 73 65 5f 61|dersData.parse_a|
      0x00000310|72 67 73 00 6f 76 65 72  66 6c 6f 77 5f 61 72 67|rgs.overflow_arg|
      0x00000320|5f 61 72 65 61 00 6c 6f  6e 67 20 6c 6f 6e 67 20|_area.long long |
      0x00000330|75 6e 73 69 67 6e 65 64  20 69 6e 74 00 73 74 5f|unsigned int.st_|
      0x00000340|62 6c 6f 63 6b 73 00 66  75 6e 63 5f 73 65 63 74|blocks.func_sect|
      0x00000350|5f 6e 6f 74 65 5f 41 42  49 5f 74 61 67 00 78 6c|_note_ABI_tag.xl|
      0x00000360|6f 67 5f 63 6f 72 65 00  70 5f 66 69 6c 65 73 7a|og_core.p_filesz|
      0x00000370|00 73 74 5f 6d 74 69 6d  65 00 66 75 6e 63 5f 73|.st_mtime.func_s|
      0x00000380|65 63 74 5f 69 6e 69 74  5f 61 72 72 61 79 00 44|ect_init_array.D|
      0x00000390|75 6d 70 50 74 72 32 53  74 72 00 5f 49 4f 5f 62|umpPtr2Str._IO_b|
      0x000003a0|61 63 6b 75 70 5f 62 61  73 65 00 50 72 6f 67 48|ackup_base.ProgH|
      0x000003b0|65 61 64 65 72 4f 62 6a  73 00 73 5f 65 6c 66 36|eaderObjs.s_elf6|
      0x000003c0|34 5f 6f 62 6a 5f 74 00  70 50 72 6f 67 48 65 61|4_obj_t.pProgHea|
      0x000003d0|64 65 72 44 61 74 61 00  5f 49 53 6c 6f 77 65 72|derData._ISlower|
      0x000003e0|00 5f 66 69 6c 65 6e 6f  00 73 74 61 74 00 70 70|._fileno.stat.pp|
      0x000003f0|50 72 6f 67 48 65 61 64  65 72 73 00 45 6c 66 48|ProgHeaders.ElfH|
      0x00000400|65 61 64 65 72 4f 62 6a  00 66 75 6e 63 5f 73 65|eaderObj.func_se|
      0x00000410|63 74 5f 6e 6f 74 65 5f  67 6e 75 5f 62 75 69 6c|ct_note_gnu_buil|
      0x00000420|64 00 5f 5f 67 6e 75 63  5f 76 61 5f 6c 69 73 74|d.__gnuc_va_list|
      0x00000430|00 66 75 6e 63 5f 73 65  63 74 5f 67 6e 75 5f 68|.func_sect_gnu_h|
      0x00000440|61 73 68 00 5f 5f 6d 6f  64 65 5f 74 00 70 44 61|ash.__mode_t.pDa|
      0x00000450|74 61 00 70 61 72 73 65  5f 65 6c 66 36 34 5f 73|ta.parse_elf64_s|
      0x00000460|65 63 74 5f 68 65 61 64  65 72 73 00 5f 49 53 78|ect_headers._ISx|
      0x00000470|64 69 67 69 74 00 5f 49  4f 5f 72 65 61 64 5f 62|digit._IO_read_b|
      0x00000480|61 73 65 00 70 61 72 73  65 5f 65 6c 66 36 34 5f|ase.parse_elf64_|
      0x00000490|73 65 63 74 5f 68 65 61  64 65 72 00 66 75 6e 63|sect_header.func|
      0x000004a0|5f 73 65 63 74 5f 6e 6f  74 65 5f 67 6e 75 5f 70|_sect_note_gnu_p|
      0x000004b0|72 6f 70 65 00 73 74 5f  67 69 64 00 61 72 67 63|rope.st_gid.argc|
      0x000004c0|00 73 74 64 69 6e 00 47  4e 55 20 43 31 31 20 39|.stdin.GNU C11 9|
      0x000004d0|2e 34 2e 30 20 2d 6d 74  75 6e 65 3d 67 65 6e 65|.4.0 -mtune=gene|
      0x000004e0|72 69 63 20 2d 6d 61 72  63 68 3d 78 38 36 2d 36|ric -march=x86-6|
      0x000004f0|34 20 2d 67 20 2d 4f 30  20 2d 73 74 64 3d 63 31|4 -g -O0 -std=c1|
      0x00000500|31 20 2d 66 61 73 79 6e  63 68 72 6f 6e 6f 75 73|1 -fasynchronous|
      0x00000510|2d 75 6e 77 69 6e 64 2d  74 61 62 6c 65 73 20 2d|-unwind-tables -|
      0x00000520|66 73 74 61 63 6b 2d 70  72 6f 74 65 63 74 6f 72|fstack-protector|
      0x00000530|2d 73 74 72 6f 6e 67 20  2d 66 73 74 61 63 6b 2d|-strong -fstack-|
      0x00000540|63 6c 61 73 68 2d 70 72  6f 74 65 63 74 69 6f 6e|clash-protection|
      0x00000550|20 2d 66 63 66 2d 70 72  6f 74 65 63 74 69 6f 6e| -fcf-protection|
      0x00000560|00 73 74 5f 6d 6f 64 65  00 45 6c 66 36 34 5f 48|.st_mode.Elf64_H|
      0x00000570|61 6c 66 00 73 74 5f 6e  6c 69 6e 6b 00 73 68 5f|alf.st_nlink.sh_|
      0x00000580|65 6e 74 73 69 7a 65 00  78 6c 6f 67 5f 6d 75 74|entsize.xlog_mut|
      0x00000590|65 78 5f 75 6e 6c 6f 63  6b 00 72 5f 69 6e 66 6f|ex_unlock.r_info|
      0x000005a0|00 53 65 63 74 48 65 61  64 65 72 4f 62 6a 73 00|.SectHeaderObjs.|
      0x000005b0|70 44 79 6e 53 74 72 44  61 74 61 00 66 75 6e 63|pDynStrData.func|
      0x000005c0|5f 73 65 63 74 5f 62 73  73 00 66 69 6c 65 6e 61|_sect_bss.filena|
      0x000005d0|6d 65 00 65 5f 66 6c 61  67 73 00 5f 49 4f 5f 6d|me.e_flags._IO_m|
      0x000005e0|61 72 6b 65 72 00 5f 49  4f 5f 72 65 61 64 5f 70|arker._IO_read_p|
      0x000005f0|74 72 00 70 5f 61 6c 69  67 6e 00 66 75 6e 63 5f|tr.p_align.func_|
      0x00000600|73 65 63 74 5f 72 65 6c  61 5f 70 6c 74 00 73 74|sect_rela_plt.st|
      0x00000610|5f 61 74 69 6d 65 00 73  68 5f 69 6e 66 6f 00 65|_atime.sh_info.e|
      0x00000620|5f 73 68 73 74 72 6e 64  78 00 5f 5f 50 52 45 54|_shstrndx.__PRET|
      0x00000630|54 59 5f 46 55 4e 43 54  49 4f 4e 5f 5f 00 66 75|TY_FUNCTION__.fu|
      0x00000640|6e 63 5f 73 65 63 74 5f  72 6f 64 61 74 61 00 70|nc_sect_rodata.p|
      0x00000650|61 72 73 65 5f 65 6c 66  36 34 5f 73 65 63 74 5f|arse_elf64_sect_|
      0x00000660|62 6f 64 79 73 00 75 69  6e 74 38 5f 74 00 66 75|bodys.uint8_t.fu|
      0x00000670|6e 63 5f 73 65 63 74 5f  69 6e 69 74 00 73 74 5f|nc_sect_init.st_|
      0x00000680|69 6e 6f 00 53 5f 45 6c  66 36 34 5f 52 65 6c 61|ino.S_Elf64_Rela|
      0x00000690|5f 74 00 66 75 6e 63 5f  73 65 63 74 5f 64 79 6e|_t.func_sect_dyn|
      0x000006a0|73 74 72 00 70 45 6c 66  48 65 61 64 65 72 00 45|str.pElfHeader.E|
      0x000006b0|6c 66 36 34 5f 58 77 6f  72 64 00 5f 49 4f 5f 77|lf64_Xword._IO_w|
      0x000006c0|72 69 74 65 5f 62 61 73  65 00 70 53 65 63 74 4e|rite_base.pSectN|
      0x000006d0|61 6d 65 73 00 6c 6f 6e  67 20 6c 6f 6e 67 20 69|ames.long long i|
      0x000006e0|6e 74 00 66 75 6e 63 5f  73 65 63 74 5f 70 6c 74|nt.func_sect_plt|
      0x000006f0|5f 67 6f 74 00 73 74 5f  6d 74 69 6d 65 6e 73 65|_got.st_mtimense|
      0x00000700|63 00 45 6c 66 36 34 5f  4f 66 66 00 5f 49 4f 5f|c.Elf64_Off._IO_|
      0x00000710|73 61 76 65 5f 62 61 73  65 00 5f 5f 64 65 76 5f|save_base.__dev_|
      0x00000720|74 00 66 75 6e 63 5f 73  65 63 74 5f 70 6c 74 00|t.func_sect_plt.|
      0x00000730|5f 49 53 63 6e 74 72 6c  00 70 53 65 63 74 48 65|_IScntrl.pSectHe|
      0x00000740|61 64 65 72 44 61 74 61  00 2f 68 6f 6d 65 2f 78|aderData./home/x|
      0x00000750|61 64 6d 69 6e 2f 78 77  6b 73 2e 67 69 74 2e 31|admin/xwks.git.1|
      0x00000760|2f 6d 79 72 65 61 64 65  6c 66 2d 63 31 31 00 70|/myreadelf-c11.p|
      0x00000770|53 65 63 74 48 65 61 64  65 72 00 70 5f 66 6c 61|SectHeader.p_fla|
      0x00000780|67 73 00 66 75 6e 63 5f  73 65 63 74 5f 67 6e 75|gs.func_sect_gnu|
      0x00000790|5f 76 65 72 73 69 6f 6e  5f 72 00 70 53 65 63 74|_version_r.pSect|
      0x000007a0|44 61 74 61 00 5f 5f 73  79 73 63 61 6c 6c 5f 73|Data.__syscall_s|
      0x000007b0|6c 6f 6e 67 5f 74 00 5f  49 53 64 69 67 69 74 00|long_t._ISdigit.|
      0x000007c0|78 6c 6f 67 5f 69 6e 66  6f 5f 78 00 70 61 72 73|xlog_info_x.pars|
      0x000007d0|65 5f 65 6c 66 36 34 5f  65 6c 66 5f 68 65 61 64|e_elf64_elf_head|
      0x000007e0|65 72 00 5f 49 53 73 70  61 63 65 00 5f 66 72 65|er._ISspace._fre|
      0x000007f0|65 72 65 73 5f 62 75 66  00 78 6c 6f 67 5f 75 6e|eres_buf.xlog_un|
      0x00000800|69 6e 69 74 00 70 5f 74  79 70 65 00 66 75 6e 63|init.p_type.func|
      0x00000810|5f 73 65 63 74 5f 65 68  5f 66 72 61 6d 65 5f 68|_sect_eh_frame_h|
      0x00000820|64 72 00 73 74 61 74 62  75 66 00 5f 5f 70 61 64|dr.statbuf.__pad|
      0x00000830|30 00 5f 5f 70 61 64 35  00 73 68 5f 6f 66 66 73|0.__pad5.sh_offs|
      0x00000840|65 74 00 5f 5f 67 6c 69  62 63 5f 72 65 73 65 72|et.__glibc_reser|
      0x00000850|76 65 64 00 66 75 6e 63  5f 73 65 63 74 5f 73 74|ved.func_sect_st|
      0x00000860|72 74 61 62 00 70 5f 76  61 64 64 72 00 62 65 66|rtab.p_vaddr.bef|
      0x00000870|6f 72 65 5f 6d 61 69 6e  5f 66 75 6e 63 00 70 5f|ore_main_func.p_|
      0x00000880|6d 65 6d 73 7a 00 5f 76  74 61 62 6c 65 5f 6f 66|memsz._vtable_of|
      0x00000890|66 73 65 74 00 66 75 6e  63 5f 73 65 63 74 5f 64|fset.func_sect_d|
      0x000008a0|65 62 75 67 5f 69 6e 66  6f 00 61 72 67 76 00 73|ebug_info.argv.s|
      0x000008b0|68 5f 6e 61 6d 65 00 5f  5f 67 69 64 5f 74 00 73|h_name.__gid_t.s|
      0x000008c0|74 5f 63 74 69 6d 65 6e  73 65 63 00 78 6c 6f 67|t_ctimensec.xlog|
      0x000008d0|5f 68 65 78 64 75 6d 70  00 70 50 72 6f 67 48 65|_hexdump.pProgHe|
      0x000008e0|61 64 65 72 00 70 4e 61  6d 65 00 66 75 6e 63 5f|ader.pName.func_|
      0x000008f0|73 65 63 74 5f 72 65 6c  61 5f 64 79 6e 00 72 5f|sect_rela_dyn.r_|
      0x00000900|6f 66 66 73 65 74 00 73  74 5f 6f 74 68 65 72 00|offset.st_other.|
      0x00000910|65 5f 73 68 6e 75 6d 00  6d 79 5f 66 69 6e 69 30|e_shnum.my_fini0|
      0x00000920|33 00 73 74 5f 73 68 6e  64 78 00 5f 49 53 70 75|3.st_shndx._ISpu|
      0x00000930|6e 63 74 00 5f 5f 73 79  73 63 61 6c 6c 5f 75 6c|nct.__syscall_ul|
      0x00000940|6f 6e 67 5f 74 00 5f 49  4f 5f 72 65 61 64 5f 65|ong_t._IO_read_e|
      0x00000950|6e 64 00 6c 6f 67 5f 73  77 69 74 63 68 00 53 5f|nd.log_switch.S_|
      0x00000960|45 6c 66 36 34 5f 53 79  6d 45 6e 74 5f 74 00 5f|Elf64_SymEnt_t._|
      0x00000970|49 53 70 72 69 6e 74 00  73 68 6f 72 74 20 69 6e|ISprint.short in|
      0x00000980|74 00 65 5f 70 68 65 6e  74 73 69 7a 65 00 70 5f|t.e_phentsize.p_|
      0x00000990|70 61 64 64 72 00 70 70  52 65 6c 61 45 6e 74 00|paddr.ppRelaEnt.|
      0x000009a0|78 6c 6f 67 5f 69 6e 69  74 00 65 5f 70 68 6e 75|xlog_init.e_phnu|
      0x000009b0|6d 00 66 75 6e 63 5f 73  65 63 74 5f 67 6f 74 5f|m.func_sect_got_|
      0x000009c0|70 6c 74 00 73 68 5f 73  69 7a 65 00 5f 49 4f 5f|plt.sh_size._IO_|
      0x000009d0|77 69 64 65 5f 64 61 74  61 00 6d 79 5f 66 69 6e|wide_data.my_fin|
      0x000009e0|69 30 31 00 6d 79 5f 66  69 6e 69 30 32 00 70 73|i01.my_fini02.ps|
      0x000009f0|74 72 5f 6e 61 6d 65 00  5f 5f 76 61 5f 6c 69 73|tr_name.__va_lis|
      0x00000a00|74 5f 74 61 67 00 5f 5f  62 6c 6b 73 69 7a 65 5f|t_tag.__blksize_|
      0x00000a10|74 00 73 68 5f 61 64 64  72 00 69 5f 6c 65 6e 00|t.sh_addr.i_len.|
      0x00000a20|66 75 6e 63 5f 73 65 63  74 5f 63 6f 6d 6d 65 6e|func_sect_commen|
      0x00000a30|74 00 66 70 5f 6f 66 66  73 65 74 00 73 74 5f 63|t.fp_offset.st_c|
      0x00000a40|74 69 6d 65 00 69 50 74  72 4d 61 78 43 6e 74 00|time.iPtrMaxCnt.|
      0x00000a50|5f 49 53 67 72 61 70 68  00 70 53 48 4e 61 6d 65|_ISgraph.pSHName|
      0x00000a60|00 69 5f 72 6f 77 00 78  6c 6f 67 5f 69 6e 66 6f|.i_row.xlog_info|
      0x00000a70|00 5f 6f 6c 64 5f 6f 66  66 73 65 74 00 5f 49 4f|._old_offset._IO|
      0x00000a80|5f 46 49 4c 45 00 70 66  75 6e 63 5f 70 72 6f 63|_FILE.pfunc_proc|
      0x00000a90|65 73 73 00 72 65 67 5f  73 61 76 65 5f 61 72 65|ess.reg_save_are|
      0x00000aa0|61 00 73 68 5f 74 79 70  65 00 5f 49 53 61 6c 70|a.sh_type._ISalp|
      0x00000ab0|68 61 00 66 75 6e 63 5f  73 65 63 74 5f 65 68 5f|ha.func_sect_eh_|
      0x00000ac0|66 72 61 6d 65 00 69 5f  65 6c 66 36 34 5f 6c 65|frame.i_elf64_le|
      0x00000ad0|6e 00 72 5f 61 64 64 65  6e 64 00 65 5f 69 64 65|n.r_addend.e_ide|
      0x00000ae0|6e 74 00 66 75 6e 63 5f  73 65 63 74 5f 64 65 62|nt.func_sect_deb|
      0x00000af0|75 67 5f 61 72 61 6e 67  65 73 00 73 69 7a 65 5f|ug_aranges.size_|
      0x00000b00|72 65 61 64 6f 6b 00 66  75 6e 63 5f 73 65 63 74|readok.func_sect|
      0x00000b10|5f 66 69 6e 69 5f 61 72  72 61 79 00 75 6e 73 69|_fini_array.unsi|
      0x00000b20|67 6e 65 64 20 63 68 61  72 00 73 65 63 74 5f 66|gned char.sect_f|
      0x00000b30|75 6e 63 73 00 70 53 65  63 74 4e 61 6d 65 00 5f|uncs.pSectName._|
      0x00000b40|49 4f 5f 77 72 69 74 65  5f 70 74 72 00 66 75 6e|IO_write_ptr.fun|
      0x00000b50|63 5f 73 65 63 74 5f 73  68 73 74 72 74 61 62 00|c_sect_shstrtab.|
      0x00000b60|70 45 6c 66 44 61 74 61  00 50 72 74 53 65 63 74|pElfData.PrtSect|
      0x00000b70|48 65 61 64 65 72 00 65  5f 74 79 70 65 00 70 53|Header.e_type.pS|
      0x00000b80|65 63 74 5f 53 68 53 74  72 54 61 62 5f 48 65 61|ect_ShStrTab_Hea|
      0x00000b90|64 65 72 00 73 68 5f 66  6c 61 67 73 00 5f 5f 74|der.sh_flags.__t|
      0x00000ba0|69 6d 65 5f 74 00 65 5f  6d 61 63 68 69 6e 65 00|ime_t.e_machine.|
      0x00000bb0|5f 49 53 61 6c 6e 75 6d  00 73 74 5f 76 61 6c 75|_ISalnum.st_valu|
      0x00000bc0|65 00 5f 5f 75 69 64 5f  74 00 73 74 5f 73 69 7a|e.__uid_t.st_siz|
      0x00000bd0|65 00 66 75 6e 63 5f 73  65 63 74 5f 64 65 62 75|e.func_sect_debu|
      0x00000be0|67 5f 6c 69 6e 65 00 73  74 5f 75 69 64 00 5f 5f|g_line.st_uid.__|
      0x00000bf0|6f 66 66 5f 74 00 5f 49  53 62 6c 61 6e 6b 00 73|off_t._ISblank.s|
      0x00000c00|74 5f 64 65 76 00 70 53  65 63 74 48 65 61 64 65|t_dev.pSectHeade|
      0x00000c10|72 73 44 61 74 61 00 73  68 6f 72 74 20 75 6e 73|rsData.short uns|
      0x00000c20|69 67 6e 65 64 20 69 6e  74 00 78 6c 6f 67 5f 6d|igned int.xlog_m|
      0x00000c30|75 74 65 78 5f 6c 6f 63  6b 00 6d 61 69 6e 00 68|utex_lock.main.h|
      0x00000c40|46 69 6c 65 00 5f 5f 62  75 69 6c 74 69 6e 5f 76|File.__builtin_v|
      0x00000c50|61 5f 6c 69 73 74 00 53  5f 45 4c 46 36 34 5f 50|a_list.S_ELF64_P|
      0x00000c60|72 6f 67 48 65 61 64 65  72 5f 74 00 66 75 6e 63|rogHeader_t.func|
      0x00000c70|5f 73 65 63 74 5f 64 79  6e 61 6d 69 63 00 5f 5f|_sect_dynamic.__|
      0x00000c80|66 75 6e 63 5f 5f 00 70  70 53 65 63 74 48 65 61|func__.ppSectHea|
      0x00000c90|64 65 72 73 00 45 6c 66  36 34 5f 53 78 77 6f 72|ders.Elf64_Sxwor|
      0x00000ca0|64 00 5f 5f 62 6c 6b 63  6e 74 5f 74 00 69 4c 65|d.__blkcnt_t.iLe|
      0x00000cb0|6e 00 5f 63 68 61 69 6e  00 5f 49 53 75 70 70 65|n._chain._ISuppe|
      0x00000cc0|72 00 73 74 5f 72 64 65  76 00 73 68 5f 61 64 64|r.st_rdev.sh_add|
      0x00000cd0|72 61 6c 69 67 6e 00 45  6c 66 36 34 5f 57 6f 72|ralign.Elf64_Wor|
      0x00000ce0|64 00 5f 66 6c 61 67 73  32 00 73 74 5f 6e 61 6d|d._flags2.st_nam|
      0x00000cf0|65 00 70 53 65 63 52 65  6c 61 64 79 6e 42 6f 64|e.pSecReladynBod|
      0x00000d00|79 00 50 72 74 50 72 6f  67 48 65 61 64 65 72 00|y.PrtProgHeader.|
      0x00000d10|5f 63 75 72 5f 63 6f 6c  75 6d 6e 00 6d 79 72 65|_cur_column.myre|
      0x00000d20|61 64 65 6c 66 2d 30 2e  31 2e 30 37 2e 63 00 70|adelf-0.1.07.c.p|
      0x00000d30|44 61 74 61 53 74 61 72  74 00 5f 5f 6f 66 66 36|DataStart.__off6|
      0x00000d40|34 5f 74 00 5f 75 6e 75  73 65 64 32 00 5f 49 4f|4_t._unused2._IO|
      0x00000d50|5f 62 75 66 5f 62 61 73  65 00 ** ** ** ** ** **|_buf_base.******|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x005611f5c167c5; str={"Elf64_Addr"};
      >> ptr[001]=0x005611f5c167d0; str={"parse_elf64_prog_header"};
      >> ptr[002]=0x005611f5c167e8; str={"func_sect_note_gnu_build_id"};
      >> ptr[003]=0x005611f5c16804; str={"get_elf64_data"};
      >> ptr[004]=0x005611f5c16813; str={"test_char"};
      >> ptr[005]=0x005611f5c1681d; str={"_shortbuf"};
      >> ptr[006]=0x005611f5c16827; str={"sh_link"};
      >> ptr[007]=0x005611f5c1682f; str={"_IO_lock_t"};
      >> ptr[008]=0x005611f5c1683a; str={"gp_offset"};
      >> ptr[009]=0x005611f5c16844; str={"parse_elf64_sect_body"};
      >> ptr[010]=0x005611f5c1685a; str={"stderr"};
      >> ptr[011]=0x005611f5c16861; str={"_IO_buf_end"};
      >> ptr[012]=0x005611f5c1686d; str={"iCnt"};
      >> ptr[013]=0x005611f5c16872; str={"st_atimensec"};
      >> ptr[014]=0x005611f5c1687f; str={"e_shoff"};
      >> ptr[015]=0x005611f5c16887; str={"pDynsymData"};
      >> ptr[016]=0x005611f5c16893; str={"after_main_func"};
      >> ptr[017]=0x005611f5c168a3; str={"func_sect_fini"};
      >> ptr[018]=0x005611f5c168b2; str={"S_ELF64_SectHeader_t"};
      >> ptr[019]=0x005611f5c168c7; str={"_IO_write_end"};
      >> ptr[020]=0x005611f5c168d5; str={"func_sect_dynsym"};
      >> ptr[021]=0x005611f5c168e6; str={"func_sect_interp"};
      >> ptr[022]=0x005611f5c168f7; str={"parse_elf64_prog_headers"};
      >> ptr[023]=0x005611f5c16910; str={"_freeres_list"};
      >> ptr[024]=0x005611f5c1691e; str={"st_blksize"};
      >> ptr[025]=0x005611f5c16929; str={"e_version"};
      >> ptr[026]=0x005611f5c16933; str={"iret"};
      >> ptr[027]=0x005611f5c16938; str={"S_Elf64_SectFunc_t"};
      >> ptr[028]=0x005611f5c1694b; str={"elf64_obj_size"};
      >> ptr[029]=0x005611f5c1695a; str={"e_phoff"};
      >> ptr[030]=0x005611f5c16962; str={"st_info"};
      >> ptr[031]=0x005611f5c1696a; str={"_markers"};
      >> ptr[032]=0x005611f5c16973; str={"e_ehsize"};
      >> ptr[033]=0x005611f5c1697c; str={"__nlink_t"};
      >> ptr[034]=0x005611f5c16986; str={"func_sect_data"};
      >> ptr[035]=0x005611f5c16995; str={"p_elf64_obj"};
      >> ptr[036]=0x005611f5c169a1; str={"S_ELF64_ELFHeader_t"};
      >> ptr[037]=0x005611f5c169b5; str={"func_sect_got"};
      >> ptr[038]=0x005611f5c169c3; str={"ui_level"};
      >> ptr[039]=0x005611f5c169cc; str={"e_shentsize"};
      >> ptr[040]=0x005611f5c169d8; str={"func_sect_symtab"};
      >> ptr[041]=0x005611f5c169e9; str={"__ino_t"};
      >> ptr[042]=0x005611f5c169f1; str={"func_sect_debug_abbrev"};
      >> ptr[043]=0x005611f5c16a08; str={"build_elf64_obj"};
      >> ptr[044]=0x005611f5c16a18; str={"e_entry"};
      >> ptr[045]=0x005611f5c16a20; str={"func_sect_debug_str"};
      >> ptr[046]=0x005611f5c16a34; str={"uint32_t"};
      >> ptr[047]=0x005611f5c16a3d; str={"my_init01"};
      >> ptr[048]=0x005611f5c16a47; str={"my_init02"};
      >> ptr[049]=0x005611f5c16a51; str={"my_init03"};
      >> ptr[050]=0x005611f5c16a5b; str={"stdout"};
      >> ptr[051]=0x005611f5c16a62; str={"_IO_save_end"};
      >> ptr[052]=0x005611f5c16a6f; str={"p_elf64_data"};
      >> ptr[053]=0x005611f5c16a7c; str={"func_sect_gnu_version"};
      >> ptr[054]=0x005611f5c16a92; str={"ppSymEnt"};
      >> ptr[055]=0x005611f5c16a9b; str={"p_data"};
      >> ptr[056]=0x005611f5c16aa2; str={"_IO_codecvt"};
      >> ptr[057]=0x005611f5c16aae; str={"func_sect_text"};
      >> ptr[058]=0x005611f5c16abd; str={"pProgHeadersData"};
      >> ptr[059]=0x005611f5c16ace; str={"parse_args"};
      >> ptr[060]=0x005611f5c16ad9; str={"overflow_arg_area"};
      >> ptr[061]=0x005611f5c16aeb; str={"long long unsigned int"};
      >> ptr[062]=0x005611f5c16b02; str={"st_blocks"};
      >> ptr[063]=0x005611f5c16b0c; str={"func_sect_note_ABI_tag"};
      >> ptr[064]=0x005611f5c16b23; str={"xlog_core"};
      >> ptr[065]=0x005611f5c16b2d; str={"p_filesz"};
      >> ptr[066]=0x005611f5c16b36; str={"st_mtime"};
      >> ptr[067]=0x005611f5c16b3f; str={"func_sect_init_array"};
      >> ptr[068]=0x005611f5c16b54; str={"DumpPtr2Str"};
      >> ptr[069]=0x005611f5c16b60; str={"_IO_backup_base"};
      >> ptr[070]=0x005611f5c16b70; str={"ProgHeaderObjs"};
      >> ptr[071]=0x005611f5c16b7f; str={"s_elf64_obj_t"};
      >> ptr[072]=0x005611f5c16b8d; str={"pProgHeaderData"};
      >> ptr[073]=0x005611f5c16b9d; str={"_ISlower"};
      >> ptr[074]=0x005611f5c16ba6; str={"_fileno"};
      >> ptr[075]=0x005611f5c16bae; str={"stat"};
      >> ptr[076]=0x005611f5c16bb3; str={"ppProgHeaders"};
      >> ptr[077]=0x005611f5c16bc1; str={"ElfHeaderObj"};
      >> ptr[078]=0x005611f5c16bce; str={"func_sect_note_gnu_build"};
      >> ptr[079]=0x005611f5c16be7; str={"__gnuc_va_list"};
      >> ptr[080]=0x005611f5c16bf6; str={"func_sect_gnu_hash"};
      >> ptr[081]=0x005611f5c16c09; str={"__mode_t"};
      >> ptr[082]=0x005611f5c16c12; str={"pData"};
      >> ptr[083]=0x005611f5c16c18; str={"parse_elf64_sect_headers"};
      >> ptr[084]=0x005611f5c16c31; str={"_ISxdigit"};
      >> ptr[085]=0x005611f5c16c3b; str={"_IO_read_base"};
      >> ptr[086]=0x005611f5c16c49; str={"parse_elf64_sect_header"};
      >> ptr[087]=0x005611f5c16c61; str={"func_sect_note_gnu_prope"};
      >> ptr[088]=0x005611f5c16c7a; str={"st_gid"};
      >> ptr[089]=0x005611f5c16c81; str={"argc"};
      >> ptr[090]=0x005611f5c16c86; str={"stdin"};
      >> ptr[091]=0x005611f5c16c8c; str={"GNU C11 9.4.0 -mtune=generic -march=x86-64 -g -O0 -std=c11 -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection"};
      >> ptr[092]=0x005611f5c16d26; str={"st_mode"};
      >> ptr[093]=0x005611f5c16d2e; str={"Elf64_Half"};
      >> ptr[094]=0x005611f5c16d39; str={"st_nlink"};
      >> ptr[095]=0x005611f5c16d42; str={"sh_entsize"};
      >> ptr[096]=0x005611f5c16d4d; str={"xlog_mutex_unlock"};
      >> ptr[097]=0x005611f5c16d5f; str={"r_info"};
      >> ptr[098]=0x005611f5c16d66; str={"SectHeaderObjs"};
      >> ptr[099]=0x005611f5c16d75; str={"pDynStrData"};
      >> ptr[100]=0x005611f5c16d81; str={"func_sect_bss"};
      >> ptr[101]=0x005611f5c16d8f; str={"filename"};
      >> ptr[102]=0x005611f5c16d98; str={"e_flags"};
      >> ptr[103]=0x005611f5c16da0; str={"_IO_marker"};
      >> ptr[104]=0x005611f5c16dab; str={"_IO_read_ptr"};
      >> ptr[105]=0x005611f5c16db8; str={"p_align"};
      >> ptr[106]=0x005611f5c16dc0; str={"func_sect_rela_plt"};
      >> ptr[107]=0x005611f5c16dd3; str={"st_atime"};
      >> ptr[108]=0x005611f5c16ddc; str={"sh_info"};
      >> ptr[109]=0x005611f5c16de4; str={"e_shstrndx"};
      >> ptr[110]=0x005611f5c16def; str={"__PRETTY_FUNCTION__"};
      >> ptr[111]=0x005611f5c16e03; str={"func_sect_rodata"};
      >> ptr[112]=0x005611f5c16e14; str={"parse_elf64_sect_bodys"};
      >> ptr[113]=0x005611f5c16e2b; str={"uint8_t"};
      >> ptr[114]=0x005611f5c16e33; str={"func_sect_init"};
      >> ptr[115]=0x005611f5c16e42; str={"st_ino"};
      >> ptr[116]=0x005611f5c16e49; str={"S_Elf64_Rela_t"};
      >> ptr[117]=0x005611f5c16e58; str={"func_sect_dynstr"};
      >> ptr[118]=0x005611f5c16e69; str={"pElfHeader"};
      >> ptr[119]=0x005611f5c16e74; str={"Elf64_Xword"};
      >> ptr[120]=0x005611f5c16e80; str={"_IO_write_base"};
      >> ptr[121]=0x005611f5c16e8f; str={"pSectNames"};
      >> ptr[122]=0x005611f5c16e9a; str={"long long int"};
      >> ptr[123]=0x005611f5c16ea8; str={"func_sect_plt_got"};
      >> ptr[124]=0x005611f5c16eba; str={"st_mtimensec"};
      >> ptr[125]=0x005611f5c16ec7; str={"Elf64_Off"};
      >> ptr[126]=0x005611f5c16ed1; str={"_IO_save_base"};
      >> ptr[127]=0x005611f5c16edf; str={"__dev_t"};
      >> ptr[128]=0x005611f5c16ee7; str={"func_sect_plt"};
      >> ptr[129]=0x005611f5c16ef5; str={"_IScntrl"};
      >> ptr[130]=0x005611f5c16efe; str={"pSectHeaderData"};
      >> ptr[131]=0x005611f5c16f0e; str={"/home/xadmin/xwks.git.1/myreadelf-c11"};
      >> ptr[132]=0x005611f5c16f34; str={"pSectHeader"};
      >> ptr[133]=0x005611f5c16f40; str={"p_flags"};
      >> ptr[134]=0x005611f5c16f48; str={"func_sect_gnu_version_r"};
      >> ptr[135]=0x005611f5c16f60; str={"pSectData"};
      >> ptr[136]=0x005611f5c16f6a; str={"__syscall_slong_t"};
      >> ptr[137]=0x005611f5c16f7c; str={"_ISdigit"};
      >> ptr[138]=0x005611f5c16f85; str={"xlog_info_x"};
      >> ptr[139]=0x005611f5c16f91; str={"parse_elf64_elf_header"};
      >> ptr[140]=0x005611f5c16fa8; str={"_ISspace"};
      >> ptr[141]=0x005611f5c16fb1; str={"_freeres_buf"};
      >> ptr[142]=0x005611f5c16fbe; str={"xlog_uninit"};
      >> ptr[143]=0x005611f5c16fca; str={"p_type"};
      >> ptr[144]=0x005611f5c16fd1; str={"func_sect_eh_frame_hdr"};
      >> ptr[145]=0x005611f5c16fe8; str={"statbuf"};
      >> ptr[146]=0x005611f5c16ff0; str={"__pad0"};
      >> ptr[147]=0x005611f5c16ff7; str={"__pad5"};
      >> ptr[148]=0x005611f5c16ffe; str={"sh_offset"};
      >> ptr[149]=0x005611f5c17008; str={"__glibc_reserved"};
      >> ptr[150]=0x005611f5c17019; str={"func_sect_strtab"};
      >> ptr[151]=0x005611f5c1702a; str={"p_vaddr"};
      >> ptr[152]=0x005611f5c17032; str={"before_main_func"};
      >> ptr[153]=0x005611f5c17043; str={"p_memsz"};
      >> ptr[154]=0x005611f5c1704b; str={"_vtable_offset"};
      >> ptr[155]=0x005611f5c1705a; str={"func_sect_debug_info"};
      >> ptr[156]=0x005611f5c1706f; str={"argv"};
      >> ptr[157]=0x005611f5c17074; str={"sh_name"};
      >> ptr[158]=0x005611f5c1707c; str={"__gid_t"};
      >> ptr[159]=0x005611f5c17084; str={"st_ctimensec"};
      >> ptr[160]=0x005611f5c17091; str={"xlog_hexdump"};
      >> ptr[161]=0x005611f5c1709e; str={"pProgHeader"};
      >> ptr[162]=0x005611f5c170aa; str={"pName"};
      >> ptr[163]=0x005611f5c170b0; str={"func_sect_rela_dyn"};
      >> ptr[164]=0x005611f5c170c3; str={"r_offset"};
      >> ptr[165]=0x005611f5c170cc; str={"st_other"};
      >> ptr[166]=0x005611f5c170d5; str={"e_shnum"};
      >> ptr[167]=0x005611f5c170dd; str={"my_fini03"};
      >> ptr[168]=0x005611f5c170e7; str={"st_shndx"};
      >> ptr[169]=0x005611f5c170f0; str={"_ISpunct"};
      >> ptr[170]=0x005611f5c170f9; str={"__syscall_ulong_t"};
      >> ptr[171]=0x005611f5c1710b; str={"_IO_read_end"};
      >> ptr[172]=0x005611f5c17118; str={"log_switch"};
      >> ptr[173]=0x005611f5c17123; str={"S_Elf64_SymEnt_t"};
      >> ptr[174]=0x005611f5c17134; str={"_ISprint"};
      >> ptr[175]=0x005611f5c1713d; str={"short int"};
      >> ptr[176]=0x005611f5c17147; str={"e_phentsize"};
      >> ptr[177]=0x005611f5c17153; str={"p_paddr"};
      >> ptr[178]=0x005611f5c1715b; str={"ppRelaEnt"};
      >> ptr[179]=0x005611f5c17165; str={"xlog_init"};
      >> ptr[180]=0x005611f5c1716f; str={"e_phnum"};
      >> ptr[181]=0x005611f5c17177; str={"func_sect_got_plt"};
      >> ptr[182]=0x005611f5c17189; str={"sh_size"};
      >> ptr[183]=0x005611f5c17191; str={"_IO_wide_data"};
      >> ptr[184]=0x005611f5c1719f; str={"my_fini01"};
      >> ptr[185]=0x005611f5c171a9; str={"my_fini02"};
      >> ptr[186]=0x005611f5c171b3; str={"pstr_name"};
      >> ptr[187]=0x005611f5c171bd; str={"__va_list_tag"};
      >> ptr[188]=0x005611f5c171cb; str={"__blksize_t"};
      >> ptr[189]=0x005611f5c171d7; str={"sh_addr"};
      >> ptr[190]=0x005611f5c171df; str={"i_len"};
      >> ptr[191]=0x005611f5c171e5; str={"func_sect_comment"};
      >> ptr[192]=0x005611f5c171f7; str={"fp_offset"};
      >> ptr[193]=0x005611f5c17201; str={"st_ctime"};
      >> ptr[194]=0x005611f5c1720a; str={"iPtrMaxCnt"};
      >> ptr[195]=0x005611f5c17215; str={"_ISgraph"};
      >> ptr[196]=0x005611f5c1721e; str={"pSHName"};
      >> ptr[197]=0x005611f5c17226; str={"i_row"};
      >> ptr[198]=0x005611f5c1722c; str={"xlog_info"};
      >> ptr[199]=0x005611f5c17236; str={"_old_offset"};
      >> ptr[200]=0x005611f5c17242; str={"_IO_FILE"};
      >> ptr[201]=0x005611f5c1724b; str={"pfunc_process"};
      >> ptr[202]=0x005611f5c17259; str={"reg_save_area"};
      >> ptr[203]=0x005611f5c17267; str={"sh_type"};
      >> ptr[204]=0x005611f5c1726f; str={"_ISalpha"};
      >> ptr[205]=0x005611f5c17278; str={"func_sect_eh_frame"};
      >> ptr[206]=0x005611f5c1728b; str={"i_elf64_len"};
      >> ptr[207]=0x005611f5c17297; str={"r_addend"};
      >> ptr[208]=0x005611f5c172a0; str={"e_ident"};
      >> ptr[209]=0x005611f5c172a8; str={"func_sect_debug_aranges"};
      >> ptr[210]=0x005611f5c172c0; str={"size_readok"};
      >> ptr[211]=0x005611f5c172cc; str={"func_sect_fini_array"};
      >> ptr[212]=0x005611f5c172e1; str={"unsigned char"};
      >> ptr[213]=0x005611f5c172ef; str={"sect_funcs"};
      >> ptr[214]=0x005611f5c172fa; str={"pSectName"};
      >> ptr[215]=0x005611f5c17304; str={"_IO_write_ptr"};
      >> ptr[216]=0x005611f5c17312; str={"func_sect_shstrtab"};
      >> ptr[217]=0x005611f5c17325; str={"pElfData"};
      >> ptr[218]=0x005611f5c1732e; str={"PrtSectHeader"};
      >> ptr[219]=0x005611f5c1733c; str={"e_type"};
      >> ptr[220]=0x005611f5c17343; str={"pSect_ShStrTab_Header"};
      >> ptr[221]=0x005611f5c17359; str={"sh_flags"};
      >> ptr[222]=0x005611f5c17362; str={"__time_t"};
      >> ptr[223]=0x005611f5c1736b; str={"e_machine"};
      >> ptr[224]=0x005611f5c17375; str={"_ISalnum"};
      >> ptr[225]=0x005611f5c1737e; str={"st_value"};
      >> ptr[226]=0x005611f5c17387; str={"__uid_t"};
      >> ptr[227]=0x005611f5c1738f; str={"st_size"};
      >> ptr[228]=0x005611f5c17397; str={"func_sect_debug_line"};
      >> ptr[229]=0x005611f5c173ac; str={"st_uid"};
      >> ptr[230]=0x005611f5c173b3; str={"__off_t"};
      >> ptr[231]=0x005611f5c173bb; str={"_ISblank"};
      >> ptr[232]=0x005611f5c173c4; str={"st_dev"};
      >> ptr[233]=0x005611f5c173cb; str={"pSectHeadersData"};
      >> ptr[234]=0x005611f5c173dc; str={"short unsigned int"};
      >> ptr[235]=0x005611f5c173ef; str={"xlog_mutex_lock"};
      >> ptr[236]=0x005611f5c173ff; str={"main"};
      >> ptr[237]=0x005611f5c17404; str={"hFile"};
      >> ptr[238]=0x005611f5c1740a; str={"__builtin_va_list"};
      >> ptr[239]=0x005611f5c1741c; str={"S_ELF64_ProgHeader_t"};
      >> ptr[240]=0x005611f5c17431; str={"func_sect_dynamic"};
      >> ptr[241]=0x005611f5c17443; str={"__func__"};
      >> ptr[242]=0x005611f5c1744c; str={"ppSectHeaders"};
      >> ptr[243]=0x005611f5c1745a; str={"Elf64_Sxword"};
      >> ptr[244]=0x005611f5c17467; str={"__blkcnt_t"};
      >> ptr[245]=0x005611f5c17472; str={"iLen"};
      >> ptr[246]=0x005611f5c17477; str={"_chain"};
      >> ptr[247]=0x005611f5c1747e; str={"_ISupper"};
      >> ptr[248]=0x005611f5c17487; str={"st_rdev"};
      >> ptr[249]=0x005611f5c1748f; str={"sh_addralign"};
      >> ptr[250]=0x005611f5c1749c; str={"Elf64_Word"};
      >> ptr[251]=0x005611f5c174a7; str={"_flags2"};
      >> ptr[252]=0x005611f5c174af; str={"st_name"};
      >> ptr[253]=0x005611f5c174b7; str={"pSecReladynBody"};
      >> ptr[254]=0x005611f5c174c7; str={"PrtProgHeader"};
      >> ptr[255]=0x005611f5c174d5; str={"_cur_column"};
      >> ptr[256]=0x005611f5c174e1; str={"myreadelf-0.1.07.c"};
      >> ptr[257]=0x005611f5c174f4; str={"pDataStart"};
      >> ptr[258]=0x005611f5c174ff; str={"__off64_t"};
      >> ptr[259]=0x005611f5c17509; str={"_unused2"};
      >> ptr[260]=0x005611f5c17512; str={"_IO_buf_base"};
      >> ptr[261]=0x005611f5c1753c; str={""};
      ===========================================================


  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=33,sect_name=".symtab",pSectData=0x5611f5c17520,iLen=0x1350}
    >> func{func_sect_symtab:(00674)} is call .

  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=34,sect_name=".strtab",pSectData=0x5611f5c18870,iLen=0xaaf}
    >> func{func_sect_strtab:(00867)} is call .
        No.[34]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x5611f5c19d00
        {
             Elf64_Word    sh_name      = 0x9;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xdfe0;
             Elf64_Xword   sh_size      = 0xaaf;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x005611f5c18870|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 63 72 74 73 74 75 66  66 2e 63 00 64 65 72 65|.crtstuff.c.dere|
      0x00000010|67 69 73 74 65 72 5f 74  6d 5f 63 6c 6f 6e 65 73|gister_tm_clones|
      0x00000020|00 5f 5f 64 6f 5f 67 6c  6f 62 61 6c 5f 64 74 6f|.__do_global_dto|
      0x00000030|72 73 5f 61 75 78 00 63  6f 6d 70 6c 65 74 65 64|rs_aux.completed|
      0x00000040|2e 38 30 36 31 00 5f 5f  64 6f 5f 67 6c 6f 62 61|.8061.__do_globa|
      0x00000050|6c 5f 64 74 6f 72 73 5f  61 75 78 5f 66 69 6e 69|l_dtors_aux_fini|
      0x00000060|5f 61 72 72 61 79 5f 65  6e 74 72 79 00 66 72 61|_array_entry.fra|
      0x00000070|6d 65 5f 64 75 6d 6d 79  00 5f 5f 66 72 61 6d 65|me_dummy.__frame|
      0x00000080|5f 64 75 6d 6d 79 5f 69  6e 69 74 5f 61 72 72 61|_dummy_init_arra|
      0x00000090|79 5f 65 6e 74 72 79 00  6d 79 72 65 61 64 65 6c|y_entry.myreadel|
      0x000000a0|66 2d 30 2e 31 2e 30 37  2e 63 00 5f 5f 66 75 6e|f-0.1.07.c.__fun|
      0x000000b0|63 5f 5f 2e 32 35 30 34  00 5f 5f 66 75 6e 63 5f|c__.2504.__func_|
      0x000000c0|5f 2e 32 35 32 32 00 5f  5f 50 52 45 54 54 59 5f|_.2522.__PRETTY_|
      0x000000d0|46 55 4e 43 54 49 4f 4e  5f 5f 2e 32 35 32 36 00|FUNCTION__.2526.|
      0x000000e0|5f 5f 66 75 6e 63 5f 5f  2e 32 35 34 35 00 5f 5f|__func__.2545.__|
      0x000000f0|50 52 45 54 54 59 5f 46  55 4e 43 54 49 4f 4e 5f|PRETTY_FUNCTION_|
      0x00000100|5f 2e 32 35 34 39 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2549.__func__.|
      0x00000110|32 37 38 36 00 5f 5f 66  75 6e 63 5f 5f 2e 32 37|2786.__func__.27|
      0x00000120|39 34 00 5f 5f 66 75 6e  63 5f 5f 2e 32 38 30 32|94.__func__.2802|
      0x00000130|00 5f 5f 66 75 6e 63 5f  5f 2e 32 38 31 30 00 5f|.__func__.2810._|
      0x00000140|5f 66 75 6e 63 5f 5f 2e  32 38 31 38 00 5f 5f 66|_func__.2818.__f|
      0x00000150|75 6e 63 5f 5f 2e 32 38  32 36 00 5f 5f 66 75 6e|unc__.2826.__fun|
      0x00000160|63 5f 5f 2e 32 38 33 34  00 5f 5f 66 75 6e 63 5f|c__.2834.__func_|
      0x00000170|5f 2e 32 38 34 32 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2842.__func__.|
      0x00000180|32 38 35 30 00 5f 5f 66  75 6e 63 5f 5f 2e 32 38|2850.__func__.28|
      0x00000190|35 38 00 5f 5f 66 75 6e  63 5f 5f 2e 32 38 36 36|58.__func__.2866|
      0x000001a0|00 5f 5f 66 75 6e 63 5f  5f 2e 32 38 37 34 00 5f|.__func__.2874._|
      0x000001b0|5f 66 75 6e 63 5f 5f 2e  32 38 38 32 00 5f 5f 66|_func__.2882.__f|
      0x000001c0|75 6e 63 5f 5f 2e 32 38  39 30 00 5f 5f 66 75 6e|unc__.2890.__fun|
      0x000001d0|63 5f 5f 2e 32 38 39 38  00 5f 5f 66 75 6e 63 5f|c__.2898.__func_|
      0x000001e0|5f 2e 32 39 30 36 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2906.__func__.|
      0x000001f0|32 39 31 34 00 5f 5f 66  75 6e 63 5f 5f 2e 32 39|2914.__func__.29|
      0x00000200|32 32 00 5f 5f 66 75 6e  63 5f 5f 2e 32 39 33 30|22.__func__.2930|
      0x00000210|00 5f 5f 66 75 6e 63 5f  5f 2e 32 39 33 38 00 5f|.__func__.2938._|
      0x00000220|5f 66 75 6e 63 5f 5f 2e  32 39 34 36 00 5f 5f 66|_func__.2946.__f|
      0x00000230|75 6e 63 5f 5f 2e 32 39  35 34 00 5f 5f 66 75 6e|unc__.2954.__fun|
      0x00000240|63 5f 5f 2e 32 39 36 32  00 5f 5f 66 75 6e 63 5f|c__.2962.__func_|
      0x00000250|5f 2e 32 39 37 30 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2970.__func__.|
      0x00000260|32 39 37 38 00 5f 5f 66  75 6e 63 5f 5f 2e 32 39|2978.__func__.29|
      0x00000270|38 36 00 5f 5f 66 75 6e  63 5f 5f 2e 32 39 39 34|86.__func__.2994|
      0x00000280|00 5f 5f 66 75 6e 63 5f  5f 2e 33 30 30 32 00 5f|.__func__.3002._|
      0x00000290|5f 66 75 6e 63 5f 5f 2e  33 30 31 30 00 5f 5f 66|_func__.3010.__f|
      0x000002a0|75 6e 63 5f 5f 2e 33 30  31 38 00 5f 5f 66 75 6e|unc__.3018.__fun|
      0x000002b0|63 5f 5f 2e 33 30 33 30  00 5f 5f 66 75 6e 63 5f|c__.3030.__func_|
      0x000002c0|5f 2e 33 30 36 31 00 5f  5f 66 75 6e 63 5f 5f 2e|_.3061.__func__.|
      0x000002d0|33 30 36 39 00 5f 5f 66  75 6e 63 5f 5f 2e 33 30|3069.__func__.30|
      0x000002e0|38 34 00 5f 5f 66 75 6e  63 5f 5f 2e 33 30 39 32|84.__func__.3092|
      0x000002f0|00 5f 5f 66 75 6e 63 5f  5f 2e 33 31 30 30 00 5f|.__func__.3100._|
      0x00000300|5f 66 75 6e 63 5f 5f 2e  33 31 31 37 00 5f 5f 66|_func__.3117.__f|
      0x00000310|75 6e 63 5f 5f 2e 33 31  32 35 00 5f 5f 66 75 6e|unc__.3125.__fun|
      0x00000320|63 5f 5f 2e 33 31 34 34  00 5f 5f 66 75 6e 63 5f|c__.3144.__func_|
      0x00000330|5f 2e 33 31 37 30 00 5f  5f 66 75 6e 63 5f 5f 2e|_.3170.__func__.|
      0x00000340|33 31 37 34 00 5f 5f 66  75 6e 63 5f 5f 2e 33 31|3174.__func__.31|
      0x00000350|39 30 00 5f 5f 66 75 6e  63 5f 5f 2e 33 31 39 34|90.__func__.3194|
      0x00000360|00 5f 5f 66 75 6e 63 5f  5f 2e 33 31 39 38 00 5f|.__func__.3198._|
      0x00000370|5f 66 75 6e 63 5f 5f 2e  33 32 30 32 00 5f 5f 66|_func__.3202.__f|
      0x00000380|75 6e 63 5f 5f 2e 33 32  30 36 00 5f 5f 66 75 6e|unc__.3206.__fun|
      0x00000390|63 5f 5f 2e 33 32 31 30  00 5f 5f 66 75 6e 63 5f|c__.3210.__func_|
      0x000003a0|5f 2e 33 32 31 35 00 5f  5f 46 52 41 4d 45 5f 45|_.3215.__FRAME_E|
      0x000003b0|4e 44 5f 5f 00 5f 5f 69  6e 69 74 5f 61 72 72 61|ND__.__init_arra|
      0x000003c0|79 5f 65 6e 64 00 5f 44  59 4e 41 4d 49 43 00 5f|y_end._DYNAMIC._|
      0x000003d0|5f 69 6e 69 74 5f 61 72  72 61 79 5f 73 74 61 72|_init_array_star|
      0x000003e0|74 00 5f 5f 47 4e 55 5f  45 48 5f 46 52 41 4d 45|t.__GNU_EH_FRAME|
      0x000003f0|5f 48 44 52 00 5f 47 4c  4f 42 41 4c 5f 4f 46 46|_HDR._GLOBAL_OFF|
      0x00000400|53 45 54 5f 54 41 42 4c  45 5f 00 5f 5f 6c 69 62|SET_TABLE_.__lib|
      0x00000410|63 5f 63 73 75 5f 66 69  6e 69 00 66 75 6e 63 5f|c_csu_fini.func_|
      0x00000420|73 65 63 74 5f 6e 6f 74  65 5f 67 6e 75 5f 70 72|sect_note_gnu_pr|
      0x00000430|6f 70 65 00 78 6c 6f 67  5f 6d 75 74 65 78 5f 6c|ope.xlog_mutex_l|
      0x00000440|6f 63 6b 00 66 75 6e 63  5f 73 65 63 74 5f 64 61|ock.func_sect_da|
      0x00000450|74 61 00 78 6c 6f 67 5f  6d 75 74 65 78 5f 75 6e|ta.xlog_mutex_un|
      0x00000460|6c 6f 63 6b 00 5f 5f 73  74 61 74 00 66 72 65 65|lock.__stat.free|
      0x00000470|40 40 47 4c 49 42 43 5f  32 2e 32 2e 35 00 66 75|@@GLIBC_2.2.5.fu|
      0x00000480|6e 63 5f 73 65 63 74 5f  70 6c 74 00 66 75 6e 63|nc_sect_plt.func|
      0x00000490|5f 73 65 63 74 5f 6e 6f  74 65 5f 41 42 49 5f 74|_sect_note_ABI_t|
      0x000004a0|61 67 00 5f 49 54 4d 5f  64 65 72 65 67 69 73 74|ag._ITM_deregist|
      0x000004b0|65 72 54 4d 43 6c 6f 6e  65 54 61 62 6c 65 00 73|erTMCloneTable.s|
      0x000004c0|74 64 6f 75 74 40 40 47  4c 49 42 43 5f 32 2e 32|tdout@@GLIBC_2.2|
      0x000004d0|2e 35 00 66 75 6e 63 5f  73 65 63 74 5f 64 65 62|.5.func_sect_deb|
      0x000004e0|75 67 5f 61 72 61 6e 67  65 73 00 66 75 6e 63 5f|ug_aranges.func_|
      0x000004f0|73 65 63 74 5f 66 69 6e  69 5f 61 72 72 61 79 00|sect_fini_array.|
      0x00000500|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
      0x00000510|5f 62 6f 64 79 73 00 66  72 65 61 64 40 40 47 4c|_bodys.fread@@GL|
      0x00000520|49 42 43 5f 32 2e 32 2e  35 00 6d 79 5f 66 69 6e|IBC_2.2.5.my_fin|
      0x00000530|69 30 31 00 6d 79 5f 66  69 6e 69 30 33 00 70 61|i01.my_fini03.pa|
      0x00000540|72 73 65 5f 65 6c 66 36  34 5f 70 72 6f 67 5f 68|rse_elf64_prog_h|
      0x00000550|65 61 64 65 72 00 66 75  6e 63 5f 73 65 63 74 5f|eader.func_sect_|
      0x00000560|63 6f 6d 6d 65 6e 74 00  78 6c 6f 67 5f 68 65 78|comment.xlog_hex|
      0x00000570|64 75 6d 70 00 66 75 6e  63 5f 73 65 63 74 5f 64|dump.func_sect_d|
      0x00000580|65 62 75 67 5f 73 74 72  00 78 6c 6f 67 5f 69 6e|ebug_str.xlog_in|
      0x00000590|66 6f 5f 78 00 66 75 6e  63 5f 73 65 63 74 5f 73|fo_x.func_sect_s|
      0x000005a0|68 73 74 72 74 61 62 00  5f 65 64 61 74 61 00 66|hstrtab._edata.f|
      0x000005b0|75 6e 63 5f 73 65 63 74  5f 70 6c 74 5f 67 6f 74|unc_sect_plt_got|
      0x000005c0|00 50 72 74 50 72 6f 67  48 65 61 64 65 72 00 66|.PrtProgHeader.f|
      0x000005d0|63 6c 6f 73 65 40 40 47  4c 49 42 43 5f 32 2e 32|close@@GLIBC_2.2|
      0x000005e0|2e 35 00 66 75 6e 63 5f  73 65 63 74 5f 64 65 62|.5.func_sect_deb|
      0x000005f0|75 67 5f 61 62 62 72 65  76 00 66 75 6e 63 5f 73|ug_abbrev.func_s|
      0x00000600|65 63 74 5f 67 6e 75 5f  76 65 72 73 69 6f 6e 5f|ect_gnu_version_|
      0x00000610|72 00 5f 5f 73 74 61 63  6b 5f 63 68 6b 5f 66 61|r.__stack_chk_fa|
      0x00000620|69 6c 40 40 47 4c 49 42  43 5f 32 2e 34 00 6d 79|il@@GLIBC_2.4.my|
      0x00000630|5f 69 6e 69 74 30 32 00  66 75 6e 63 5f 73 65 63|_init02.func_sec|
      0x00000640|74 5f 64 79 6e 73 74 72  00 66 75 6e 63 5f 73 65|t_dynstr.func_se|
      0x00000650|63 74 5f 64 65 62 75 67  5f 69 6e 66 6f 00 5f 5f|ct_debug_info.__|
      0x00000660|61 73 73 65 72 74 5f 66  61 69 6c 40 40 47 4c 49|assert_fail@@GLI|
      0x00000670|42 43 5f 32 2e 32 2e 35  00 66 75 6e 63 5f 73 65|BC_2.2.5.func_se|
      0x00000680|63 74 5f 6e 6f 74 65 5f  67 6e 75 5f 62 75 69 6c|ct_note_gnu_buil|
      0x00000690|64 5f 69 64 00 66 75 6e  63 5f 73 65 63 74 5f 73|d_id.func_sect_s|
      0x000006a0|74 72 74 61 62 00 70 61  72 73 65 5f 61 72 67 73|trtab.parse_args|
      0x000006b0|00 5f 5f 6c 69 62 63 5f  73 74 61 72 74 5f 6d 61|.__libc_start_ma|
      0x000006c0|69 6e 40 40 47 4c 49 42  43 5f 32 2e 32 2e 35 00|in@@GLIBC_2.2.5.|
      0x000006d0|63 61 6c 6c 6f 63 40 40  47 4c 49 42 43 5f 32 2e|calloc@@GLIBC_2.|
      0x000006e0|32 2e 35 00 70 61 72 73  65 5f 65 6c 66 36 34 5f|2.5.parse_elf64_|
      0x000006f0|73 65 63 74 5f 68 65 61  64 65 72 73 00 5f 5f 64|sect_headers.__d|
      0x00000700|61 74 61 5f 73 74 61 72  74 00 73 74 72 63 6d 70|ata_start.strcmp|
      0x00000710|40 40 47 4c 49 42 43 5f  32 2e 32 2e 35 00 66 75|@@GLIBC_2.2.5.fu|
      0x00000720|6e 63 5f 73 65 63 74 5f  67 6e 75 5f 68 61 73 68|nc_sect_gnu_hash|
      0x00000730|00 66 75 6e 63 5f 73 65  63 74 5f 73 79 6d 74 61|.func_sect_symta|
      0x00000740|62 00 66 75 6e 63 5f 70  72 6f 63 65 73 73 00 66|b.func_process.f|
      0x00000750|75 6e 63 5f 73 65 63 74  5f 72 65 6c 61 5f 64 79|unc_sect_rela_dy|
      0x00000760|6e 00 5f 5f 67 6d 6f 6e  5f 73 74 61 72 74 5f 5f|n.__gmon_start__|
      0x00000770|00 66 75 6e 63 5f 73 65  63 74 5f 66 69 6e 69 00|.func_sect_fini.|
      0x00000780|5f 5f 64 73 6f 5f 68 61  6e 64 6c 65 00 66 75 6e|__dso_handle.fun|
      0x00000790|63 5f 73 65 63 74 5f 69  6e 69 74 5f 61 72 72 61|c_sect_init_arra|
      0x000007a0|79 00 5f 49 4f 5f 73 74  64 69 6e 5f 75 73 65 64|y._IO_stdin_used|
      0x000007b0|00 66 75 6e 63 5f 73 65  63 74 5f 67 6e 75 5f 76|.func_sect_gnu_v|
      0x000007c0|65 72 73 69 6f 6e 00 5f  5f 78 73 74 61 74 40 40|ersion.__xstat@@|
      0x000007d0|47 4c 49 42 43 5f 32 2e  32 2e 35 00 78 6c 6f 67|GLIBC_2.2.5.xlog|
      0x000007e0|5f 69 6e 69 74 00 50 72  74 53 65 63 74 48 65 61|_init.PrtSectHea|
      0x000007f0|64 65 72 00 44 75 6d 70  50 74 72 32 53 74 72 00|der.DumpPtr2Str.|
      0x00000800|5f 5f 6c 69 62 63 5f 63  73 75 5f 69 6e 69 74 00|__libc_csu_init.|
      0x00000810|6d 61 6c 6c 6f 63 40 40  47 4c 49 42 43 5f 32 2e|malloc@@GLIBC_2.|
      0x00000820|32 2e 35 00 66 66 6c 75  73 68 40 40 47 4c 49 42|2.5.fflush@@GLIB|
      0x00000830|43 5f 32 2e 32 2e 35 00  70 61 72 73 65 5f 65 6c|C_2.2.5.parse_el|
      0x00000840|66 36 34 5f 70 72 6f 67  5f 68 65 61 64 65 72 73|f64_prog_headers|
      0x00000850|00 62 75 69 6c 64 5f 65  6c 66 36 34 5f 6f 62 6a|.build_elf64_obj|
      0x00000860|00 78 6c 6f 67 5f 75 6e  69 6e 69 74 00 73 65 63|.xlog_uninit.sec|
      0x00000870|74 5f 66 75 6e 63 73 00  61 66 74 65 72 5f 6d 61|t_funcs.after_ma|
      0x00000880|69 6e 5f 66 75 6e 63 00  76 70 72 69 6e 74 66 40|in_func.vprintf@|
      0x00000890|40 47 4c 49 42 43 5f 32  2e 32 2e 35 00 67 65 74|@GLIBC_2.2.5.get|
      0x000008a0|5f 65 6c 66 36 34 5f 64  61 74 61 00 66 75 6e 63|_elf64_data.func|
      0x000008b0|5f 73 65 63 74 5f 69 6e  74 65 72 70 00 6d 79 5f|_sect_interp.my_|
      0x000008c0|66 69 6e 69 30 32 00 66  75 6e 63 5f 73 65 63 74|fini02.func_sect|
      0x000008d0|5f 65 68 5f 66 72 61 6d  65 5f 68 64 72 00 66 75|_eh_frame_hdr.fu|
      0x000008e0|6e 63 5f 73 65 63 74 5f  74 65 78 74 00 5f 5f 62|nc_sect_text.__b|
      0x000008f0|73 73 5f 73 74 61 72 74  00 6d 61 69 6e 00 66 75|ss_start.main.fu|
      0x00000900|6e 63 5f 73 65 63 74 5f  65 68 5f 66 72 61 6d 65|nc_sect_eh_frame|
      0x00000910|00 66 75 6e 63 5f 73 65  63 74 5f 72 6f 64 61 74|.func_sect_rodat|
      0x00000920|61 00 6d 79 5f 69 6e 69  74 30 33 00 6d 79 5f 69|a.my_init03.my_i|
      0x00000930|6e 69 74 30 31 00 66 6f  70 65 6e 40 40 47 4c 49|nit01.fopen@@GLI|
      0x00000940|42 43 5f 32 2e 32 2e 35  00 62 65 66 6f 72 65 5f|BC_2.2.5.before_|
      0x00000950|6d 61 69 6e 5f 66 75 6e  63 00 70 61 72 73 65 5f|main_func.parse_|
      0x00000960|65 6c 66 36 34 5f 65 6c  66 5f 68 65 61 64 65 72|elf64_elf_header|
      0x00000970|00 66 75 6e 63 5f 73 65  63 74 5f 67 6f 74 5f 70|.func_sect_got_p|
      0x00000980|6c 74 00 66 75 6e 63 5f  73 65 63 74 5f 72 65 6c|lt.func_sect_rel|
      0x00000990|61 5f 70 6c 74 00 78 6c  6f 67 5f 63 6f 72 65 00|a_plt.xlog_core.|
      0x000009a0|5f 5f 54 4d 43 5f 45 4e  44 5f 5f 00 70 61 72 73|__TMC_END__.pars|
      0x000009b0|65 5f 65 6c 66 36 34 5f  73 65 63 74 5f 68 65 61|e_elf64_sect_hea|
      0x000009c0|64 65 72 00 5f 49 54 4d  5f 72 65 67 69 73 74 65|der._ITM_registe|
      0x000009d0|72 54 4d 43 6c 6f 6e 65  54 61 62 6c 65 00 70 61|rTMCloneTable.pa|
      0x000009e0|72 73 65 5f 65 6c 66 36  34 5f 73 65 63 74 5f 62|rse_elf64_sect_b|
      0x000009f0|6f 64 79 00 66 75 6e 63  5f 73 65 63 74 5f 67 6f|ody.func_sect_go|
      0x00000a00|74 00 66 75 6e 63 5f 73  65 63 74 5f 64 79 6e 73|t.func_sect_dyns|
      0x00000a10|79 6d 00 66 75 6e 63 5f  73 65 63 74 5f 69 6e 69|ym.func_sect_ini|
      0x00000a20|74 00 78 6c 6f 67 5f 69  6e 66 6f 00 66 75 6e 63|t.xlog_info.func|
      0x00000a30|5f 73 65 63 74 5f 6e 6f  74 65 5f 67 6e 75 5f 62|_sect_note_gnu_b|
      0x00000a40|75 69 6c 64 00 66 75 6e  63 5f 73 65 63 74 5f 64|uild.func_sect_d|
      0x00000a50|65 62 75 67 5f 6c 69 6e  65 00 5f 5f 63 78 61 5f|ebug_line.__cxa_|
      0x00000a60|66 69 6e 61 6c 69 7a 65  40 40 47 4c 49 42 43 5f|finalize@@GLIBC_|
      0x00000a70|32 2e 32 2e 35 00 66 75  6e 63 5f 73 65 63 74 5f|2.2.5.func_sect_|
      0x00000a80|64 79 6e 61 6d 69 63 00  5f 5f 63 74 79 70 65 5f|dynamic.__ctype_|
      0x00000a90|62 5f 6c 6f 63 40 40 47  4c 49 42 43 5f 32 2e 33|b_loc@@GLIBC_2.3|
      0x00000aa0|00 66 75 6e 63 5f 73 65  63 74 5f 62 73 73 00 **|.func_sect_bss.*|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x005611f5c18871; str={"crtstuff.c"};
      >> ptr[001]=0x005611f5c1887c; str={"deregister_tm_clones"};
      >> ptr[002]=0x005611f5c18891; str={"__do_global_dtors_aux"};
      >> ptr[003]=0x005611f5c188a7; str={"completed.8061"};
      >> ptr[004]=0x005611f5c188b6; str={"__do_global_dtors_aux_fini_array_entry"};
      >> ptr[005]=0x005611f5c188dd; str={"frame_dummy"};
      >> ptr[006]=0x005611f5c188e9; str={"__frame_dummy_init_array_entry"};
      >> ptr[007]=0x005611f5c18908; str={"myreadelf-0.1.07.c"};
      >> ptr[008]=0x005611f5c1891b; str={"__func__.2504"};
      >> ptr[009]=0x005611f5c18929; str={"__func__.2522"};
      >> ptr[010]=0x005611f5c18937; str={"__PRETTY_FUNCTION__.2526"};
      >> ptr[011]=0x005611f5c18950; str={"__func__.2545"};
      >> ptr[012]=0x005611f5c1895e; str={"__PRETTY_FUNCTION__.2549"};
      >> ptr[013]=0x005611f5c18977; str={"__func__.2786"};
      >> ptr[014]=0x005611f5c18985; str={"__func__.2794"};
      >> ptr[015]=0x005611f5c18993; str={"__func__.2802"};
      >> ptr[016]=0x005611f5c189a1; str={"__func__.2810"};
      >> ptr[017]=0x005611f5c189af; str={"__func__.2818"};
      >> ptr[018]=0x005611f5c189bd; str={"__func__.2826"};
      >> ptr[019]=0x005611f5c189cb; str={"__func__.2834"};
      >> ptr[020]=0x005611f5c189d9; str={"__func__.2842"};
      >> ptr[021]=0x005611f5c189e7; str={"__func__.2850"};
      >> ptr[022]=0x005611f5c189f5; str={"__func__.2858"};
      >> ptr[023]=0x005611f5c18a03; str={"__func__.2866"};
      >> ptr[024]=0x005611f5c18a11; str={"__func__.2874"};
      >> ptr[025]=0x005611f5c18a1f; str={"__func__.2882"};
      >> ptr[026]=0x005611f5c18a2d; str={"__func__.2890"};
      >> ptr[027]=0x005611f5c18a3b; str={"__func__.2898"};
      >> ptr[028]=0x005611f5c18a49; str={"__func__.2906"};
      >> ptr[029]=0x005611f5c18a57; str={"__func__.2914"};
      >> ptr[030]=0x005611f5c18a65; str={"__func__.2922"};
      >> ptr[031]=0x005611f5c18a73; str={"__func__.2930"};
      >> ptr[032]=0x005611f5c18a81; str={"__func__.2938"};
      >> ptr[033]=0x005611f5c18a8f; str={"__func__.2946"};
      >> ptr[034]=0x005611f5c18a9d; str={"__func__.2954"};
      >> ptr[035]=0x005611f5c18aab; str={"__func__.2962"};
      >> ptr[036]=0x005611f5c18ab9; str={"__func__.2970"};
      >> ptr[037]=0x005611f5c18ac7; str={"__func__.2978"};
      >> ptr[038]=0x005611f5c18ad5; str={"__func__.2986"};
      >> ptr[039]=0x005611f5c18ae3; str={"__func__.2994"};
      >> ptr[040]=0x005611f5c18af1; str={"__func__.3002"};
      >> ptr[041]=0x005611f5c18aff; str={"__func__.3010"};
      >> ptr[042]=0x005611f5c18b0d; str={"__func__.3018"};
      >> ptr[043]=0x005611f5c18b1b; str={"__func__.3030"};
      >> ptr[044]=0x005611f5c18b29; str={"__func__.3061"};
      >> ptr[045]=0x005611f5c18b37; str={"__func__.3069"};
      >> ptr[046]=0x005611f5c18b45; str={"__func__.3084"};
      >> ptr[047]=0x005611f5c18b53; str={"__func__.3092"};
      >> ptr[048]=0x005611f5c18b61; str={"__func__.3100"};
      >> ptr[049]=0x005611f5c18b6f; str={"__func__.3117"};
      >> ptr[050]=0x005611f5c18b7d; str={"__func__.3125"};
      >> ptr[051]=0x005611f5c18b8b; str={"__func__.3144"};
      >> ptr[052]=0x005611f5c18b99; str={"__func__.3170"};
      >> ptr[053]=0x005611f5c18ba7; str={"__func__.3174"};
      >> ptr[054]=0x005611f5c18bb5; str={"__func__.3190"};
      >> ptr[055]=0x005611f5c18bc3; str={"__func__.3194"};
      >> ptr[056]=0x005611f5c18bd1; str={"__func__.3198"};
      >> ptr[057]=0x005611f5c18bdf; str={"__func__.3202"};
      >> ptr[058]=0x005611f5c18bed; str={"__func__.3206"};
      >> ptr[059]=0x005611f5c18bfb; str={"__func__.3210"};
      >> ptr[060]=0x005611f5c18c09; str={"__func__.3215"};
      >> ptr[061]=0x005611f5c18c17; str={"__FRAME_END__"};
      >> ptr[062]=0x005611f5c18c25; str={"__init_array_end"};
      >> ptr[063]=0x005611f5c18c36; str={"_DYNAMIC"};
      >> ptr[064]=0x005611f5c18c3f; str={"__init_array_start"};
      >> ptr[065]=0x005611f5c18c52; str={"__GNU_EH_FRAME_HDR"};
      >> ptr[066]=0x005611f5c18c65; str={"_GLOBAL_OFFSET_TABLE_"};
      >> ptr[067]=0x005611f5c18c7b; str={"__libc_csu_fini"};
      >> ptr[068]=0x005611f5c18c8b; str={"func_sect_note_gnu_prope"};
      >> ptr[069]=0x005611f5c18ca4; str={"xlog_mutex_lock"};
      >> ptr[070]=0x005611f5c18cb4; str={"func_sect_data"};
      >> ptr[071]=0x005611f5c18cc3; str={"xlog_mutex_unlock"};
      >> ptr[072]=0x005611f5c18cd5; str={"__stat"};
      >> ptr[073]=0x005611f5c18cdc; str={"free@@GLIBC_2.2.5"};
      >> ptr[074]=0x005611f5c18cee; str={"func_sect_plt"};
      >> ptr[075]=0x005611f5c18cfc; str={"func_sect_note_ABI_tag"};
      >> ptr[076]=0x005611f5c18d13; str={"_ITM_deregisterTMCloneTable"};
      >> ptr[077]=0x005611f5c18d2f; str={"stdout@@GLIBC_2.2.5"};
      >> ptr[078]=0x005611f5c18d43; str={"func_sect_debug_aranges"};
      >> ptr[079]=0x005611f5c18d5b; str={"func_sect_fini_array"};
      >> ptr[080]=0x005611f5c18d70; str={"parse_elf64_sect_bodys"};
      >> ptr[081]=0x005611f5c18d87; str={"fread@@GLIBC_2.2.5"};
      >> ptr[082]=0x005611f5c18d9a; str={"my_fini01"};
      >> ptr[083]=0x005611f5c18da4; str={"my_fini03"};
      >> ptr[084]=0x005611f5c18dae; str={"parse_elf64_prog_header"};
      >> ptr[085]=0x005611f5c18dc6; str={"func_sect_comment"};
      >> ptr[086]=0x005611f5c18dd8; str={"xlog_hexdump"};
      >> ptr[087]=0x005611f5c18de5; str={"func_sect_debug_str"};
      >> ptr[088]=0x005611f5c18df9; str={"xlog_info_x"};
      >> ptr[089]=0x005611f5c18e05; str={"func_sect_shstrtab"};
      >> ptr[090]=0x005611f5c18e18; str={"_edata"};
      >> ptr[091]=0x005611f5c18e1f; str={"func_sect_plt_got"};
      >> ptr[092]=0x005611f5c18e31; str={"PrtProgHeader"};
      >> ptr[093]=0x005611f5c18e3f; str={"fclose@@GLIBC_2.2.5"};
      >> ptr[094]=0x005611f5c18e53; str={"func_sect_debug_abbrev"};
      >> ptr[095]=0x005611f5c18e6a; str={"func_sect_gnu_version_r"};
      >> ptr[096]=0x005611f5c18e82; str={"__stack_chk_fail@@GLIBC_2.4"};
      >> ptr[097]=0x005611f5c18e9e; str={"my_init02"};
      >> ptr[098]=0x005611f5c18ea8; str={"func_sect_dynstr"};
      >> ptr[099]=0x005611f5c18eb9; str={"func_sect_debug_info"};
      >> ptr[100]=0x005611f5c18ece; str={"__assert_fail@@GLIBC_2.2.5"};
      >> ptr[101]=0x005611f5c18ee9; str={"func_sect_note_gnu_build_id"};
      >> ptr[102]=0x005611f5c18f05; str={"func_sect_strtab"};
      >> ptr[103]=0x005611f5c18f16; str={"parse_args"};
      >> ptr[104]=0x005611f5c18f21; str={"__libc_start_main@@GLIBC_2.2.5"};
      >> ptr[105]=0x005611f5c18f40; str={"calloc@@GLIBC_2.2.5"};
      >> ptr[106]=0x005611f5c18f54; str={"parse_elf64_sect_headers"};
      >> ptr[107]=0x005611f5c18f6d; str={"__data_start"};
      >> ptr[108]=0x005611f5c18f7a; str={"strcmp@@GLIBC_2.2.5"};
      >> ptr[109]=0x005611f5c18f8e; str={"func_sect_gnu_hash"};
      >> ptr[110]=0x005611f5c18fa1; str={"func_sect_symtab"};
      >> ptr[111]=0x005611f5c18fb2; str={"func_process"};
      >> ptr[112]=0x005611f5c18fbf; str={"func_sect_rela_dyn"};
      >> ptr[113]=0x005611f5c18fd2; str={"__gmon_start__"};
      >> ptr[114]=0x005611f5c18fe1; str={"func_sect_fini"};
      >> ptr[115]=0x005611f5c18ff0; str={"__dso_handle"};
      >> ptr[116]=0x005611f5c18ffd; str={"func_sect_init_array"};
      >> ptr[117]=0x005611f5c19012; str={"_IO_stdin_used"};
      >> ptr[118]=0x005611f5c19021; str={"func_sect_gnu_version"};
      >> ptr[119]=0x005611f5c19037; str={"__xstat@@GLIBC_2.2.5"};
      >> ptr[120]=0x005611f5c1904c; str={"xlog_init"};
      >> ptr[121]=0x005611f5c19056; str={"PrtSectHeader"};
      >> ptr[122]=0x005611f5c19064; str={"DumpPtr2Str"};
      >> ptr[123]=0x005611f5c19070; str={"__libc_csu_init"};
      >> ptr[124]=0x005611f5c19080; str={"malloc@@GLIBC_2.2.5"};
      >> ptr[125]=0x005611f5c19094; str={"fflush@@GLIBC_2.2.5"};
      >> ptr[126]=0x005611f5c190a8; str={"parse_elf64_prog_headers"};
      >> ptr[127]=0x005611f5c190c1; str={"build_elf64_obj"};
      >> ptr[128]=0x005611f5c190d1; str={"xlog_uninit"};
      >> ptr[129]=0x005611f5c190dd; str={"sect_funcs"};
      >> ptr[130]=0x005611f5c190e8; str={"after_main_func"};
      >> ptr[131]=0x005611f5c190f8; str={"vprintf@@GLIBC_2.2.5"};
      >> ptr[132]=0x005611f5c1910d; str={"get_elf64_data"};
      >> ptr[133]=0x005611f5c1911c; str={"func_sect_interp"};
      >> ptr[134]=0x005611f5c1912d; str={"my_fini02"};
      >> ptr[135]=0x005611f5c19137; str={"func_sect_eh_frame_hdr"};
      >> ptr[136]=0x005611f5c1914e; str={"func_sect_text"};
      >> ptr[137]=0x005611f5c1915d; str={"__bss_start"};
      >> ptr[138]=0x005611f5c19169; str={"main"};
      >> ptr[139]=0x005611f5c1916e; str={"func_sect_eh_frame"};
      >> ptr[140]=0x005611f5c19181; str={"func_sect_rodata"};
      >> ptr[141]=0x005611f5c19192; str={"my_init03"};
      >> ptr[142]=0x005611f5c1919c; str={"my_init01"};
      >> ptr[143]=0x005611f5c191a6; str={"fopen@@GLIBC_2.2.5"};
      >> ptr[144]=0x005611f5c191b9; str={"before_main_func"};
      >> ptr[145]=0x005611f5c191ca; str={"parse_elf64_elf_header"};
      >> ptr[146]=0x005611f5c191e1; str={"func_sect_got_plt"};
      >> ptr[147]=0x005611f5c191f3; str={"func_sect_rela_plt"};
      >> ptr[148]=0x005611f5c19206; str={"xlog_core"};
      >> ptr[149]=0x005611f5c19210; str={"__TMC_END__"};
      >> ptr[150]=0x005611f5c1921c; str={"parse_elf64_sect_header"};
      >> ptr[151]=0x005611f5c19234; str={"_ITM_registerTMCloneTable"};
      >> ptr[152]=0x005611f5c1924e; str={"parse_elf64_sect_body"};
      >> ptr[153]=0x005611f5c19264; str={"func_sect_got"};
      >> ptr[154]=0x005611f5c19272; str={"func_sect_dynsym"};
      >> ptr[155]=0x005611f5c19283; str={"func_sect_init"};
      >> ptr[156]=0x005611f5c19292; str={"xlog_info"};
      >> ptr[157]=0x005611f5c1929c; str={"func_sect_note_gnu_build"};
      >> ptr[158]=0x005611f5c192b5; str={"func_sect_debug_line"};
      >> ptr[159]=0x005611f5c192ca; str={"__cxa_finalize@@GLIBC_2.2.5"};
      >> ptr[160]=0x005611f5c192e6; str={"func_sect_dynamic"};
      >> ptr[161]=0x005611f5c192f8; str={"__ctype_b_loc@@GLIBC_2.3"};
      >> ptr[162]=0x005611f5c19311; str={"func_sect_bss"};
      >> ptr[163]=0x005611f5c19320; str={".symtab"};
      ===========================================================


  >> func{parse_elf64_sect_body:(00954)} is call. 
      {idx=35,sect_name=".shstrtab",pSectData=0x5611f5c1931f,iLen=0x15a}
    >> func{func_sect_shstrtab:(00880)} is call .
        No.[35]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x5611f5c19d40
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xea8f;
             Elf64_Xword   sh_size      = 0x15a;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x005611f5c1931f|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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

      ===========================================================
      >> ptr[000]=0x005611f5c19320; str={".symtab"};
      >> ptr[001]=0x005611f5c19328; str={".strtab"};
      >> ptr[002]=0x005611f5c19330; str={".shstrtab"};
      >> ptr[003]=0x005611f5c1933a; str={".interp"};
      >> ptr[004]=0x005611f5c19342; str={".note.gnu.property"};
      >> ptr[005]=0x005611f5c19355; str={".note.gnu.build-id"};
      >> ptr[006]=0x005611f5c19368; str={".note.ABI-tag"};
      >> ptr[007]=0x005611f5c19376; str={".gnu.hash"};
      >> ptr[008]=0x005611f5c19380; str={".dynsym"};
      >> ptr[009]=0x005611f5c19388; str={".dynstr"};
      >> ptr[010]=0x005611f5c19390; str={".gnu.version"};
      >> ptr[011]=0x005611f5c1939d; str={".gnu.version_r"};
      >> ptr[012]=0x005611f5c193ac; str={".rela.dyn"};
      >> ptr[013]=0x005611f5c193b6; str={".rela.plt"};
      >> ptr[014]=0x005611f5c193c0; str={".init"};
      >> ptr[015]=0x005611f5c193c6; str={".plt.got"};
      >> ptr[016]=0x005611f5c193cf; str={".plt.sec"};
      >> ptr[017]=0x005611f5c193d8; str={".text"};
      >> ptr[018]=0x005611f5c193de; str={".fini"};
      >> ptr[019]=0x005611f5c193e4; str={".rodata"};
      >> ptr[020]=0x005611f5c193ec; str={".eh_frame_hdr"};
      >> ptr[021]=0x005611f5c193fa; str={".eh_frame"};
      >> ptr[022]=0x005611f5c19404; str={".init_array"};
      >> ptr[023]=0x005611f5c19410; str={".fini_array"};
      >> ptr[024]=0x005611f5c1941c; str={".dynamic"};
      >> ptr[025]=0x005611f5c19425; str={".data"};
      >> ptr[026]=0x005611f5c1942b; str={".bss"};
      >> ptr[027]=0x005611f5c19430; str={".comment"};
      >> ptr[028]=0x005611f5c19439; str={".debug_aranges"};
      >> ptr[029]=0x005611f5c19448; str={".debug_info"};
      >> ptr[030]=0x005611f5c19454; str={".debug_abbrev"};
      >> ptr[031]=0x005611f5c19462; str={".debug_line"};
      >> ptr[032]=0x005611f5c1946e; str={".debug_str"};
      >> ptr[033]=0x005611f5c194c0; str={"};
      ===========================================================


  >> build_elf64_obj() exit;
  >> the app exit.
  >> func{my_fini03:(01131)@(myreadelf-0.1.07.c)} is call .
  #<<<<====
  >> func{my_fini02:(01119)@(myreadelf-0.1.07.c)} is call .
  #<<<<====
  >> func{my_fini01:(01107)@(myreadelf-0.1.07.c)} is call .
  #<<<<====
  >> func{after_main_func:(01087)@(myreadelf-0.1.07.c)} is call .
  #<<<<====
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 

#endif
