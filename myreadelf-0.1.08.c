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
int func_sect_plt_sec          (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader);
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
        {".plt.sec"          , func_sect_plt_sec          },
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
//int func_sect_rela_plt       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_init           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_plt            (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_plt_got        (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_plt_sec        (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_text           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_fini           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_rodata         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_eh_frame_hdr     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_eh_frame         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_init_array     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_fini_array     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_dynamic        (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_got            (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_got_plt        (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_data           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_bss            (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_comment        (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_debug_aranges    (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_debug_info       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_debug_abbrev     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_debug_line       (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_debug_str      (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_symtab         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
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
            if(j++<iCnt)
                pDataStart++;
            else
                goto exit ;
        }

        xlog_info("      >> ptr[%03d]=%016p; str={\"%s\"};\n", i, pDataStart, (char*)pDataStart);

        while (*(char*)pDataStart != '\0')
        {
            if(j++<iCnt)
                pDataStart++;
            else
                goto exit ;
        }
    }
exit:
    xlog_info("      ===========================================================\n");
    xlog_info("\n");

    return;
}

int func_sect_dynstr             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    DumpPtr2Str(pData, iLen, 50);
    
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

int func_sect_rela_plt         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    do
    {
        unsigned char* pSecRelapltBody = pData;
        struct S_Elf64_Rela_t** ppRelaEnt = (struct S_Elf64_Rela_t**)malloc(sizeof(struct S_Elf64_Rela_t*)*(pSectHeader->sh_size/pSectHeader->sh_entsize));
        xlog_info("\n");
        
        xlog_info("Relocation section '.rela.plt' at offset ?? contains %d entries:\n", 
                                                        (int)(pSectHeader->sh_size/pSectHeader->sh_entsize));
        xlog_info("  Idx  Offset          Info         Type      Sym. Value Sym. Name + Addend\n");
        
        for(int i=0; i<(pSectHeader->sh_size/pSectHeader->sh_entsize); i++)
        {
            struct S_Elf64_Rela_t* pRelaEnt = (struct S_Elf64_Rela_t*)(pSecRelapltBody + sizeof(struct S_Elf64_Rela_t)*i);
            if(1)
            {
                xlog_info("  [%02d]\e[1m %012llx %012llx 0x%08llx      test    sym.name  + %lld\e[0m\n", i, 
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

int func_sect_init               (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    //Disassembly of section .init:
    //
    //0000000000002000 <_init>:
    //    2000:	f3 0f 1e fa          	endbr64 
    //    2004:	48 83 ec 08          	sub    $0x8,%rsp
    //    2008:	48 8b 05 d9 7f 00 00 	mov    0x7fd9(%rip),%rax        # 9fe8 <__gmon_start__>
    //    200f:	48 85 c0             	test   %rax,%rax
    //    2012:	74 02                	je     2016 <_init+0x16>
    //    2014:	ff d0                	callq  *%rax
    //    2016:	48 83 c4 08          	add    $0x8,%rsp
    //    201a:	c3                   	retq   
    
    return 0;
}

int func_sect_plt                (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    //Disassembly of section .plt:
    //0000000000002020 <.plt>:
    //    2020:	ff 35 32 7f 00 00    	pushq  0x7f32(%rip)        # 9f58 <_GLOBAL_OFFSET_TABLE_+0x8>
    //    2026:	f2 ff 25 33 7f 00 00 	bnd jmpq *0x7f33(%rip)        # 9f60 <_GLOBAL_OFFSET_TABLE_+0x10>
    //    202d:	0f 1f 00             	nopl   (%rax)
    //    2030:	f3 0f 1e fa          	endbr64 
    //    2034:	68 00 00 00 00       	pushq  $0x0
    //    2039:	f2 e9 e1 ff ff ff    	bnd jmpq 2020 <.plt>
    //    203f:	90                   	nop
    //    2040:	f3 0f 1e fa          	endbr64 
    //    2044:	68 01 00 00 00       	pushq  $0x1
    //    2049:	f2 e9 d1 ff ff ff    	bnd jmpq 2020 <.plt>
    //    204f:	90                   	nop
    //    2050:	f3 0f 1e fa          	endbr64 
    //    2054:	68 02 00 00 00       	pushq  $0x2
    //    2059:	f2 e9 c1 ff ff ff    	bnd jmpq 2020 <.plt>
    //    205f:	90                   	nop
    //    2060:	f3 0f 1e fa          	endbr64 
    //    2064:	68 03 00 00 00       	pushq  $0x3
    //    2069:	f2 e9 b1 ff ff ff    	bnd jmpq 2020 <.plt>
    //    206f:	90                   	nop
    //    2070:	f3 0f 1e fa          	endbr64 
    //    2074:	68 04 00 00 00       	pushq  $0x4
    //    2079:	f2 e9 a1 ff ff ff    	bnd jmpq 2020 <.plt>
    //    207f:	90                   	nop
    //    2080:	f3 0f 1e fa          	endbr64 
    //    2084:	68 05 00 00 00       	pushq  $0x5
    //    2089:	f2 e9 91 ff ff ff    	bnd jmpq 2020 <.plt>
    //    208f:	90                   	nop
    //    2090:	f3 0f 1e fa          	endbr64 
    //    2094:	68 06 00 00 00       	pushq  $0x6
    //    2099:	f2 e9 81 ff ff ff    	bnd jmpq 2020 <.plt>
    //    209f:	90                   	nop
    //    20a0:	f3 0f 1e fa          	endbr64 
    //    20a4:	68 07 00 00 00       	pushq  $0x7
    //    20a9:	f2 e9 71 ff ff ff    	bnd jmpq 2020 <.plt>
    //    20af:	90                   	nop
    //    20b0:	f3 0f 1e fa          	endbr64 
    //    20b4:	68 08 00 00 00       	pushq  $0x8
    //    20b9:	f2 e9 61 ff ff ff    	bnd jmpq 2020 <.plt>
    //    20bf:	90                   	nop
    //    20c0:	f3 0f 1e fa          	endbr64 
    //    20c4:	68 09 00 00 00       	pushq  $0x9
    //    20c9:	f2 e9 51 ff ff ff    	bnd jmpq 2020 <.plt>
    //    20cf:	90                   	nop
    //    20d0:	f3 0f 1e fa          	endbr64 
    //    20d4:	68 0a 00 00 00       	pushq  $0xa
    //    20d9:	f2 e9 41 ff ff ff    	bnd jmpq 2020 <.plt>
    //    20df:	90                   	nop
    //    20e0:	f3 0f 1e fa          	endbr64 
    //    20e4:	68 0b 00 00 00       	pushq  $0xb
    //    20e9:	f2 e9 31 ff ff ff    	bnd jmpq 2020 <.plt>
    //    20ef:	90                   	nop
    //    20f0:	f3 0f 1e fa          	endbr64 
    //    20f4:	68 0c 00 00 00       	pushq  $0xc
    //    20f9:	f2 e9 21 ff ff ff    	bnd jmpq 2020 <.plt>
    //    20ff:	90                   	nop
    //    2100:	f3 0f 1e fa          	endbr64 
    //    2104:	68 0d 00 00 00       	pushq  $0xd
    //    2109:	f2 e9 11 ff ff ff    	bnd jmpq 2020 <.plt>
    //    210f:	90                   	nop
    
    return 0;
}

int func_sect_plt_got            (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);

    //Disassembly of section .plt.got:
    //
    //0000000000002110 <__cxa_finalize@plt>:
    //    2110:	f3 0f 1e fa          	endbr64 
    //    2114:	f2 ff 25 dd 7e 00 00 	bnd jmpq *0x7edd(%rip)        # 9ff8 <__cxa_finalize@GLIBC_2.2.5>
    //    211b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    
    return 0;
}

int func_sect_plt_sec            (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);

    //Disassembly of section .plt.sec:
    //
    //0000000000002120 <free@plt>:
    //    2120:	f3 0f 1e fa          	endbr64 
    //    2124:	f2 ff 25 3d 7e 00 00 	bnd jmpq *0x7e3d(%rip)        # 9f68 <free@GLIBC_2.2.5>
    //    212b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //0000000000002130 <fread@plt>:
    //    2130:	f3 0f 1e fa          	endbr64 
    //    2134:	f2 ff 25 35 7e 00 00 	bnd jmpq *0x7e35(%rip)        # 9f70 <fread@GLIBC_2.2.5>
    //    213b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //0000000000002140 <fclose@plt>:
    //    2140:	f3 0f 1e fa          	endbr64 
    //    2144:	f2 ff 25 2d 7e 00 00 	bnd jmpq *0x7e2d(%rip)        # 9f78 <fclose@GLIBC_2.2.5>
    //    214b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //0000000000002150 <__stack_chk_fail@plt>:
    //    2150:	f3 0f 1e fa          	endbr64 
    //    2154:	f2 ff 25 25 7e 00 00 	bnd jmpq *0x7e25(%rip)        # 9f80 <__stack_chk_fail@GLIBC_2.4>
    //    215b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //0000000000002160 <printf@plt>:
    //    2160:	f3 0f 1e fa          	endbr64 
    //    2164:	f2 ff 25 1d 7e 00 00 	bnd jmpq *0x7e1d(%rip)        # 9f88 <printf@GLIBC_2.2.5>
    //    216b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //0000000000002170 <__assert_fail@plt>:
    //    2170:	f3 0f 1e fa          	endbr64 
    //    2174:	f2 ff 25 15 7e 00 00 	bnd jmpq *0x7e15(%rip)        # 9f90 <__assert_fail@GLIBC_2.2.5>
    //    217b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //0000000000002180 <calloc@plt>:
    //    2180:	f3 0f 1e fa          	endbr64 
    //    2184:	f2 ff 25 0d 7e 00 00 	bnd jmpq *0x7e0d(%rip)        # 9f98 <calloc@GLIBC_2.2.5>
    //    218b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //0000000000002190 <strcmp@plt>:
    //    2190:	f3 0f 1e fa          	endbr64 
    //    2194:	f2 ff 25 05 7e 00 00 	bnd jmpq *0x7e05(%rip)        # 9fa0 <strcmp@GLIBC_2.2.5>
    //    219b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //00000000000021a0 <__xstat@plt>:
    //    21a0:	f3 0f 1e fa          	endbr64 
    //    21a4:	f2 ff 25 fd 7d 00 00 	bnd jmpq *0x7dfd(%rip)        # 9fa8 <__xstat@GLIBC_2.2.5>
    //    21ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //00000000000021b0 <malloc@plt>:
    //    21b0:	f3 0f 1e fa          	endbr64 
    //    21b4:	f2 ff 25 f5 7d 00 00 	bnd jmpq *0x7df5(%rip)        # 9fb0 <malloc@GLIBC_2.2.5>
    //    21bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //00000000000021c0 <fflush@plt>:
    //    21c0:	f3 0f 1e fa          	endbr64 
    //    21c4:	f2 ff 25 ed 7d 00 00 	bnd jmpq *0x7ded(%rip)        # 9fb8 <fflush@GLIBC_2.2.5>
    //    21cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //00000000000021d0 <vprintf@plt>:
    //    21d0:	f3 0f 1e fa          	endbr64 
    //    21d4:	f2 ff 25 e5 7d 00 00 	bnd jmpq *0x7de5(%rip)        # 9fc0 <vprintf@GLIBC_2.2.5>
    //    21db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //00000000000021e0 <fopen@plt>:
    //    21e0:	f3 0f 1e fa          	endbr64 
    //    21e4:	f2 ff 25 dd 7d 00 00 	bnd jmpq *0x7ddd(%rip)        # 9fc8 <fopen@GLIBC_2.2.5>
    //    21eb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    //
    //00000000000021f0 <__ctype_b_loc@plt>:
    //    21f0:	f3 0f 1e fa          	endbr64 
    //    21f4:	f2 ff 25 d5 7d 00 00 	bnd jmpq *0x7dd5(%rip)        # 9fd0 <__ctype_b_loc@GLIBC_2.3>
    //    21fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    
    return 0;
}

int func_sect_text               (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, 16*20+9);
    
    //Disassembly of section .text:
    //
    //0000000000002200 <_start>:
    //    2200:	f3 0f 1e fa          	endbr64 
    //    2204:	31 ed                	xor    %ebp,%ebp
    //    2206:	49 89 d1             	mov    %rdx,%r9
    //    2209:	5e                   	pop    %rsi
    //    220a:	48 89 e2             	mov    %rsp,%rdx
    //    220d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    //    2211:	50                   	push   %rax
    //    2212:	54                   	push   %rsp
    //    2213:	4c 8d 05 26 30 00 00 	lea    0x3026(%rip),%r8        # 5240 <__libc_csu_fini>
    //    221a:	48 8d 0d af 2f 00 00 	lea    0x2faf(%rip),%rcx        # 51d0 <__libc_csu_init>
    //    2221:	48 8d 3d 3f 2e 00 00 	lea    0x2e3f(%rip),%rdi        # 5067 <main>
    //    2228:	ff 15 b2 7d 00 00    	callq  *0x7db2(%rip)        # 9fe0 <__libc_start_main@GLIBC_2.2.5>
    //    222e:	f4                   	hlt    
    //    222f:	90                   	nop
    //
    //0000000000005067 <main>:
    //    5067:	f3 0f 1e fa          	endbr64 
    //    506b:	55                   	push   %rbp
    //    506c:	48 89 e5             	mov    %rsp,%rbp
    //    506f:	48 83 ec 40          	sub    $0x40,%rsp
    //    5073:	89 7d cc             	mov    %edi,-0x34(%rbp)
    //    5076:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
    //    507a:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    //    5081:	00 00 
    //    5083:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    //    5087:	31 c0                	xor    %eax,%eax
    //    5089:	b8 00 00 00 00       	mov    $0x0,%eax
    //    508e:	e8 56 d2 ff ff       	callq  22e9 <xlog_init>
    //    5093:	48 8d 3d ce 22 00 00 	lea    0x22ce(%rip),%rdi        # 7368 <_IO_stdin_used+0x1368>
    //    509a:	b8 00 00 00 00       	mov    $0x0,%eax
    //    509f:	e8 87 d7 ff ff       	callq  282b <xlog_info>
    //    50a4:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    //    50a8:	be 5b 00 00 00       	mov    $0x5b,%esi
    //    50ad:	48 89 c7             	mov    %rax,%rdi
    //    50b0:	e8 bb d3 ff ff       	callq  2470 <xlog_hexdump>
    //    50b5:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    //    50b9:	48 8b 00             	mov    (%rax),%rax
    //    50bc:	be 5b 00 00 00       	mov    $0x5b,%esi
    //    50c1:	48 89 c7             	mov    %rax,%rdi
    //    50c4:	e8 a7 d3 ff ff       	callq  2470 <xlog_hexdump>
    //    50c9:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    //    50cd:	8b 45 cc             	mov    -0x34(%rbp),%eax
    //    50d0:	48 89 d6             	mov    %rdx,%rsi
    //    50d3:	89 c7                	mov    %eax,%edi
    //    50d5:	e8 aa fe ff ff       	callq  4f84 <parse_args>
    //    50da:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    //    50de:	48 8b 00             	mov    (%rax),%rax
    //    50e1:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    //    50e5:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
    //    50ec:	00 
    //    50ed:	48 8d 55 d8          	lea    -0x28(%rbp),%rdx
    //    50f1:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    //    50f5:	48 89 d6             	mov    %rdx,%rsi
    //    50f8:	48 89 c7             	mov    %rax,%rdi
    //    50fb:	e8 59 d8 ff ff       	callq  2959 <get_elf64_data>
    //    5100:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    //    5104:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    //    5109:	74 09                	je     5114 <main+0xad>
    //    510b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    //    510f:	48 85 c0             	test   %rax,%rax
    //    5112:	75 1a                	jne    512e <main+0xc7>
    //    5114:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    //    5118:	48 89 c6             	mov    %rax,%rsi
    //    511b:	48 8d 3d 66 22 00 00 	lea    0x2266(%rip),%rdi        # 7388 <_IO_stdin_used+0x1388>
    //    5122:	b8 00 00 00 00       	mov    $0x0,%eax
    //    5127:	e8 ff d6 ff ff       	callq  282b <xlog_info>
    //    512c:	eb 63                	jmp    5191 <main+0x12a>
    //    512e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    //    5132:	be 55 00 00 00       	mov    $0x55,%esi
    //    5137:	48 89 c7             	mov    %rax,%rdi
    //    513a:	e8 31 d3 ff ff       	callq  2470 <xlog_hexdump>
    //    513f:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    //    5143:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    //    5147:	48 89 d6             	mov    %rdx,%rsi
    //    514a:	48 89 c7             	mov    %rax,%rdi
    //    514d:	e8 22 f9 ff ff       	callq  4a74 <build_elf64_obj>
    //    5152:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    //    5156:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    //    515a:	48 8b 40 50          	mov    0x50(%rax),%rax
    //    515e:	48 89 c7             	mov    %rax,%rdi
    //    5161:	e8 ba cf ff ff       	callq  2120 <free@plt>
    //    5166:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    //    516a:	48 8b 80 58 0c 00 00 	mov    0xc58(%rax),%rax
    //    5171:	48 89 c7             	mov    %rax,%rdi
    //    5174:	e8 a7 cf ff ff       	callq  2120 <free@plt>
    //    5179:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    //    517d:	48 89 c7             	mov    %rax,%rdi
    //    5180:	e8 9b cf ff ff       	callq  2120 <free@plt>
    //    5185:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    //    5189:	48 89 c7             	mov    %rax,%rdi
    //    518c:	e8 8f cf ff ff       	callq  2120 <free@plt>
    //    5191:	48 8d 3d 1f 22 00 00 	lea    0x221f(%rip),%rdi        # 73b7 <_IO_stdin_used+0x13b7>
    //    5198:	b8 00 00 00 00       	mov    $0x0,%eax
    //    519d:	e8 89 d6 ff ff       	callq  282b <xlog_info>
    //    51a2:	b8 00 00 00 00       	mov    $0x0,%eax
    //    51a7:	e8 48 d1 ff ff       	callq  22f4 <xlog_uninit>
    //    51ac:	b8 00 00 00 00       	mov    $0x0,%eax
    //    51b1:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
    //    51b5:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
    //    51bc:	00 00 
    //    51be:	74 05                	je     51c5 <main+0x15e>
    //    51c0:	e8 8b cf ff ff       	callq  2150 <__stack_chk_fail@plt>
    //    51c5:	c9                   	leaveq 
    //    51c6:	c3                   	retq   
    //    51c7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    //    51ce:	00 00 

    return 0;
}

int func_sect_fini               (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    //Disassembly of section .fini:
    //0000000000005264 <_fini>:
    //    5264:       f3 0f 1e fa             endbr64 
    //    5268:       48 83 ec 08             sub    $0x8,%rsp
    //    526c:       48 83 c4 08             add    $0x8,%rsp
    //    5270:       c3                      retq   

    return 0;
}

int func_sect_rodata             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);

    //  >> func{parse_elf64_sect_body:(01135)} is call. 
    //      {idx=18,sect_name=".rodata",pSectData=0x561e22859890,iLen=0x196b}
    //    >> func{func_sect_rodata:(00975)} is call .
    //        No.[18]--------------------------------------------
    //        struct S_ELF64_SectHeader_t * pSectHeader = 0x561e22863a70
    //        {
    //             Elf64_Word    sh_name      = 0xc5;
    //             Elf64_Word    sh_type      = 0x1;
    //             Elf64_Xword   sh_flags     = 0x2;
    //             Elf64_Addr    sh_addr      = 0x6000;
    //             Elf64_Off     sh_offset    = 0x6000;
    //             Elf64_Xword   sh_size      = 0x196b;
    //             Elf64_Word    sh_link      = 0x0;
    //             Elf64_Word    sh_info      = 0x0;
    //             Elf64_Xword   sh_addralign = 0x10;
    //             Elf64_Xword   sh_entsize   = 0x0;
    //        }
    //
    //0x00561e22859890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
    //      =============================================================================
    //      0x00000000|01 00 02 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
    //      0x00000010|0a 00 25 30 31 36 70 00  7c 30 30 20 30 31 20 30|..%016p.|00 01 0|
    //      0x00000020|32 20 30 33 20 30 34 20  30 35 20 30 36 20 30 37|2 03 04 05 06 07|
    //      0x00000030|20 20 30 38 20 30 39 20  30 41 20 30 42 20 30 43|  08 09 0A 0B 0C|
    //      0x00000040|20 30 44 20 30 45 20 30  46 7c 30 31 32 33 34 35| 0D 0E 0F|012345|
    //      0x00000050|36 37 38 39 41 42 43 44  45 46 7c 0a 00 00 00 00|6789ABCDEF|.....|
    //      0x00000060|20 20 20 20 20 20 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|      ==========|
    //      0x00000070|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
    // ... ...
    //      0x000018e0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
    //      0x000018f0|61 66 74 65 72 5f 6d 61  69 6e 5f 66 75 6e 63 00|after_main_func.|
    //      0x00001900|6d 79 5f 69 6e 69 74 30  31 00 00 00 00 00 00 00|my_init01.......|
    //      0x00001910|6d 79 5f 66 69 6e 69 30  31 00 00 00 00 00 00 00|my_fini01.......|
    //      0x00001920|6d 79 5f 69 6e 69 74 30  32 00 00 00 00 00 00 00|my_init02.......|
    //      0x00001930|6d 79 5f 66 69 6e 69 30  32 00 00 00 00 00 00 00|my_fini02.......|
    //      0x00001940|6d 79 5f 69 6e 69 74 30  33 00 00 00 00 00 00 00|my_init03.......|
    //      0x00001950|6d 79 5f 66 69 6e 69 30  33 00 00 00 00 00 00 00|my_fini03.......|
    //      0x00001960|70 61 72 73 65 5f 61 72  67 73 00 ** ** ** ** **|parse_args.*****|
    //      =============================================================================
    //
    
    return 0;
}

//int func_sect_eh_frame_hdr     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
//int func_sect_eh_frame         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}

void xlog_ptrdump(unsigned char* pDataStart, unsigned int iPtrCnt)
{
	void** ppVoidPtr = (void**)pDataStart;
	xlog_info("  >>=============================================\n");
	
	for (unsigned int i = 0; i < iPtrCnt; i++)
	{
		xlog_info("      >> ptr[%03d] = %016p;\n", i, *(ppVoidPtr + i));
	}
	
	xlog_info("  >>=============================================\n");
	xlog_info("\n");

	return;
}

int func_sect_init_array         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    xlog_ptrdump(pData, iLen/pSectHeader->sh_entsize);
    
    return 0;
}
//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=21,sect_name=".init_array",pSectData=0x56376f63a5a0,iLen=0x28}
//    >> func{func_sect_init_array:(01316)} is call .
//        No.[21]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x56376f641c48
//        {
//             Elf64_Word    sh_name      = 0xe5;
//             Elf64_Word    sh_type      = 0xe;
//             Elf64_Xword   sh_flags     = 0x3;
//             Elf64_Addr    sh_addr      = 0x9d10;
//             Elf64_Off     sh_offset    = 0x8d10;
//             Elf64_Xword   sh_size      = 0x28;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x8;
//             Elf64_Xword   sh_entsize   = 0x8;
//        }
//
//0x0056376f63a5a0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|e0 22 00 00 00 00 00 00  4e 4e 00 00 00 00 00 00|."......NN......|
//      0x00000010|df 4e 00 00 00 00 00 00  5f 4f 00 00 00 00 00 00|.N......_O......|
//      0x00000020|df 4f 00 00 00 00 00 00  ** ** ** ** ** ** ** **|.O......********|
//      =============================================================================
//
//  >>=============================================
//      >> ptr[000] = 0x000000000022e0; 00000000000022e0 <frame_dummy>:
//      >> ptr[001] = 0x00000000004e4e; 0000000000004e4e <before_main_func>:
//      >> ptr[002] = 0x00000000004edf; 0000000000004edf <my_init01>:
//      >> ptr[003] = 0x00000000004f5f; 0000000000004f5f <my_init02>:
//      >> ptr[004] = 0x00000000004fdf; 0000000000004fdf <my_init03>:
//  >>=============================================

int func_sect_fini_array         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    xlog_ptrdump(pData, iLen/pSectHeader->sh_entsize);
    
    return 0;
}

//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=22,sect_name=".fini_array",pSectData=0x56376f63a5c8,iLen=0x28}
//    >> func{func_sect_fini_array:(01329)} is call .
//        No.[22]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x56376f641c88
//        {
//             Elf64_Word    sh_name      = 0xf1;
//             Elf64_Word    sh_type      = 0xf;
//             Elf64_Xword   sh_flags     = 0x3;
//             Elf64_Addr    sh_addr      = 0x9d38;
//             Elf64_Off     sh_offset    = 0x8d38;
//             Elf64_Xword   sh_size      = 0x28;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x8;
//             Elf64_Xword   sh_entsize   = 0x8;
//        }
//
//0x0056376f63a5c8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|a0 22 00 00 00 00 00 00  9f 4e 00 00 00 00 00 00|.".......N......|
//      0x00000010|1f 4f 00 00 00 00 00 00  9f 4f 00 00 00 00 00 00|.O.......O......|
//      0x00000020|1f 50 00 00 00 00 00 00  ** ** ** ** ** ** ** **|.P......********|
//      =============================================================================
//
//  >>=============================================
//      >> ptr[000] = 0x000000000022a0; 00000000000022a0 <__do_global_dtors_aux>:
//      >> ptr[001] = 0x00000000004e9f; 0000000000004e9f <after_main_func>:
//      >> ptr[002] = 0x00000000004f1f; 0000000000004f1f <my_fini01>:
//      >> ptr[003] = 0x00000000004f9f; 0000000000004f9f <my_fini02>:
//      >> ptr[004] = 0x0000000000501f; 000000000000501f <my_fini03>:
//  >>=============================================

int func_sect_dynamic            (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    return 0;
}

int func_sect_got                (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    return 0;
}
//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=24,sect_name=".got",pSectData=0x56376f63a7e0,iLen=0xb0}
//    >> func{func_sect_got:(01353)} is call .
//        No.[24]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x56376f641d08
//        {
//             Elf64_Word    sh_name      = 0xab;
//             Elf64_Word    sh_type      = 0x1;
//             Elf64_Xword   sh_flags     = 0x3;
//             Elf64_Addr    sh_addr      = 0x9f50;
//             Elf64_Off     sh_offset    = 0x8f50;
//             Elf64_Xword   sh_size      = 0xb0;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x8;
//             Elf64_Xword   sh_entsize   = 0x8;
//        }
//
//0x0056376f63a7e0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|60 9d 00 00 00 00 00 00  00 00 00 00 00 00 00 00|`...............|
//      0x00000010|00 00 00 00 00 00 00 00  30 20 00 00 00 00 00 00|........0 ......|
//      0x00000020|40 20 00 00 00 00 00 00  50 20 00 00 00 00 00 00|@ ......P ......|
//      0x00000030|60 20 00 00 00 00 00 00  70 20 00 00 00 00 00 00|` ......p ......|
//      0x00000040|80 20 00 00 00 00 00 00  90 20 00 00 00 00 00 00|. ....... ......|
//      0x00000050|a0 20 00 00 00 00 00 00  b0 20 00 00 00 00 00 00|. ....... ......|
//      0x00000060|c0 20 00 00 00 00 00 00  d0 20 00 00 00 00 00 00|. ....... ......|
//      0x00000070|e0 20 00 00 00 00 00 00  f0 20 00 00 00 00 00 00|. ....... ......|
//      0x00000080|00 21 00 00 00 00 00 00  00 00 00 00 00 00 00 00|.!..............|
//      0x00000090|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
//      0x000000a0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
//      =============================================================================

int func_sect_got_plt            (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    return 0;
}

int func_sect_data               (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    return 0;
}

//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=25,sect_name=".data",pSectData=0x562a0e3f6890,iLen=0x270}
//    >> func{func_sect_data:(01375)} is call .
//        No.[25]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x562a0e3fdd48
//        {
//             Elf64_Word    sh_name      = 0x106;
//             Elf64_Word    sh_type      = 0x1;
//             Elf64_Xword   sh_flags     = 0x3;
//             Elf64_Addr    sh_addr      = 0xa000;
//             Elf64_Off     sh_offset    = 0x9000;
//             Elf64_Xword   sh_size      = 0x270;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x20;
//             Elf64_Xword   sh_entsize   = 0x0;
//        }
//
//0x00562a0e3f6890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|00 00 00 00 00 00 00 00  08 a0 00 00 00 00 00 00|................|
//      0x00000010|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
//      0x00000020|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
//      0x00000030|ca 6b 00 00 00 00 00 00  78 39 00 00 00 00 00 00|.k......x9......|
//      0x00000040|d2 6b 00 00 00 00 00 00  dc 35 00 00 00 00 00 00|.k.......5......|
//      0x00000050|e2 6b 00 00 00 00 00 00  60 36 00 00 00 00 00 00|.k......`6......|
//      0x00000060|f0 6b 00 00 00 00 00 00  a2 36 00 00 00 00 00 00|.k.......6......|
//      0x00000070|03 6c 00 00 00 00 00 00  e4 36 00 00 00 00 00 00|.l.......6......|
//      0x00000080|0d 6c 00 00 00 00 00 00  7a 3a 00 00 00 00 00 00|.l......z:......|
//      0x00000090|15 6c 00 00 00 00 00 00  36 3d 00 00 00 00 00 00|.l......6=......|
//      0x000000a0|1d 6c 00 00 00 00 00 00  26 37 00 00 00 00 00 00|.l......&7......|
//      0x000000b0|2a 6c 00 00 00 00 00 00  68 37 00 00 00 00 00 00|*l......h7......|
//      0x000000c0|39 6c 00 00 00 00 00 00  b4 3d 00 00 00 00 00 00|9l.......=......|
//      0x000000d0|43 6c 00 00 00 00 00 00  35 3f 00 00 00 00 00 00|Cl......5?......|
//      0x000000e0|4d 6c 00 00 00 00 00 00  c7 40 00 00 00 00 00 00|Ml.......@......|
//      0x000000f0|53 6c 00 00 00 00 00 00  2f 41 00 00 00 00 00 00|Sl....../A......|
//      0x00000100|58 6c 00 00 00 00 00 00  97 41 00 00 00 00 00 00|Xl.......A......|
//      0x00000110|61 6c 00 00 00 00 00 00  ff 41 00 00 00 00 00 00|al.......A......|
//      0x00000120|67 6c 00 00 00 00 00 00  63 42 00 00 00 00 00 00|gl......cB......|
//      0x00000130|6d 6c 00 00 00 00 00 00  cb 42 00 00 00 00 00 00|ml.......B......|
//      0x00000140|75 6c 00 00 00 00 00 00  aa 37 00 00 00 00 00 00|ul.......7......|
//      0x00000150|83 6c 00 00 00 00 00 00  ec 37 00 00 00 00 00 00|.l.......7......|
//      0x00000160|8d 6c 00 00 00 00 00 00  c4 43 00 00 00 00 00 00|.l.......C......|
//      0x00000170|99 6c 00 00 00 00 00 00  51 44 00 00 00 00 00 00|.l......QD......|
//      0x00000180|a5 6c 00 00 00 00 00 00  de 44 00 00 00 00 00 00|.l.......D......|
//      0x00000190|ae 6c 00 00 00 00 00 00  46 45 00 00 00 00 00 00|.l......FE......|
//      0x000001a0|b3 6c 00 00 00 00 00 00  ae 45 00 00 00 00 00 00|.l.......E......|
//      0x000001b0|bc 6c 00 00 00 00 00 00  16 46 00 00 00 00 00 00|.l.......F......|
//      0x000001c0|c2 6c 00 00 00 00 00 00  7e 46 00 00 00 00 00 00|.l......~F......|
//      0x000001d0|c7 6c 00 00 00 00 00 00  e6 46 00 00 00 00 00 00|.l.......F......|
//      0x000001e0|d0 6c 00 00 00 00 00 00  2e 38 00 00 00 00 00 00|.l.......8......|
//      0x000001f0|df 6c 00 00 00 00 00 00  70 38 00 00 00 00 00 00|.l......p8......|
//      0x00000200|eb 6c 00 00 00 00 00 00  b2 38 00 00 00 00 00 00|.l.......8......|
//      0x00000210|f9 6c 00 00 00 00 00 00  f4 38 00 00 00 00 00 00|.l.......8......|
//      0x00000220|05 6d 00 00 00 00 00 00  4e 47 00 00 00 00 00 00|.m......NG......|
//      0x00000230|10 6d 00 00 00 00 00 00  36 39 00 00 00 00 00 00|.m......69......|
//      0x00000240|18 6d 00 00 00 00 00 00  cc 47 00 00 00 00 00 00|.m.......G......|
//      0x00000250|20 6d 00 00 00 00 00 00  4a 48 00 00 00 00 00 00| m......JH......|
//      0x00000260|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
//      =============================================================================

int func_sect_bss                (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    return 0;
}

//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=26,sect_name=".bss",pSectData=0x562a0e3f6b00,iLen=0x10}
//    >> func{func_sect_bss:(01386)} is call .
//        No.[26]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x562a0e3fdd88
//        {
//             Elf64_Word    sh_name      = 0x10c;
//             Elf64_Word    sh_type      = 0x8;
//             Elf64_Xword   sh_flags     = 0x3;
//             Elf64_Addr    sh_addr      = 0xa270;
//             Elf64_Off     sh_offset    = 0x9270;
//             Elf64_Xword   sh_size      = 0x10;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x8;
//             Elf64_Xword   sh_entsize   = 0x0;
//        }
//
//0x00562a0e3f6b00|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|47 43 43 3a 20 28 55 62  75 6e 74 75 20 39 2e 34|GCC: (Ubuntu 9.4|
//      =============================================================================


int func_sect_comment            (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    return 0;
}

//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=27,sect_name=".comment",pSectData=0x562a0e3f6b00,iLen=0x2b}
//    >> func{func_sect_comment:(01397)} is call .
//        No.[27]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x562a0e3fddc8
//        {
//             Elf64_Word    sh_name      = 0x111;
//             Elf64_Word    sh_type      = 0x1;
//             Elf64_Xword   sh_flags     = 0x30;
//             Elf64_Addr    sh_addr      = 0x0;
//             Elf64_Off     sh_offset    = 0x9270;
//             Elf64_Xword   sh_size      = 0x2b;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x1;
//             Elf64_Xword   sh_entsize   = 0x1;
//        }
//
//0x00562a0e3f6b00|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|47 43 43 3a 20 28 55 62  75 6e 74 75 20 39 2e 34|GCC: (Ubuntu 9.4|
//      0x00000010|2e 30 2d 31 75 62 75 6e  74 75 31 7e 32 30 2e 30|.0-1ubuntu1~20.0|
//      0x00000020|34 2e 31 29 20 39 2e 34  2e 30 00 ** ** ** ** **|4.1) 9.4.0.*****|
//      =============================================================================

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

//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=32,sect_name=".debug_str",pSectData=0x562a0e3fa9a1,iLen=0xd8e}
//    >> func{func_sect_debug_str:(01413)} is call .
//        No.[32]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x562a0e3fdf08
//        {
//             Elf64_Word    sh_name      = 0x14f;
//             Elf64_Word    sh_type      = 0x1;
//             Elf64_Xword   sh_flags     = 0x30;
//             Elf64_Addr    sh_addr      = 0x0;
//             Elf64_Off     sh_offset    = 0xd111;
//             Elf64_Xword   sh_size      = 0xd8e;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x1;
//             Elf64_Xword   sh_entsize   = 0x1;
//        }
//
//0x00562a0e3fa9a1|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|45 6c 66 36 34 5f 41 64  64 72 00 70 61 72 73 65|Elf64_Addr.parse|
//      0x00000010|5f 65 6c 66 36 34 5f 70  72 6f 67 5f 68 65 61 64|_elf64_prog_head|
//      0x00000020|65 72 00 66 75 6e 63 5f  73 65 63 74 5f 6e 6f 74|er.func_sect_not|
//      0x00000030|65 5f 67 6e 75 5f 62 75  69 6c 64 5f 69 64 00 67|e_gnu_build_id.g|
//      0x00000040|65 74 5f 65 6c 66 36 34  5f 64 61 74 61 00 74 65|et_elf64_data.te|
//      0x00000050|73 74 5f 63 68 61 72 00  5f 73 68 6f 72 74 62 75|st_char._shortbu|
//      0x00000060|66 00 73 68 5f 6c 69 6e  6b 00 5f 49 4f 5f 6c 6f|f.sh_link._IO_lo|
//      0x00000070|63 6b 5f 74 00 67 70 5f  6f 66 66 73 65 74 00 70|ck_t.gp_offset.p|
//      0x00000080|61 72 73 65 5f 65 6c 66  36 34 5f 73 65 63 74 5f|arse_elf64_sect_|
//      0x00000090|62 6f 64 79 00 73 74 64  65 72 72 00 5f 49 4f 5f|body.stderr._IO_|
//      0x000000a0|62 75 66 5f 65 6e 64 00  69 43 6e 74 00 73 74 5f|buf_end.iCnt.st_|
//      0x000000b0|61 74 69 6d 65 6e 73 65  63 00 65 5f 73 68 6f 66|atimensec.e_shof|
//      0x000000c0|66 00 70 44 79 6e 73 79  6d 44 61 74 61 00 61 66|f.pDynsymData.af|
//      0x000000d0|74 65 72 5f 6d 61 69 6e  5f 66 75 6e 63 00 66 75|ter_main_func.fu|
//      0x000000e0|6e 63 5f 73 65 63 74 5f  66 69 6e 69 00 53 5f 45|nc_sect_fini.S_E|
//      0x000000f0|4c 46 36 34 5f 53 65 63  74 48 65 61 64 65 72 5f|LF64_SectHeader_|
//      0x00000100|74 00 5f 49 4f 5f 77 72  69 74 65 5f 65 6e 64 00|t._IO_write_end.|
//      0x00000110|66 75 6e 63 5f 73 65 63  74 5f 64 79 6e 73 79 6d|func_sect_dynsym|
//      0x00000120|00 66 75 6e 63 5f 73 65  63 74 5f 69 6e 74 65 72|.func_sect_inter|
//      0x00000130|70 00 70 61 72 73 65 5f  65 6c 66 36 34 5f 70 72|p.parse_elf64_pr|
//      0x00000140|6f 67 5f 68 65 61 64 65  72 73 00 5f 66 72 65 65|og_headers._free|
//      0x00000150|72 65 73 5f 6c 69 73 74  00 73 74 5f 62 6c 6b 73|res_list.st_blks|
//      0x00000160|69 7a 65 00 65 5f 76 65  72 73 69 6f 6e 00 69 72|ize.e_version.ir|
//      0x00000170|65 74 00 53 5f 45 6c 66  36 34 5f 53 65 63 74 46|et.S_Elf64_SectF|
//      0x00000180|75 6e 63 5f 74 00 65 6c  66 36 34 5f 6f 62 6a 5f|unc_t.elf64_obj_|
//      0x00000190|73 69 7a 65 00 65 5f 70  68 6f 66 66 00 73 74 5f|size.e_phoff.st_|
//      0x000001a0|69 6e 66 6f 00 5f 6d 61  72 6b 65 72 73 00 65 5f|info._markers.e_|
//      0x000001b0|65 68 73 69 7a 65 00 5f  5f 6e 6c 69 6e 6b 5f 74|ehsize.__nlink_t|
//      0x000001c0|00 66 75 6e 63 5f 73 65  63 74 5f 64 61 74 61 00|.func_sect_data.|
//      0x000001d0|70 5f 65 6c 66 36 34 5f  6f 62 6a 00 53 5f 45 4c|p_elf64_obj.S_EL|
//      0x000001e0|46 36 34 5f 45 4c 46 48  65 61 64 65 72 5f 74 00|F64_ELFHeader_t.|
//      0x000001f0|66 75 6e 63 5f 73 65 63  74 5f 67 6f 74 00 75 69|func_sect_got.ui|
//      0x00000200|5f 6c 65 76 65 6c 00 65  5f 73 68 65 6e 74 73 69|_level.e_shentsi|
//      0x00000210|7a 65 00 66 75 6e 63 5f  73 65 63 74 5f 73 79 6d|ze.func_sect_sym|
//      0x00000220|74 61 62 00 5f 5f 69 6e  6f 5f 74 00 66 75 6e 63|tab.__ino_t.func|
//      0x00000230|5f 73 65 63 74 5f 64 65  62 75 67 5f 61 62 62 72|_sect_debug_abbr|
//      0x00000240|65 76 00 62 75 69 6c 64  5f 65 6c 66 36 34 5f 6f|ev.build_elf64_o|
//      0x00000250|62 6a 00 65 5f 65 6e 74  72 79 00 66 75 6e 63 5f|bj.e_entry.func_|
//      0x00000260|73 65 63 74 5f 64 65 62  75 67 5f 73 74 72 00 75|sect_debug_str.u|
//      0x00000270|69 6e 74 33 32 5f 74 00  6d 79 5f 69 6e 69 74 30|int32_t.my_init0|
//      0x00000280|31 00 6d 79 5f 69 6e 69  74 30 32 00 6d 79 5f 69|1.my_init02.my_i|
//      0x00000290|6e 69 74 30 33 00 73 74  64 6f 75 74 00 5f 49 4f|nit03.stdout._IO|
//      0x000002a0|5f 73 61 76 65 5f 65 6e  64 00 70 5f 65 6c 66 36|_save_end.p_elf6|
//      0x000002b0|34 5f 64 61 74 61 00 66  75 6e 63 5f 73 65 63 74|4_data.func_sect|
//      0x000002c0|5f 67 6e 75 5f 76 65 72  73 69 6f 6e 00 70 70 53|_gnu_version.ppS|
//      0x000002d0|79 6d 45 6e 74 00 70 5f  64 61 74 61 00 5f 49 4f|ymEnt.p_data._IO|
//      0x000002e0|5f 63 6f 64 65 63 76 74  00 66 75 6e 63 5f 73 65|_codecvt.func_se|
//      0x000002f0|63 74 5f 74 65 78 74 00  70 50 72 6f 67 48 65 61|ct_text.pProgHea|
//      0x00000300|64 65 72 73 44 61 74 61  00 70 61 72 73 65 5f 61|dersData.parse_a|
//      0x00000310|72 67 73 00 6f 76 65 72  66 6c 6f 77 5f 61 72 67|rgs.overflow_arg|
//      0x00000320|5f 61 72 65 61 00 70 53  65 63 52 65 6c 61 70 6c|_area.pSecRelapl|
//      0x00000330|74 42 6f 64 79 00 6c 6f  6e 67 20 6c 6f 6e 67 20|tBody.long long |
//      0x00000340|75 6e 73 69 67 6e 65 64  20 69 6e 74 00 73 74 5f|unsigned int.st_|
//      0x00000350|62 6c 6f 63 6b 73 00 66  75 6e 63 5f 73 65 63 74|blocks.func_sect|
//      0x00000360|5f 6e 6f 74 65 5f 41 42  49 5f 74 61 67 00 78 6c|_note_ABI_tag.xl|
//      0x00000370|6f 67 5f 63 6f 72 65 00  70 5f 66 69 6c 65 73 7a|og_core.p_filesz|
//      0x00000380|00 73 74 5f 6d 74 69 6d  65 00 66 75 6e 63 5f 73|.st_mtime.func_s|
//      0x00000390|65 63 74 5f 69 6e 69 74  5f 61 72 72 61 79 00 44|ect_init_array.D|
//      0x000003a0|75 6d 70 50 74 72 32 53  74 72 00 5f 49 4f 5f 62|umpPtr2Str._IO_b|
//      0x000003b0|61 63 6b 75 70 5f 62 61  73 65 00 50 72 6f 67 48|ackup_base.ProgH|
//      0x000003c0|65 61 64 65 72 4f 62 6a  73 00 73 5f 65 6c 66 36|eaderObjs.s_elf6|
//      0x000003d0|34 5f 6f 62 6a 5f 74 00  78 6c 6f 67 5f 70 74 72|4_obj_t.xlog_ptr|
//      0x000003e0|64 75 6d 70 00 70 50 72  6f 67 48 65 61 64 65 72|dump.pProgHeader|
//      0x000003f0|44 61 74 61 00 5f 49 53  6c 6f 77 65 72 00 5f 66|Data._ISlower._f|
//      0x00000400|69 6c 65 6e 6f 00 73 74  61 74 00 70 70 50 72 6f|ileno.stat.ppPro|
//      0x00000410|67 48 65 61 64 65 72 73  00 45 6c 66 48 65 61 64|gHeaders.ElfHead|
//      0x00000420|65 72 4f 62 6a 00 66 75  6e 63 5f 73 65 63 74 5f|erObj.func_sect_|
//      0x00000430|6e 6f 74 65 5f 67 6e 75  5f 62 75 69 6c 64 00 5f|note_gnu_build._|
//      0x00000440|5f 67 6e 75 63 5f 76 61  5f 6c 69 73 74 00 66 75|_gnuc_va_list.fu|
//      0x00000450|6e 63 5f 73 65 63 74 5f  67 6e 75 5f 68 61 73 68|nc_sect_gnu_hash|
//      0x00000460|00 5f 5f 6d 6f 64 65 5f  74 00 70 44 61 74 61 00|.__mode_t.pData.|
//      0x00000470|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
//      0x00000480|5f 68 65 61 64 65 72 73  00 5f 49 53 78 64 69 67|_headers._ISxdig|
//      0x00000490|69 74 00 5f 49 4f 5f 72  65 61 64 5f 62 61 73 65|it._IO_read_base|
//      0x000004a0|00 70 61 72 73 65 5f 65  6c 66 36 34 5f 73 65 63|.parse_elf64_sec|
//      0x000004b0|74 5f 68 65 61 64 65 72  00 66 75 6e 63 5f 73 65|t_header.func_se|
//      0x000004c0|63 74 5f 6e 6f 74 65 5f  67 6e 75 5f 70 72 6f 70|ct_note_gnu_prop|
//      0x000004d0|65 00 73 74 5f 67 69 64  00 61 72 67 63 00 73 74|e.st_gid.argc.st|
//      0x000004e0|64 69 6e 00 47 4e 55 20  43 31 31 20 39 2e 34 2e|din.GNU C11 9.4.|
//      0x000004f0|30 20 2d 6d 74 75 6e 65  3d 67 65 6e 65 72 69 63|0 -mtune=generic|
//      0x00000500|20 2d 6d 61 72 63 68 3d  78 38 36 2d 36 34 20 2d| -march=x86-64 -|
//      0x00000510|67 20 2d 4f 30 20 2d 73  74 64 3d 63 31 31 20 2d|g -O0 -std=c11 -|
//      0x00000520|66 61 73 79 6e 63 68 72  6f 6e 6f 75 73 2d 75 6e|fasynchronous-un|
//      0x00000530|77 69 6e 64 2d 74 61 62  6c 65 73 20 2d 66 73 74|wind-tables -fst|
//      0x00000540|61 63 6b 2d 70 72 6f 74  65 63 74 6f 72 2d 73 74|ack-protector-st|
//      0x00000550|72 6f 6e 67 20 2d 66 73  74 61 63 6b 2d 63 6c 61|rong -fstack-cla|
//      0x00000560|73 68 2d 70 72 6f 74 65  63 74 69 6f 6e 20 2d 66|sh-protection -f|
//      0x00000570|63 66 2d 70 72 6f 74 65  63 74 69 6f 6e 00 73 74|cf-protection.st|
//      0x00000580|5f 6d 6f 64 65 00 45 6c  66 36 34 5f 48 61 6c 66|_mode.Elf64_Half|
//      0x00000590|00 73 74 5f 6e 6c 69 6e  6b 00 73 68 5f 65 6e 74|.st_nlink.sh_ent|
//      0x000005a0|73 69 7a 65 00 6d 79 72  65 61 64 65 6c 66 2d 30|size.myreadelf-0|
//      0x000005b0|2e 31 2e 30 38 2e 63 00  65 78 69 74 00 72 5f 69|.1.08.c.exit.r_i|
//      0x000005c0|6e 66 6f 00 53 65 63 74  48 65 61 64 65 72 4f 62|nfo.SectHeaderOb|
//      0x000005d0|6a 73 00 70 44 79 6e 53  74 72 44 61 74 61 00 66|js.pDynStrData.f|
//      0x000005e0|75 6e 63 5f 73 65 63 74  5f 62 73 73 00 66 69 6c|unc_sect_bss.fil|
//      0x000005f0|65 6e 61 6d 65 00 65 5f  66 6c 61 67 73 00 5f 49|ename.e_flags._I|
//      0x00000600|4f 5f 6d 61 72 6b 65 72  00 5f 49 4f 5f 72 65 61|O_marker._IO_rea|
//      0x00000610|64 5f 70 74 72 00 70 5f  61 6c 69 67 6e 00 66 75|d_ptr.p_align.fu|
//      0x00000620|6e 63 5f 73 65 63 74 5f  72 65 6c 61 5f 70 6c 74|nc_sect_rela_plt|
//      0x00000630|00 73 74 5f 61 74 69 6d  65 00 73 68 5f 69 6e 66|.st_atime.sh_inf|
//      0x00000640|6f 00 65 5f 73 68 73 74  72 6e 64 78 00 5f 5f 50|o.e_shstrndx.__P|
//      0x00000650|52 45 54 54 59 5f 46 55  4e 43 54 49 4f 4e 5f 5f|RETTY_FUNCTION__|
//      0x00000660|00 66 75 6e 63 5f 73 65  63 74 5f 72 6f 64 61 74|.func_sect_rodat|
//      0x00000670|61 00 70 61 72 73 65 5f  65 6c 66 36 34 5f 73 65|a.parse_elf64_se|
//      0x00000680|63 74 5f 62 6f 64 79 73  00 75 69 6e 74 38 5f 74|ct_bodys.uint8_t|
//      0x00000690|00 66 75 6e 63 5f 73 65  63 74 5f 69 6e 69 74 00|.func_sect_init.|
//      0x000006a0|73 74 5f 69 6e 6f 00 53  5f 45 6c 66 36 34 5f 52|st_ino.S_Elf64_R|
//      0x000006b0|65 6c 61 5f 74 00 66 75  6e 63 5f 73 65 63 74 5f|ela_t.func_sect_|
//      0x000006c0|64 79 6e 73 74 72 00 70  45 6c 66 48 65 61 64 65|dynstr.pElfHeade|
//      0x000006d0|72 00 45 6c 66 36 34 5f  58 77 6f 72 64 00 5f 49|r.Elf64_Xword._I|
//      0x000006e0|4f 5f 77 72 69 74 65 5f  62 61 73 65 00 70 53 65|O_write_base.pSe|
//      0x000006f0|63 74 4e 61 6d 65 73 00  6c 6f 6e 67 20 6c 6f 6e|ctNames.long lon|
//      0x00000700|67 20 69 6e 74 00 66 75  6e 63 5f 73 65 63 74 5f|g int.func_sect_|
//      0x00000710|70 6c 74 5f 67 6f 74 00  73 74 5f 6d 74 69 6d 65|plt_got.st_mtime|
//      0x00000720|6e 73 65 63 00 45 6c 66  36 34 5f 4f 66 66 00 5f|nsec.Elf64_Off._|
//      0x00000730|49 4f 5f 73 61 76 65 5f  62 61 73 65 00 5f 5f 64|IO_save_base.__d|
//      0x00000740|65 76 5f 74 00 66 75 6e  63 5f 73 65 63 74 5f 70|ev_t.func_sect_p|
//      0x00000750|6c 74 00 5f 49 53 63 6e  74 72 6c 00 70 53 65 63|lt._IScntrl.pSec|
//      0x00000760|74 48 65 61 64 65 72 44  61 74 61 00 2f 68 6f 6d|tHeaderData./hom|
//      0x00000770|65 2f 78 61 64 6d 69 6e  2f 78 77 6b 73 2e 67 69|e/xadmin/xwks.gi|
//      0x00000780|74 2e 31 2f 6d 79 72 65  61 64 65 6c 66 2d 63 31|t.1/myreadelf-c1|
//      0x00000790|31 00 70 53 65 63 74 48  65 61 64 65 72 00 70 5f|1.pSectHeader.p_|
//      0x000007a0|66 6c 61 67 73 00 66 75  6e 63 5f 73 65 63 74 5f|flags.func_sect_|
//      0x000007b0|67 6e 75 5f 76 65 72 73  69 6f 6e 5f 72 00 70 53|gnu_version_r.pS|
//      0x000007c0|65 63 74 44 61 74 61 00  5f 5f 73 79 73 63 61 6c|ectData.__syscal|
//      0x000007d0|6c 5f 73 6c 6f 6e 67 5f  74 00 5f 49 53 64 69 67|l_slong_t._ISdig|
//      0x000007e0|69 74 00 70 70 56 6f 69  64 50 74 72 00 78 6c 6f|it.ppVoidPtr.xlo|
//      0x000007f0|67 5f 69 6e 66 6f 5f 78  00 70 61 72 73 65 5f 65|g_info_x.parse_e|
//      0x00000800|6c 66 36 34 5f 65 6c 66  5f 68 65 61 64 65 72 00|lf64_elf_header.|
//      0x00000810|5f 49 53 73 70 61 63 65  00 5f 66 72 65 65 72 65|_ISspace._freere|
//      0x00000820|73 5f 62 75 66 00 78 6c  6f 67 5f 75 6e 69 6e 69|s_buf.xlog_unini|
//      0x00000830|74 00 70 5f 74 79 70 65  00 66 75 6e 63 5f 73 65|t.p_type.func_se|
//      0x00000840|63 74 5f 65 68 5f 66 72  61 6d 65 5f 68 64 72 00|ct_eh_frame_hdr.|
//      0x00000850|73 74 61 74 62 75 66 00  5f 5f 70 61 64 30 00 5f|statbuf.__pad0._|
//      0x00000860|5f 70 61 64 35 00 73 68  5f 6f 66 66 73 65 74 00|_pad5.sh_offset.|
//      0x00000870|5f 5f 67 6c 69 62 63 5f  72 65 73 65 72 76 65 64|__glibc_reserved|
//      0x00000880|00 66 75 6e 63 5f 73 65  63 74 5f 73 74 72 74 61|.func_sect_strta|
//      0x00000890|62 00 70 5f 76 61 64 64  72 00 62 65 66 6f 72 65|b.p_vaddr.before|
//      0x000008a0|5f 6d 61 69 6e 5f 66 75  6e 63 00 70 5f 6d 65 6d|_main_func.p_mem|
//      0x000008b0|73 7a 00 5f 76 74 61 62  6c 65 5f 6f 66 66 73 65|sz._vtable_offse|
//      0x000008c0|74 00 66 75 6e 63 5f 73  65 63 74 5f 64 65 62 75|t.func_sect_debu|
//      0x000008d0|67 5f 69 6e 66 6f 00 61  72 67 76 00 73 68 5f 6e|g_info.argv.sh_n|
//      0x000008e0|61 6d 65 00 5f 5f 67 69  64 5f 74 00 73 74 5f 63|ame.__gid_t.st_c|
//      0x000008f0|74 69 6d 65 6e 73 65 63  00 78 6c 6f 67 5f 68 65|timensec.xlog_he|
//      0x00000900|78 64 75 6d 70 00 70 50  72 6f 67 48 65 61 64 65|xdump.pProgHeade|
//      0x00000910|72 00 70 4e 61 6d 65 00  66 75 6e 63 5f 73 65 63|r.pName.func_sec|
//      0x00000920|74 5f 72 65 6c 61 5f 64  79 6e 00 72 5f 6f 66 66|t_rela_dyn.r_off|
//      0x00000930|73 65 74 00 73 74 5f 6f  74 68 65 72 00 65 5f 73|set.st_other.e_s|
//      0x00000940|68 6e 75 6d 00 6d 79 5f  66 69 6e 69 30 33 00 73|hnum.my_fini03.s|
//      0x00000950|74 5f 73 68 6e 64 78 00  5f 49 53 70 75 6e 63 74|t_shndx._ISpunct|
//      0x00000960|00 5f 5f 73 79 73 63 61  6c 6c 5f 75 6c 6f 6e 67|.__syscall_ulong|
//      0x00000970|5f 74 00 5f 49 4f 5f 72  65 61 64 5f 65 6e 64 00|_t._IO_read_end.|
//      0x00000980|6c 6f 67 5f 73 77 69 74  63 68 00 53 5f 45 6c 66|log_switch.S_Elf|
//      0x00000990|36 34 5f 53 79 6d 45 6e  74 5f 74 00 5f 49 53 70|64_SymEnt_t._ISp|
//      0x000009a0|72 69 6e 74 00 73 68 6f  72 74 20 69 6e 74 00 65|rint.short int.e|
//      0x000009b0|5f 70 68 65 6e 74 73 69  7a 65 00 70 5f 70 61 64|_phentsize.p_pad|
//      0x000009c0|64 72 00 70 70 52 65 6c  61 45 6e 74 00 78 6c 6f|dr.ppRelaEnt.xlo|
//      0x000009d0|67 5f 69 6e 69 74 00 65  5f 70 68 6e 75 6d 00 66|g_init.e_phnum.f|
//      0x000009e0|75 6e 63 5f 73 65 63 74  5f 67 6f 74 5f 70 6c 74|unc_sect_got_plt|
//      0x000009f0|00 73 68 5f 73 69 7a 65  00 5f 49 4f 5f 77 69 64|.sh_size._IO_wid|
//      0x00000a00|65 5f 64 61 74 61 00 6d  79 5f 66 69 6e 69 30 31|e_data.my_fini01|
//      0x00000a10|00 6d 79 5f 66 69 6e 69  30 32 00 70 73 74 72 5f|.my_fini02.pstr_|
//      0x00000a20|6e 61 6d 65 00 5f 5f 76  61 5f 6c 69 73 74 5f 74|name.__va_list_t|
//      0x00000a30|61 67 00 5f 5f 62 6c 6b  73 69 7a 65 5f 74 00 73|ag.__blksize_t.s|
//      0x00000a40|68 5f 61 64 64 72 00 69  5f 6c 65 6e 00 66 75 6e|h_addr.i_len.fun|
//      0x00000a50|63 5f 73 65 63 74 5f 63  6f 6d 6d 65 6e 74 00 66|c_sect_comment.f|
//      0x00000a60|70 5f 6f 66 66 73 65 74  00 73 74 5f 63 74 69 6d|p_offset.st_ctim|
//      0x00000a70|65 00 69 50 74 72 4d 61  78 43 6e 74 00 5f 49 53|e.iPtrMaxCnt._IS|
//      0x00000a80|67 72 61 70 68 00 69 50  74 72 43 6e 74 00 70 53|graph.iPtrCnt.pS|
//      0x00000a90|48 4e 61 6d 65 00 69 5f  72 6f 77 00 78 6c 6f 67|HName.i_row.xlog|
//      0x00000aa0|5f 69 6e 66 6f 00 5f 6f  6c 64 5f 6f 66 66 73 65|_info._old_offse|
//      0x00000ab0|74 00 5f 49 4f 5f 46 49  4c 45 00 70 66 75 6e 63|t._IO_FILE.pfunc|
//      0x00000ac0|5f 70 72 6f 63 65 73 73  00 72 65 67 5f 73 61 76|_process.reg_sav|
//      0x00000ad0|65 5f 61 72 65 61 00 73  68 5f 74 79 70 65 00 5f|e_area.sh_type._|
//      0x00000ae0|49 53 61 6c 70 68 61 00  66 75 6e 63 5f 73 65 63|ISalpha.func_sec|
//      0x00000af0|74 5f 65 68 5f 66 72 61  6d 65 00 69 5f 65 6c 66|t_eh_frame.i_elf|
//      0x00000b00|36 34 5f 6c 65 6e 00 72  5f 61 64 64 65 6e 64 00|64_len.r_addend.|
//      0x00000b10|65 5f 69 64 65 6e 74 00  66 75 6e 63 5f 73 65 63|e_ident.func_sec|
//      0x00000b20|74 5f 64 65 62 75 67 5f  61 72 61 6e 67 65 73 00|t_debug_aranges.|
//      0x00000b30|73 69 7a 65 5f 72 65 61  64 6f 6b 00 66 75 6e 63|size_readok.func|
//      0x00000b40|5f 73 65 63 74 5f 66 69  6e 69 5f 61 72 72 61 79|_sect_fini_array|
//      0x00000b50|00 75 6e 73 69 67 6e 65  64 20 63 68 61 72 00 73|.unsigned char.s|
//      0x00000b60|65 63 74 5f 66 75 6e 63  73 00 70 53 65 63 74 4e|ect_funcs.pSectN|
//      0x00000b70|61 6d 65 00 5f 49 4f 5f  77 72 69 74 65 5f 70 74|ame._IO_write_pt|
//      0x00000b80|72 00 66 75 6e 63 5f 73  65 63 74 5f 73 68 73 74|r.func_sect_shst|
//      0x00000b90|72 74 61 62 00 70 45 6c  66 44 61 74 61 00 50 72|rtab.pElfData.Pr|
//      0x00000ba0|74 53 65 63 74 48 65 61  64 65 72 00 65 5f 74 79|tSectHeader.e_ty|
//      0x00000bb0|70 65 00 70 53 65 63 74  5f 53 68 53 74 72 54 61|pe.pSect_ShStrTa|
//      0x00000bc0|62 5f 48 65 61 64 65 72  00 78 6c 6f 67 5f 6d 75|b_Header.xlog_mu|
//      0x00000bd0|74 65 78 5f 75 6e 6c 6f  63 6b 00 73 68 5f 66 6c|tex_unlock.sh_fl|
//      0x00000be0|61 67 73 00 5f 5f 74 69  6d 65 5f 74 00 65 5f 6d|ags.__time_t.e_m|
//      0x00000bf0|61 63 68 69 6e 65 00 5f  49 53 61 6c 6e 75 6d 00|achine._ISalnum.|
//      0x00000c00|73 74 5f 76 61 6c 75 65  00 5f 5f 75 69 64 5f 74|st_value.__uid_t|
//      0x00000c10|00 73 74 5f 73 69 7a 65  00 66 75 6e 63 5f 73 65|.st_size.func_se|
//      0x00000c20|63 74 5f 64 65 62 75 67  5f 6c 69 6e 65 00 73 74|ct_debug_line.st|
//      0x00000c30|5f 75 69 64 00 5f 5f 6f  66 66 5f 74 00 5f 49 53|_uid.__off_t._IS|
//      0x00000c40|62 6c 61 6e 6b 00 73 74  5f 64 65 76 00 70 53 65|blank.st_dev.pSe|
//      0x00000c50|63 74 48 65 61 64 65 72  73 44 61 74 61 00 73 68|ctHeadersData.sh|
//      0x00000c60|6f 72 74 20 75 6e 73 69  67 6e 65 64 20 69 6e 74|ort unsigned int|
//      0x00000c70|00 78 6c 6f 67 5f 6d 75  74 65 78 5f 6c 6f 63 6b|.xlog_mutex_lock|
//      0x00000c80|00 6d 61 69 6e 00 68 46  69 6c 65 00 5f 5f 62 75|.main.hFile.__bu|
//      0x00000c90|69 6c 74 69 6e 5f 76 61  5f 6c 69 73 74 00 53 5f|iltin_va_list.S_|
//      0x00000ca0|45 4c 46 36 34 5f 50 72  6f 67 48 65 61 64 65 72|ELF64_ProgHeader|
//      0x00000cb0|5f 74 00 66 75 6e 63 5f  73 65 63 74 5f 64 79 6e|_t.func_sect_dyn|
//      0x00000cc0|61 6d 69 63 00 5f 5f 66  75 6e 63 5f 5f 00 70 70|amic.__func__.pp|
//      0x00000cd0|53 65 63 74 48 65 61 64  65 72 73 00 45 6c 66 36|SectHeaders.Elf6|
//      0x00000ce0|34 5f 53 78 77 6f 72 64  00 5f 5f 62 6c 6b 63 6e|4_Sxword.__blkcn|
//      0x00000cf0|74 5f 74 00 69 4c 65 6e  00 5f 63 68 61 69 6e 00|t_t.iLen._chain.|
//      0x00000d00|5f 49 53 75 70 70 65 72  00 73 74 5f 72 64 65 76|_ISupper.st_rdev|
//      0x00000d10|00 73 68 5f 61 64 64 72  61 6c 69 67 6e 00 45 6c|.sh_addralign.El|
//      0x00000d20|66 36 34 5f 57 6f 72 64  00 5f 66 6c 61 67 73 32|f64_Word._flags2|
//      0x00000d30|00 73 74 5f 6e 61 6d 65  00 70 53 65 63 52 65 6c|.st_name.pSecRel|
//      0x00000d40|61 64 79 6e 42 6f 64 79  00 50 72 74 50 72 6f 67|adynBody.PrtProg|
//      0x00000d50|48 65 61 64 65 72 00 5f  63 75 72 5f 63 6f 6c 75|Header._cur_colu|
//      0x00000d60|6d 6e 00 70 44 61 74 61  53 74 61 72 74 00 5f 5f|mn.pDataStart.__|
//      0x00000d70|6f 66 66 36 34 5f 74 00  5f 75 6e 75 73 65 64 32|off64_t._unused2|
//      0x00000d80|00 5f 49 4f 5f 62 75 66  5f 62 61 73 65 00 ** **|._IO_buf_base.**|
//      =============================================================================
//
//      ===========================================================
//      >> ptr[000]=0x00562a0e3fa9a1; str={"Elf64_Addr"};
//      >> ptr[001]=0x00562a0e3fa9ac; str={"parse_elf64_prog_header"};
//      >> ptr[002]=0x00562a0e3fa9c4; str={"func_sect_note_gnu_build_id"};
//      >> ptr[003]=0x00562a0e3fa9e0; str={"get_elf64_data"};
//      >> ptr[004]=0x00562a0e3fa9ef; str={"test_char"};
//      >> ptr[005]=0x00562a0e3fa9f9; str={"_shortbuf"};
//      >> ptr[006]=0x00562a0e3faa03; str={"sh_link"};
//      >> ptr[007]=0x00562a0e3faa0b; str={"_IO_lock_t"};
//      >> ptr[008]=0x00562a0e3faa16; str={"gp_offset"};
//      >> ptr[009]=0x00562a0e3faa20; str={"parse_elf64_sect_body"};
//      >> ptr[010]=0x00562a0e3faa36; str={"stderr"};
//      >> ptr[011]=0x00562a0e3faa3d; str={"_IO_buf_end"};
//      >> ptr[012]=0x00562a0e3faa49; str={"iCnt"};
//      >> ptr[013]=0x00562a0e3faa4e; str={"st_atimensec"};
//      >> ptr[014]=0x00562a0e3faa5b; str={"e_shoff"};
//      >> ptr[015]=0x00562a0e3faa63; str={"pDynsymData"};
//      >> ptr[016]=0x00562a0e3faa6f; str={"after_main_func"};
//      >> ptr[017]=0x00562a0e3faa7f; str={"func_sect_fini"};
//      >> ptr[018]=0x00562a0e3faa8e; str={"S_ELF64_SectHeader_t"};
//      >> ptr[019]=0x00562a0e3faaa3; str={"_IO_write_end"};
//      >> ptr[020]=0x00562a0e3faab1; str={"func_sect_dynsym"};
//      >> ptr[021]=0x00562a0e3faac2; str={"func_sect_interp"};
//      >> ptr[022]=0x00562a0e3faad3; str={"parse_elf64_prog_headers"};
//      >> ptr[023]=0x00562a0e3faaec; str={"_freeres_list"};
//      >> ptr[024]=0x00562a0e3faafa; str={"st_blksize"};
//      >> ptr[025]=0x00562a0e3fab05; str={"e_version"};
//      >> ptr[026]=0x00562a0e3fab0f; str={"iret"};
//      >> ptr[027]=0x00562a0e3fab14; str={"S_Elf64_SectFunc_t"};
//      >> ptr[028]=0x00562a0e3fab27; str={"elf64_obj_size"};
//      >> ptr[029]=0x00562a0e3fab36; str={"e_phoff"};
//      >> ptr[030]=0x00562a0e3fab3e; str={"st_info"};
//      >> ptr[031]=0x00562a0e3fab46; str={"_markers"};
//      >> ptr[032]=0x00562a0e3fab4f; str={"e_ehsize"};
//      >> ptr[033]=0x00562a0e3fab58; str={"__nlink_t"};
//      >> ptr[034]=0x00562a0e3fab62; str={"func_sect_data"};
//      >> ptr[035]=0x00562a0e3fab71; str={"p_elf64_obj"};
//      >> ptr[036]=0x00562a0e3fab7d; str={"S_ELF64_ELFHeader_t"};
//      >> ptr[037]=0x00562a0e3fab91; str={"func_sect_got"};
//      >> ptr[038]=0x00562a0e3fab9f; str={"ui_level"};
//      >> ptr[039]=0x00562a0e3faba8; str={"e_shentsize"};
//      >> ptr[040]=0x00562a0e3fabb4; str={"func_sect_symtab"};
//      >> ptr[041]=0x00562a0e3fabc5; str={"__ino_t"};
//      >> ptr[042]=0x00562a0e3fabcd; str={"func_sect_debug_abbrev"};
//      >> ptr[043]=0x00562a0e3fabe4; str={"build_elf64_obj"};
//      >> ptr[044]=0x00562a0e3fabf4; str={"e_entry"};
//      >> ptr[045]=0x00562a0e3fabfc; str={"func_sect_debug_str"};
//      >> ptr[046]=0x00562a0e3fac10; str={"uint32_t"};
//      >> ptr[047]=0x00562a0e3fac19; str={"my_init01"};
//      >> ptr[048]=0x00562a0e3fac23; str={"my_init02"};
//      >> ptr[049]=0x00562a0e3fac2d; str={"my_init03"};
//      >> ptr[050]=0x00562a0e3fac37; str={"stdout"};
//      >> ptr[051]=0x00562a0e3fac3e; str={"_IO_save_end"};
//      >> ptr[052]=0x00562a0e3fac4b; str={"p_elf64_data"};
//      >> ptr[053]=0x00562a0e3fac58; str={"func_sect_gnu_version"};
//      >> ptr[054]=0x00562a0e3fac6e; str={"ppSymEnt"};
//      >> ptr[055]=0x00562a0e3fac77; str={"p_data"};
//      >> ptr[056]=0x00562a0e3fac7e; str={"_IO_codecvt"};
//      >> ptr[057]=0x00562a0e3fac8a; str={"func_sect_text"};
//      >> ptr[058]=0x00562a0e3fac99; str={"pProgHeadersData"};
//      >> ptr[059]=0x00562a0e3facaa; str={"parse_args"};
//      >> ptr[060]=0x00562a0e3facb5; str={"overflow_arg_area"};
//      >> ptr[061]=0x00562a0e3facc7; str={"pSecRelapltBody"};
//      >> ptr[062]=0x00562a0e3facd7; str={"long long unsigned int"};
//      >> ptr[063]=0x00562a0e3facee; str={"st_blocks"};
//      >> ptr[064]=0x00562a0e3facf8; str={"func_sect_note_ABI_tag"};
//      >> ptr[065]=0x00562a0e3fad0f; str={"xlog_core"};
//      >> ptr[066]=0x00562a0e3fad19; str={"p_filesz"};
//      >> ptr[067]=0x00562a0e3fad22; str={"st_mtime"};
//      >> ptr[068]=0x00562a0e3fad2b; str={"func_sect_init_array"};
//      >> ptr[069]=0x00562a0e3fad40; str={"DumpPtr2Str"};
//      >> ptr[070]=0x00562a0e3fad4c; str={"_IO_backup_base"};
//      >> ptr[071]=0x00562a0e3fad5c; str={"ProgHeaderObjs"};
//      >> ptr[072]=0x00562a0e3fad6b; str={"s_elf64_obj_t"};
//      >> ptr[073]=0x00562a0e3fad79; str={"xlog_ptrdump"};
//      >> ptr[074]=0x00562a0e3fad86; str={"pProgHeaderData"};
//      >> ptr[075]=0x00562a0e3fad96; str={"_ISlower"};
//      >> ptr[076]=0x00562a0e3fad9f; str={"_fileno"};
//      >> ptr[077]=0x00562a0e3fada7; str={"stat"};
//      >> ptr[078]=0x00562a0e3fadac; str={"ppProgHeaders"};
//      >> ptr[079]=0x00562a0e3fadba; str={"ElfHeaderObj"};
//      >> ptr[080]=0x00562a0e3fadc7; str={"func_sect_note_gnu_build"};
//      >> ptr[081]=0x00562a0e3fade0; str={"__gnuc_va_list"};
//      >> ptr[082]=0x00562a0e3fadef; str={"func_sect_gnu_hash"};
//      >> ptr[083]=0x00562a0e3fae02; str={"__mode_t"};
//      >> ptr[084]=0x00562a0e3fae0b; str={"pData"};
//      >> ptr[085]=0x00562a0e3fae11; str={"parse_elf64_sect_headers"};
//      >> ptr[086]=0x00562a0e3fae2a; str={"_ISxdigit"};
//      >> ptr[087]=0x00562a0e3fae34; str={"_IO_read_base"};
//      >> ptr[088]=0x00562a0e3fae42; str={"parse_elf64_sect_header"};
//      >> ptr[089]=0x00562a0e3fae5a; str={"func_sect_note_gnu_prope"};
//      >> ptr[090]=0x00562a0e3fae73; str={"st_gid"};
//      >> ptr[091]=0x00562a0e3fae7a; str={"argc"};
//      >> ptr[092]=0x00562a0e3fae7f; str={"stdin"};
//      >> ptr[093]=0x00562a0e3fae85; str={"GNU C11 9.4.0 -mtune=generic -march=x86-64 -g -O0 -std=c11 -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection"};
//      >> ptr[094]=0x00562a0e3faf1f; str={"st_mode"};
//      >> ptr[095]=0x00562a0e3faf27; str={"Elf64_Half"};
//      >> ptr[096]=0x00562a0e3faf32; str={"st_nlink"};
//      >> ptr[097]=0x00562a0e3faf3b; str={"sh_entsize"};
//      >> ptr[098]=0x00562a0e3faf46; str={"myreadelf-0.1.08.c"};
//      >> ptr[099]=0x00562a0e3faf59; str={"exit"};
//      >> ptr[100]=0x00562a0e3faf5e; str={"r_info"};
//      >> ptr[101]=0x00562a0e3faf65; str={"SectHeaderObjs"};
//      >> ptr[102]=0x00562a0e3faf74; str={"pDynStrData"};
//      >> ptr[103]=0x00562a0e3faf80; str={"func_sect_bss"};
//      >> ptr[104]=0x00562a0e3faf8e; str={"filename"};
//      >> ptr[105]=0x00562a0e3faf97; str={"e_flags"};
//      >> ptr[106]=0x00562a0e3faf9f; str={"_IO_marker"};
//      >> ptr[107]=0x00562a0e3fafaa; str={"_IO_read_ptr"};
//      >> ptr[108]=0x00562a0e3fafb7; str={"p_align"};
//      >> ptr[109]=0x00562a0e3fafbf; str={"func_sect_rela_plt"};
//      >> ptr[110]=0x00562a0e3fafd2; str={"st_atime"};
//      >> ptr[111]=0x00562a0e3fafdb; str={"sh_info"};
//      >> ptr[112]=0x00562a0e3fafe3; str={"e_shstrndx"};
//      >> ptr[113]=0x00562a0e3fafee; str={"__PRETTY_FUNCTION__"};
//      >> ptr[114]=0x00562a0e3fb002; str={"func_sect_rodata"};
//      >> ptr[115]=0x00562a0e3fb013; str={"parse_elf64_sect_bodys"};
//      >> ptr[116]=0x00562a0e3fb02a; str={"uint8_t"};
//      >> ptr[117]=0x00562a0e3fb032; str={"func_sect_init"};
//      >> ptr[118]=0x00562a0e3fb041; str={"st_ino"};
//      >> ptr[119]=0x00562a0e3fb048; str={"S_Elf64_Rela_t"};
//      >> ptr[120]=0x00562a0e3fb057; str={"func_sect_dynstr"};
//      >> ptr[121]=0x00562a0e3fb068; str={"pElfHeader"};
//      >> ptr[122]=0x00562a0e3fb073; str={"Elf64_Xword"};
//      >> ptr[123]=0x00562a0e3fb07f; str={"_IO_write_base"};
//      >> ptr[124]=0x00562a0e3fb08e; str={"pSectNames"};
//      >> ptr[125]=0x00562a0e3fb099; str={"long long int"};
//      >> ptr[126]=0x00562a0e3fb0a7; str={"func_sect_plt_got"};
//      >> ptr[127]=0x00562a0e3fb0b9; str={"st_mtimensec"};
//      >> ptr[128]=0x00562a0e3fb0c6; str={"Elf64_Off"};
//      >> ptr[129]=0x00562a0e3fb0d0; str={"_IO_save_base"};
//      >> ptr[130]=0x00562a0e3fb0de; str={"__dev_t"};
//      >> ptr[131]=0x00562a0e3fb0e6; str={"func_sect_plt"};
//      >> ptr[132]=0x00562a0e3fb0f4; str={"_IScntrl"};
//      >> ptr[133]=0x00562a0e3fb0fd; str={"pSectHeaderData"};
//      >> ptr[134]=0x00562a0e3fb10d; str={"/home/xadmin/xwks.git.1/myreadelf-c11"};
//      >> ptr[135]=0x00562a0e3fb133; str={"pSectHeader"};
//      >> ptr[136]=0x00562a0e3fb13f; str={"p_flags"};
//      >> ptr[137]=0x00562a0e3fb147; str={"func_sect_gnu_version_r"};
//      >> ptr[138]=0x00562a0e3fb15f; str={"pSectData"};
//      >> ptr[139]=0x00562a0e3fb169; str={"__syscall_slong_t"};
//      >> ptr[140]=0x00562a0e3fb17b; str={"_ISdigit"};
//      >> ptr[141]=0x00562a0e3fb184; str={"ppVoidPtr"};
//      >> ptr[142]=0x00562a0e3fb18e; str={"xlog_info_x"};
//      >> ptr[143]=0x00562a0e3fb19a; str={"parse_elf64_elf_header"};
//      >> ptr[144]=0x00562a0e3fb1b1; str={"_ISspace"};
//      >> ptr[145]=0x00562a0e3fb1ba; str={"_freeres_buf"};
//      >> ptr[146]=0x00562a0e3fb1c7; str={"xlog_uninit"};
//      >> ptr[147]=0x00562a0e3fb1d3; str={"p_type"};
//      >> ptr[148]=0x00562a0e3fb1da; str={"func_sect_eh_frame_hdr"};
//      >> ptr[149]=0x00562a0e3fb1f1; str={"statbuf"};
//      >> ptr[150]=0x00562a0e3fb1f9; str={"__pad0"};
//      >> ptr[151]=0x00562a0e3fb200; str={"__pad5"};
//      >> ptr[152]=0x00562a0e3fb207; str={"sh_offset"};
//      >> ptr[153]=0x00562a0e3fb211; str={"__glibc_reserved"};
//      >> ptr[154]=0x00562a0e3fb222; str={"func_sect_strtab"};
//      >> ptr[155]=0x00562a0e3fb233; str={"p_vaddr"};
//      >> ptr[156]=0x00562a0e3fb23b; str={"before_main_func"};
//      >> ptr[157]=0x00562a0e3fb24c; str={"p_memsz"};
//      >> ptr[158]=0x00562a0e3fb254; str={"_vtable_offset"};
//      >> ptr[159]=0x00562a0e3fb263; str={"func_sect_debug_info"};
//      >> ptr[160]=0x00562a0e3fb278; str={"argv"};
//      >> ptr[161]=0x00562a0e3fb27d; str={"sh_name"};
//      >> ptr[162]=0x00562a0e3fb285; str={"__gid_t"};
//      >> ptr[163]=0x00562a0e3fb28d; str={"st_ctimensec"};
//      >> ptr[164]=0x00562a0e3fb29a; str={"xlog_hexdump"};
//      >> ptr[165]=0x00562a0e3fb2a7; str={"pProgHeader"};
//      >> ptr[166]=0x00562a0e3fb2b3; str={"pName"};
//      >> ptr[167]=0x00562a0e3fb2b9; str={"func_sect_rela_dyn"};
//      >> ptr[168]=0x00562a0e3fb2cc; str={"r_offset"};
//      >> ptr[169]=0x00562a0e3fb2d5; str={"st_other"};
//      >> ptr[170]=0x00562a0e3fb2de; str={"e_shnum"};
//      >> ptr[171]=0x00562a0e3fb2e6; str={"my_fini03"};
//      >> ptr[172]=0x00562a0e3fb2f0; str={"st_shndx"};
//      >> ptr[173]=0x00562a0e3fb2f9; str={"_ISpunct"};
//      >> ptr[174]=0x00562a0e3fb302; str={"__syscall_ulong_t"};
//      >> ptr[175]=0x00562a0e3fb314; str={"_IO_read_end"};
//      >> ptr[176]=0x00562a0e3fb321; str={"log_switch"};
//      >> ptr[177]=0x00562a0e3fb32c; str={"S_Elf64_SymEnt_t"};
//      >> ptr[178]=0x00562a0e3fb33d; str={"_ISprint"};
//      >> ptr[179]=0x00562a0e3fb346; str={"short int"};
//      >> ptr[180]=0x00562a0e3fb350; str={"e_phentsize"};
//      >> ptr[181]=0x00562a0e3fb35c; str={"p_paddr"};
//      >> ptr[182]=0x00562a0e3fb364; str={"ppRelaEnt"};
//      >> ptr[183]=0x00562a0e3fb36e; str={"xlog_init"};
//      >> ptr[184]=0x00562a0e3fb378; str={"e_phnum"};
//      >> ptr[185]=0x00562a0e3fb380; str={"func_sect_got_plt"};
//      >> ptr[186]=0x00562a0e3fb392; str={"sh_size"};
//      >> ptr[187]=0x00562a0e3fb39a; str={"_IO_wide_data"};
//      >> ptr[188]=0x00562a0e3fb3a8; str={"my_fini01"};
//      >> ptr[189]=0x00562a0e3fb3b2; str={"my_fini02"};
//      >> ptr[190]=0x00562a0e3fb3bc; str={"pstr_name"};
//      >> ptr[191]=0x00562a0e3fb3c6; str={"__va_list_tag"};
//      >> ptr[192]=0x00562a0e3fb3d4; str={"__blksize_t"};
//      >> ptr[193]=0x00562a0e3fb3e0; str={"sh_addr"};
//      >> ptr[194]=0x00562a0e3fb3e8; str={"i_len"};
//      >> ptr[195]=0x00562a0e3fb3ee; str={"func_sect_comment"};
//      >> ptr[196]=0x00562a0e3fb400; str={"fp_offset"};
//      >> ptr[197]=0x00562a0e3fb40a; str={"st_ctime"};
//      >> ptr[198]=0x00562a0e3fb413; str={"iPtrMaxCnt"};
//      >> ptr[199]=0x00562a0e3fb41e; str={"_ISgraph"};
//      >> ptr[200]=0x00562a0e3fb427; str={"iPtrCnt"};
//      >> ptr[201]=0x00562a0e3fb42f; str={"pSHName"};
//      >> ptr[202]=0x00562a0e3fb437; str={"i_row"};
//      >> ptr[203]=0x00562a0e3fb43d; str={"xlog_info"};
//      >> ptr[204]=0x00562a0e3fb447; str={"_old_offset"};
//      >> ptr[205]=0x00562a0e3fb453; str={"_IO_FILE"};
//      >> ptr[206]=0x00562a0e3fb45c; str={"pfunc_process"};
//      >> ptr[207]=0x00562a0e3fb46a; str={"reg_save_area"};
//      >> ptr[208]=0x00562a0e3fb478; str={"sh_type"};
//      >> ptr[209]=0x00562a0e3fb480; str={"_ISalpha"};
//      >> ptr[210]=0x00562a0e3fb489; str={"func_sect_eh_frame"};
//      >> ptr[211]=0x00562a0e3fb49c; str={"i_elf64_len"};
//      >> ptr[212]=0x00562a0e3fb4a8; str={"r_addend"};
//      >> ptr[213]=0x00562a0e3fb4b1; str={"e_ident"};
//      >> ptr[214]=0x00562a0e3fb4b9; str={"func_sect_debug_aranges"};
//      >> ptr[215]=0x00562a0e3fb4d1; str={"size_readok"};
//      >> ptr[216]=0x00562a0e3fb4dd; str={"func_sect_fini_array"};
//      >> ptr[217]=0x00562a0e3fb4f2; str={"unsigned char"};
//      >> ptr[218]=0x00562a0e3fb500; str={"sect_funcs"};
//      >> ptr[219]=0x00562a0e3fb50b; str={"pSectName"};
//      >> ptr[220]=0x00562a0e3fb515; str={"_IO_write_ptr"};
//      >> ptr[221]=0x00562a0e3fb523; str={"func_sect_shstrtab"};
//      >> ptr[222]=0x00562a0e3fb536; str={"pElfData"};
//      >> ptr[223]=0x00562a0e3fb53f; str={"PrtSectHeader"};
//      >> ptr[224]=0x00562a0e3fb54d; str={"e_type"};
//      >> ptr[225]=0x00562a0e3fb554; str={"pSect_ShStrTab_Header"};
//      >> ptr[226]=0x00562a0e3fb56a; str={"xlog_mutex_unlock"};
//      >> ptr[227]=0x00562a0e3fb57c; str={"sh_flags"};
//      >> ptr[228]=0x00562a0e3fb585; str={"__time_t"};
//      >> ptr[229]=0x00562a0e3fb58e; str={"e_machine"};
//      >> ptr[230]=0x00562a0e3fb598; str={"_ISalnum"};
//      >> ptr[231]=0x00562a0e3fb5a1; str={"st_value"};
//      >> ptr[232]=0x00562a0e3fb5aa; str={"__uid_t"};
//      >> ptr[233]=0x00562a0e3fb5b2; str={"st_size"};
//      >> ptr[234]=0x00562a0e3fb5ba; str={"func_sect_debug_line"};
//      >> ptr[235]=0x00562a0e3fb5cf; str={"st_uid"};
//      >> ptr[236]=0x00562a0e3fb5d6; str={"__off_t"};
//      >> ptr[237]=0x00562a0e3fb5de; str={"_ISblank"};
//      >> ptr[238]=0x00562a0e3fb5e7; str={"st_dev"};
//      >> ptr[239]=0x00562a0e3fb5ee; str={"pSectHeadersData"};
//      >> ptr[240]=0x00562a0e3fb5ff; str={"short unsigned int"};
//      >> ptr[241]=0x00562a0e3fb612; str={"xlog_mutex_lock"};
//      >> ptr[242]=0x00562a0e3fb622; str={"main"};
//      >> ptr[243]=0x00562a0e3fb627; str={"hFile"};
//      >> ptr[244]=0x00562a0e3fb62d; str={"__builtin_va_list"};
//      >> ptr[245]=0x00562a0e3fb63f; str={"S_ELF64_ProgHeader_t"};
//      >> ptr[246]=0x00562a0e3fb654; str={"func_sect_dynamic"};
//      >> ptr[247]=0x00562a0e3fb666; str={"__func__"};
//      >> ptr[248]=0x00562a0e3fb66f; str={"ppSectHeaders"};
//      >> ptr[249]=0x00562a0e3fb67d; str={"Elf64_Sxword"};
//      >> ptr[250]=0x00562a0e3fb68a; str={"__blkcnt_t"};
//      >> ptr[251]=0x00562a0e3fb695; str={"iLen"};
//      >> ptr[252]=0x00562a0e3fb69a; str={"_chain"};
//      >> ptr[253]=0x00562a0e3fb6a1; str={"_ISupper"};
//      >> ptr[254]=0x00562a0e3fb6aa; str={"st_rdev"};
//      >> ptr[255]=0x00562a0e3fb6b2; str={"sh_addralign"};
//      >> ptr[256]=0x00562a0e3fb6bf; str={"Elf64_Word"};
//      >> ptr[257]=0x00562a0e3fb6ca; str={"_flags2"};
//      >> ptr[258]=0x00562a0e3fb6d2; str={"st_name"};
//      >> ptr[259]=0x00562a0e3fb6da; str={"pSecReladynBody"};
//      >> ptr[260]=0x00562a0e3fb6ea; str={"PrtProgHeader"};
//      >> ptr[261]=0x00562a0e3fb6f8; str={"_cur_column"};
//      >> ptr[262]=0x00562a0e3fb704; str={"pDataStart"};
//      >> ptr[263]=0x00562a0e3fb70f; str={"__off64_t"};
//      >> ptr[264]=0x00562a0e3fb719; str={"_unused2"};
//      >> ptr[265]=0x00562a0e3fb722; str={"_IO_buf_base"};
//      >> ptr[266]=0x00562a0e3fb72f; str={"�"};
//      ===========================================================

int func_sect_symtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    unsigned char* pSymTabData = pData;
    struct S_Elf64_SymEnt_t** ppSymEnt = (struct S_Elf64_SymEnt_t**)malloc((pSectHeader->sh_size+1)*(sizeof(struct S_Elf64_SymEnt_t*)));
    
    printf("\n");
    printf("Symbol table '.symtab' contains %d entries:\n", (int)(pSectHeader->sh_size/pSectHeader->sh_entsize));
    printf("   Num:    Value  Size Type    Bind   Vis      Ndx  Name  NameStr\n");
    for(int i=0; i<(pSectHeader->sh_size/pSectHeader->sh_entsize); i++)
    {
        struct S_Elf64_SymEnt_t* pSymEnt = (struct S_Elf64_SymEnt_t*)(pSymTabData + sizeof(struct S_Elf64_SymEnt_t)*i);
        if(1)
        {
            printf("   \e[1m%03d: %8llx %5lld  %02x      %02x    %02x       %04x %04x  %s\e[0m\n", i, 
                                        pSymEnt->st_value, 
                                        pSymEnt->st_size, 
                                        (ELF64_ST_TYPE(pSymEnt->st_info)), 
                                        (ELF64_ST_BIND(pSymEnt->st_info)), 
                                        (ELF64_ST_VISIBILITY(pSymEnt->st_other)), 
                                        pSymEnt->st_shndx,
                                        pSymEnt->st_name,
                                        "tempstr"
                    );
        }
        *(ppSymEnt+i) = pSymEnt;
    }
    
    return 0;
}

//  >> func{parse_elf64_sect_body:(02390)} is call. 
//      {idx=34,sect_name=".symtab",pSectData=0x559e89512920,iLen=0x13e0}
//    >> func{func_sect_symtab:(02156)} is call .
//        No.[34]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e895151f0
//        {
//             Elf64_Word    sh_name      = 0x1;
//             Elf64_Word    sh_type      = 0x2;
//             Elf64_Xword   sh_flags     = 0x0;
//             Elf64_Addr    sh_addr      = 0x0;
//             Elf64_Off     sh_offset    = 0xe090;
//             Elf64_Xword   sh_size      = 0x13e0;
//             Elf64_Word    sh_link      = 0x23;
//             Elf64_Word    sh_info      = 0x6b;
//             Elf64_Xword   sh_addralign = 0x8;
//             Elf64_Xword   sh_entsize   = 0x18;
//        }
//
//0x00559e89512920|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
//      0x00000010|00 00 00 00 00 00 00 00  00 00 00 00 03 00 01 00|................|
//      0x00000020|18 03 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
//      0x00000030|00 00 00 00 03 00 02 00  38 03 00 00 00 00 00 00|........8.......|
//      0x00000040|00 00 00 00 00 00 00 00  00 00 00 00 03 00 03 00|................|
// ... ...
//      0x00001380|ae 0a 00 00 22 00 00 00  00 00 00 00 00 00 00 00|...."...........|
//      0x00001390|00 00 00 00 00 00 00 00  ca 0a 00 00 12 00 10 00|................|
//      0x000013a0|44 45 00 00 00 00 00 00  68 00 00 00 00 00 00 00|DE......h.......|
//      0x000013b0|dc 0a 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
//      0x000013c0|00 00 00 00 00 00 00 00  f5 0a 00 00 12 00 10 00|................|
//      0x000013d0|e4 46 00 00 00 00 00 00  68 00 00 00 00 00 00 00|.F......h.......|
//      =============================================================================
//
//
//Symbol table '.symtab' contains 212 entries:
//   Num:    Value  Size Type    Bind   Vis      Ndx  Name  NameStr
//   000:        0     0  00      00    00       0000 0000  tempstr
//   001:      318     0  03      00    00       0001 0000  tempstr
//   002:      338     0  03      00    00       0002 0000  tempstr
//   003:      358     0  03      00    00       0003 0000  tempstr
//   004:      37c     0  03      00    00       0004 0000  tempstr
// ... ...
//   192:     41fd   104  02      01    00       0010 098b  tempstr
//   193:     5073    81  02      01    00       0010 099d  tempstr
//   194:     2dfb   649  02      01    00       0010 09ae  tempstr
//   195:     4614   104  02      01    00       0010 09c5  tempstr
//   196:     3f33   402  02      01    00       0010 09d7  tempstr
//   197:     2355    65  02      01    00       0010 09ea  tempstr
//   198:     a280     0  01      01    02       0019 09f4  tempstr
//   199:     3084    37  02      01    00       0010 0a00  tempstr
//   200:        0     0  00      02    00       0000 0a18  tempstr
//   201:     4b6e   287  02      01    00       0010 0a32  tempstr
//   202:     45ac   104  02      01    00       0010 0a48  tempstr
//   203:     3a78   487  02      01    00       0010 0a56  tempstr
//   204:     40c5   104  02      01    00       0010 0a67  tempstr
//   205:     286b   302  02      01    00       0010 0a76  tempstr
//   206:     365e    66  02      01    00       0010 0a80  tempstr
//   207:     3934    66  02      01    00       0010 0a99  tempstr
//   208:        0     0  02      02    00       0000 0aae  tempstr
//   209:     4544   104  02      01    00       0010 0aca  tempstr
//   210:        0     0  02      01    00       0000 0adc  tempstr
//   211:     46e4   104  02      01    00       0010 0af5  tempstr


int func_sect_strtab             (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen);
    
    DumpPtr2Str(pData, iLen, 500);
    
    return 0;
}

//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=35,sect_name=".strtab",pSectData=0x562a0e3fcae0,iLen=0xabc}
//    >> func{func_sect_strtab:(01428)} is call .
//        No.[35]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x562a0e3fdfc8
//        {
//             Elf64_Word    sh_name      = 0x9;
//             Elf64_Word    sh_type      = 0x3;
//             Elf64_Xword   sh_flags     = 0x0;
//             Elf64_Addr    sh_addr      = 0x0;
//             Elf64_Off     sh_offset    = 0xf250;
//             Elf64_Xword   sh_size      = 0xabc;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x1;
//             Elf64_Xword   sh_entsize   = 0x0;
//        }
//
//0x00562a0e3fcae0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|00 63 72 74 73 74 75 66  66 2e 63 00 64 65 72 65|.crtstuff.c.dere|
//      0x00000010|67 69 73 74 65 72 5f 74  6d 5f 63 6c 6f 6e 65 73|gister_tm_clones|
//      0x00000020|00 5f 5f 64 6f 5f 67 6c  6f 62 61 6c 5f 64 74 6f|.__do_global_dto|
//      0x00000030|72 73 5f 61 75 78 00 63  6f 6d 70 6c 65 74 65 64|rs_aux.completed|
//      0x00000040|2e 38 30 36 31 00 5f 5f  64 6f 5f 67 6c 6f 62 61|.8061.__do_globa|
//      0x00000050|6c 5f 64 74 6f 72 73 5f  61 75 78 5f 66 69 6e 69|l_dtors_aux_fini|
//      0x00000060|5f 61 72 72 61 79 5f 65  6e 74 72 79 00 66 72 61|_array_entry.fra|
//      0x00000070|6d 65 5f 64 75 6d 6d 79  00 5f 5f 66 72 61 6d 65|me_dummy.__frame|
// ... ...
//      0x000009d0|00 5f 49 54 4d 5f 72 65  67 69 73 74 65 72 54 4d|._ITM_registerTM|
//      0x000009e0|43 6c 6f 6e 65 54 61 62  6c 65 00 70 61 72 73 65|CloneTable.parse|
//      0x000009f0|5f 65 6c 66 36 34 5f 73  65 63 74 5f 62 6f 64 79|_elf64_sect_body|
//      0x00000a00|00 66 75 6e 63 5f 73 65  63 74 5f 67 6f 74 00 66|.func_sect_got.f|
//      0x00000a10|75 6e 63 5f 73 65 63 74  5f 64 79 6e 73 79 6d 00|unc_sect_dynsym.|
//      0x00000a20|66 75 6e 63 5f 73 65 63  74 5f 69 6e 69 74 00 78|func_sect_init.x|
//      0x00000a30|6c 6f 67 5f 69 6e 66 6f  00 66 75 6e 63 5f 73 65|log_info.func_se|
//      0x00000a40|63 74 5f 6e 6f 74 65 5f  67 6e 75 5f 62 75 69 6c|ct_note_gnu_buil|
//      0x00000a50|64 00 66 75 6e 63 5f 73  65 63 74 5f 64 65 62 75|d.func_sect_debu|
//      0x00000a60|67 5f 6c 69 6e 65 00 5f  5f 63 78 61 5f 66 69 6e|g_line.__cxa_fin|
//      0x00000a70|61 6c 69 7a 65 40 40 47  4c 49 42 43 5f 32 2e 32|alize@@GLIBC_2.2|
//      0x00000a80|2e 35 00 66 75 6e 63 5f  73 65 63 74 5f 64 79 6e|.5.func_sect_dyn|
//      0x00000a90|61 6d 69 63 00 5f 5f 63  74 79 70 65 5f 62 5f 6c|amic.__ctype_b_l|
//      0x00000aa0|6f 63 40 40 47 4c 49 42  43 5f 32 2e 33 00 66 75|oc@@GLIBC_2.3.fu|
//      0x00000ab0|6e 63 5f 73 65 63 74 5f  62 73 73 00 ** ** ** **|nc_sect_bss.****|
//      =============================================================================
//
//      ===========================================================
//      >> ptr[000]=0x00562a0e3fcae1; str={"crtstuff.c"};
//      >> ptr[001]=0x00562a0e3fcaec; str={"deregister_tm_clones"};
//      >> ptr[002]=0x00562a0e3fcb01; str={"__do_global_dtors_aux"};
//      >> ptr[003]=0x00562a0e3fcb17; str={"completed.8061"};
//      >> ptr[004]=0x00562a0e3fcb26; str={"__do_global_dtors_aux_fini_array_entry"};
//      >> ptr[005]=0x00562a0e3fcb4d; str={"frame_dummy"};
//      >> ptr[006]=0x00562a0e3fcb59; str={"__frame_dummy_init_array_entry"};
//      >> ptr[007]=0x00562a0e3fcb78; str={"myreadelf-0.1.08.c"};
//      >> ptr[008]=0x00562a0e3fcb8b; str={"__func__.2504"};
//      >> ptr[009]=0x00562a0e3fcb99; str={"__func__.2522"};
//      >> ptr[010]=0x00562a0e3fcba7; str={"__PRETTY_FUNCTION__.2526"};
//      >> ptr[011]=0x00562a0e3fcbc0; str={"__func__.2545"};
//      >> ptr[012]=0x00562a0e3fcbce; str={"__PRETTY_FUNCTION__.2549"};
//      >> ptr[013]=0x00562a0e3fcbe7; str={"__func__.2795"};
//      >> ptr[014]=0x00562a0e3fcbf5; str={"__func__.2803"};
//      >> ptr[015]=0x00562a0e3fcc03; str={"__func__.2811"};
//      >> ptr[016]=0x00562a0e3fcc11; str={"__func__.2819"};
//      >> ptr[017]=0x00562a0e3fcc1f; str={"__func__.2827"};
// ... ...
//      >> ptr[157]=0x00562a0e3fd50f; str={"xlog_info"};
//      >> ptr[158]=0x00562a0e3fd519; str={"func_sect_note_gnu_build"};
//      >> ptr[159]=0x00562a0e3fd532; str={"func_sect_debug_line"};
//      >> ptr[160]=0x00562a0e3fd547; str={"__cxa_finalize@@GLIBC_2.2.5"};
//      >> ptr[161]=0x00562a0e3fd563; str={"func_sect_dynamic"};
//      >> ptr[162]=0x00562a0e3fd575; str={"__ctype_b_loc@@GLIBC_2.3"};
//      >> ptr[163]=0x00562a0e3fd58e; str={"func_sect_bss"};
//      ===========================================================

int func_sect_shstrtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader)
{
    xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);
    
    PrtSectHeader(idx, pSectHeader);
    
    xlog_hexdump(pData, iLen+0x20);
    
    DumpPtr2Str(pData, iLen, 100);
    
    return 0;
}

//  >> func{parse_elf64_sect_body:(01466)} is call. 
//      {idx=36,sect_name=".shstrtab",pSectData=0x562a0e3fd59c,iLen=0x168}
//    >> func{func_sect_shstrtab:(01441)} is call .
//        No.[36]--------------------------------------------
//        struct S_ELF64_SectHeader_t * pSectHeader = 0x562a0e3fe008
//        {
//             Elf64_Word    sh_name      = 0x11;
//             Elf64_Word    sh_type      = 0x3;
//             Elf64_Xword   sh_flags     = 0x0;
//             Elf64_Addr    sh_addr      = 0x0;
//             Elf64_Off     sh_offset    = 0xfd0c;
//             Elf64_Xword   sh_size      = 0x168;
//             Elf64_Word    sh_link      = 0x0;
//             Elf64_Word    sh_info      = 0x0;
//             Elf64_Xword   sh_addralign = 0x1;
//             Elf64_Xword   sh_entsize   = 0x0;
//        }
//
//0x00562a0e3fd59c|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
//      =============================================================================
//      0x00000000|00 2e 73 79 6d 74 61 62  00 2e 73 74 72 74 61 62|..symtab..strtab|
//      0x00000010|00 2e 73 68 73 74 72 74  61 62 00 2e 69 6e 74 65|..shstrtab..inte|
//      0x00000020|72 70 00 2e 6e 6f 74 65  2e 67 6e 75 2e 70 72 6f|rp..note.gnu.pro|
//      0x00000030|70 65 72 74 79 00 2e 6e  6f 74 65 2e 67 6e 75 2e|perty..note.gnu.|
//      0x00000040|62 75 69 6c 64 2d 69 64  00 2e 6e 6f 74 65 2e 41|build-id..note.A|
//      0x00000050|42 49 2d 74 61 67 00 2e  67 6e 75 2e 68 61 73 68|BI-tag..gnu.hash|
//      0x00000060|00 2e 64 79 6e 73 79 6d  00 2e 64 79 6e 73 74 72|..dynsym..dynstr|
//      0x00000070|00 2e 67 6e 75 2e 76 65  72 73 69 6f 6e 00 2e 67|..gnu.version..g|
//      0x00000080|6e 75 2e 76 65 72 73 69  6f 6e 5f 72 00 2e 72 65|nu.version_r..re|
//      0x00000090|6c 61 2e 64 79 6e 00 2e  72 65 6c 61 2e 70 6c 74|la.dyn..rela.plt|
//      0x000000a0|00 2e 69 6e 69 74 00 2e  70 6c 74 2e 67 6f 74 00|..init..plt.got.|
//      0x000000b0|2e 70 6c 74 2e 73 65 63  00 2e 74 65 78 74 00 2e|.plt.sec..text..|
//      0x000000c0|66 69 6e 69 00 2e 72 6f  64 61 74 61 00 2e 65 68|fini..rodata..eh|
//      0x000000d0|5f 66 72 61 6d 65 5f 68  64 72 00 2e 65 68 5f 66|_frame_hdr..eh_f|
//      0x000000e0|72 61 6d 65 00 2e 69 6e  69 74 5f 61 72 72 61 79|rame..init_array|
//      0x000000f0|00 2e 66 69 6e 69 5f 61  72 72 61 79 00 2e 64 79|..fini_array..dy|
//      0x00000100|6e 61 6d 69 63 00 2e 64  61 74 61 00 2e 62 73 73|namic..data..bss|
//      0x00000110|00 2e 63 6f 6d 6d 65 6e  74 00 2e 64 65 62 75 67|..comment..debug|
//      0x00000120|5f 61 72 61 6e 67 65 73  00 2e 64 65 62 75 67 5f|_aranges..debug_|
//      0x00000130|69 6e 66 6f 00 2e 64 65  62 75 67 5f 61 62 62 72|info..debug_abbr|
//      0x00000140|65 76 00 2e 64 65 62 75  67 5f 6c 69 6e 65 00 2e|ev..debug_line..|
//      0x00000150|64 65 62 75 67 5f 73 74  72 00 2e 64 65 62 75 67|debug_str..debug|
//      0x00000160|5f 72 61 6e 67 65 73 00  00 00 00 00 00 00 00 00|_ranges.........|
//      0x00000170|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
//      0x00000180|00 00 00 00 00 00 00 00  ** ** ** ** ** ** ** **|........********|
//      =============================================================================
//
//      ===========================================================
//      >> ptr[000]=0x00562a0e3fd59d; str={".symtab"};
//      >> ptr[001]=0x00562a0e3fd5a5; str={".strtab"};
//      >> ptr[002]=0x00562a0e3fd5ad; str={".shstrtab"};
//      >> ptr[003]=0x00562a0e3fd5b7; str={".interp"};
//      >> ptr[004]=0x00562a0e3fd5bf; str={".note.gnu.property"};
//      >> ptr[005]=0x00562a0e3fd5d2; str={".note.gnu.build-id"};
//      >> ptr[006]=0x00562a0e3fd5e5; str={".note.ABI-tag"};
//      >> ptr[007]=0x00562a0e3fd5f3; str={".gnu.hash"};
//      >> ptr[008]=0x00562a0e3fd5fd; str={".dynsym"};
//      >> ptr[009]=0x00562a0e3fd605; str={".dynstr"};
//      >> ptr[010]=0x00562a0e3fd60d; str={".gnu.version"};
//      >> ptr[011]=0x00562a0e3fd61a; str={".gnu.version_r"};
//      >> ptr[012]=0x00562a0e3fd629; str={".rela.dyn"};
//      >> ptr[013]=0x00562a0e3fd633; str={".rela.plt"};
//      >> ptr[014]=0x00562a0e3fd63d; str={".init"};
//      >> ptr[015]=0x00562a0e3fd643; str={".plt.got"};
//      >> ptr[016]=0x00562a0e3fd64c; str={".plt.sec"};
//      >> ptr[017]=0x00562a0e3fd655; str={".text"};
//      >> ptr[018]=0x00562a0e3fd65b; str={".fini"};
//      >> ptr[019]=0x00562a0e3fd661; str={".rodata"};
//      >> ptr[020]=0x00562a0e3fd669; str={".eh_frame_hdr"};
//      >> ptr[021]=0x00562a0e3fd677; str={".eh_frame"};
//      >> ptr[022]=0x00562a0e3fd681; str={".init_array"};
//      >> ptr[023]=0x00562a0e3fd68d; str={".fini_array"};
//      >> ptr[024]=0x00562a0e3fd699; str={".dynamic"};
//      >> ptr[025]=0x00562a0e3fd6a2; str={".data"};
//      >> ptr[026]=0x00562a0e3fd6a8; str={".bss"};
//      >> ptr[027]=0x00562a0e3fd6ad; str={".comment"};
//      >> ptr[028]=0x00562a0e3fd6b6; str={".debug_aranges"};
//      >> ptr[029]=0x00562a0e3fd6c5; str={".debug_info"};
//      >> ptr[030]=0x00562a0e3fd6d1; str={".debug_abbrev"};
//      >> ptr[031]=0x00562a0e3fd6df; str={".debug_line"};
//      >> ptr[032]=0x00562a0e3fd6eb; str={".debug_str"};
//      >> ptr[033]=0x00562a0e3fd6f6; str={".debug_ranges"};
//      ===========================================================

#endif

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
xadmin@hw:~/xwks.git.1/myreadelf-c11$ gcc -std=c11 -g -Wall -O0  myreadelf-0.1.08.c -o myapp
xadmin@hw:~/xwks.git.1/myreadelf-c11$ ./myapp
################################################{}##################################################
  #====>>>>
  >> func{before_main_func:(02498)@(myreadelf-0.1.08.c)} is call .
  #====>>>>
  >> func{my_init01:(02519)@(myreadelf-0.1.08.c)} is call .
  #====>>>>
  >> func{my_init02:(02531)@(myreadelf-0.1.08.c)} is call .
  #====>>>>
  >> func{my_init03:(02543)@(myreadelf-0.1.08.c)} is call .
  >> the app starting ... ...

0x007ffc5db3a998|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|60 c6 b3 5d fc 7f 00 00  00 00 00 00 00 00 00 00|`..]............|
      0x00000010|68 c6 b3 5d fc 7f 00 00  78 c6 b3 5d fc 7f 00 00|h..]....x..]....|
      0x00000020|90 c6 b3 5d fc 7f 00 00  a7 c6 b3 5d fc 7f 00 00|...].......]....|
      0x00000030|bb c6 b3 5d fc 7f 00 00  d3 c6 b3 5d fc 7f 00 00|...].......]....|
      0x00000040|fd c6 b3 5d fc 7f 00 00  0c c7 b3 5d fc 7f 00 00|...].......]....|
      0x00000050|21 c7 b3 5d fc 7f 00 00  30 c7 b3 ** ** ** ** **|!..]....0..*****|
      =============================================================================


0x007ffc5db3c660|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2e 2f 6d 79 61 70 70 00  53 48 45 4c 4c 3d 2f 62|./myapp.SHELL=/b|
      0x00000010|69 6e 2f 62 61 73 68 00  4c 41 4e 47 55 41 47 45|in/bash.LANGUAGE|
      0x00000020|3d 7a 68 5f 43 4e 3a 65  6e 5f 55 53 3a 65 6e 00|=zh_CN:en_US:en.|
      0x00000030|4c 43 5f 41 44 44 52 45  53 53 3d 7a 68 5f 43 4e|LC_ADDRESS=zh_CN|
      0x00000040|2e 55 54 46 2d 38 00 4c  43 5f 4e 41 4d 45 3d 7a|.UTF-8.LC_NAME=z|
      0x00000050|68 5f 43 4e 2e 55 54 46  2d 38 00 ** ** ** ** **|h_CN.UTF-8.*****|
      =============================================================================

  >> func:parse_args(1, 0x7ffc5db3a998) is called. (@file:myreadelf-0.1.08.c,line:2557).

    >>> argv[00](addr=0x7ffc5db3c660) = {"./myapp"}.

  >> func:parse_args() is called. @line:(2564).
  >> get_elf64_data("./myapp", len) entry;

0x00559e89504890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  40 22 00 00 00 00 00 00|..>.....@"......|
      0x00000020|40 00 00 00 00 00 00 00  e0 00 01 00 00 00 00 00|@...............|
      0x00000030|00 00 00 00 40 00 38 00  0d 00 40 00 25 00 24 00|....@.8...@.%.$.|
      0x00000040|06 00 00 00 04 00 00 00  40 00 00 00 00 00 00 00|........@.......|
      0x00000050|40 00 00 00 00 ** ** **  ** ** ** ** ** ** ** **|@....***********|
      =============================================================================

  >> build_elf64_obj(0x559e89504890, 68128) entry;
  >> func{parse_elf64_elf_header:(00401)} is call.{pElfData=0x559e89504890}.
        struct S_ELF64_ELFHeader_t pElfHeader = {0x559e89504890} 
        {
                 unsigned char e_ident[16] = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00};
                 Elf64_Half    e_type      = 0x0003;
                 Elf64_Half    e_machine   = 0x003e;
                 Elf64_Word    e_version   = 0x1  ;
                 Elf64_Addr    e_entry     = 0x2240;
                 Elf64_Off     e_phoff     = 0x40;
                 Elf64_Off     e_shoff     = 0x100e0;
                 Elf64_Word    e_flags     = 0x0  ;
                 Elf64_Half    e_ehsize    = 0x0040;
                 Elf64_Half    e_phentsize = 0x0038;
                 Elf64_Half    e_phnum     = 0x000d;
                 Elf64_Half    e_shentsize = 0x0040;
                 Elf64_Half    e_shnum     = 0x0025;
                 Elf64_Half    e_shstrndx  = 0x0024;
        };
        No.[36]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89515270
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xff73;
             Elf64_Xword   sh_size      = 0x168;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e89514803|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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
      0x00000150|64 65 62 75 67 5f 73 74  72 00 2e 64 65 62 75 67|debug_str..debug|
      0x00000160|5f 72 61 6e 67 65 73 00  ** ** ** ** ** ** ** **|_ranges.********|
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
  [06] .dynsym         0000000b  00000003c8  000968  000552  000024  0x0002 0x0007 0x0001 0x0008
  [07] .dynstr         00000003  00000005f0  001520  000278  000000  0x0002 0x0000 0x0000 0x0001
  [08] .gnu.version    6fffffff  0000000706  001798  000046  000002  0x0002 0x0006 0x0000 0x0002
  [09] .gnu.version_r  6ffffffe  0000000738  001848  000064  000000  0x0002 0x0007 0x0001 0x0008
  [10] .rela.dyn       00000004  0000000778  001912  002136  000024  0x0002 0x0006 0x0000 0x0008
  [11] .rela.plt       00000004  0000000fd0  004048  000384  000024  0x0042 0x0006 0x0018 0x0008
  [12] .init           00000001  0000002000  008192  000027  000000  0x0006 0x0000 0x0000 0x0004
  [13] .plt            00000001  0000002020  008224  000272  000016  0x0006 0x0000 0x0000 0x0010
  [14] .plt.got        00000001  0000002130  008496  000016  000016  0x0006 0x0000 0x0000 0x0010
  [15] .plt.sec        00000001  0000002140  008512  000256  000016  0x0006 0x0000 0x0000 0x0010
  [16] .text           00000001  0000002240  008768  013092  000000  0x0006 0x0000 0x0000 0x0010
  [17] .fini           00000001  0000005564  021860  000013  000000  0x0006 0x0000 0x0000 0x0004
  [18] .rodata         00000001  0000006000  024576  006843  000000  0x0002 0x0000 0x0000 0x0010
  [19] .eh_frame_hdr   00000001  0000007abc  031420  000620  000000  0x0002 0x0000 0x0000 0x0004
  [20] .eh_frame       00000001  0000007d28  032040  002472  000000  0x0002 0x0000 0x0000 0x0008
  [21] .init_array     0000000e  0000009d00  036096  000040  000008  0x0003 0x0000 0x0000 0x0008
  [22] .fini_array     0000000f  0000009d28  036136  000040  000008  0x0003 0x0000 0x0000 0x0008
  [23] .dynamic        00000006  0000009d50  036176  000496  000016  0x0003 0x0007 0x0000 0x0008
  [24] .got            00000001  0000009f40  036672  000192  000008  0x0003 0x0000 0x0000 0x0008
  [25] .data           00000001  000000a000  036864  000640  000000  0x0003 0x0000 0x0000 0x0020
  [26] .bss            00000008  000000a280  037504  000016  000000  0x0003 0x0000 0x0000 0x0008
  [27] .comment        00000001  0000000000  037504  000043  000001  0x0030 0x0000 0x0000 0x0001
  [28] .debug_aranges  00000001  0000000000  037547  000048  000000  0x0000 0x0000 0x0000 0x0001
  [29] .debug_info     00000001  0000000000  037595  011741  000000  0x0000 0x0000 0x0000 0x0001
  [30] .debug_abbrev   00000001  0000000000  049336  000692  000000  0x0000 0x0000 0x0000 0x0001
  [31] .debug_line     00000001  0000000000  050028  003912  000000  0x0000 0x0000 0x0000 0x0001
  [32] .debug_str      00000001  0000000000  053940  003500  000001  0x0030 0x0000 0x0000 0x0001
  [33] .debug_ranges   00000001  0000000000  057440  000048  000000  0x0000 0x0000 0x0000 0x0001
  [34] .symtab         00000002  0000000000  057488  005088  000024  0x0000 0x0023 0x006b 0x0008
  [35] .strtab         00000003  0000000000  062576  002819  000000  0x0000 0x0000 0x0000 0x0001
  [36] .shstrtab       00000003  0000000000  065395  000360  000000  0x0000 0x0000 0x0000 0x0001
----------------------------------------------------------------
  >> func{parse_elf64_sect_headers:(00522)} is call .
  >> func{parse_elf64_prog_headers:(00557)} is call .

    ----------------------------------------------------------------
    Program Headers:
    [No] Type     Offset   VirtAddr   PhysAddr   FileSiz  MemSiz   Flags    Align
    [00] 00000006 00000040 0000000040 0000000040 0x0002d8 0x0002d8 0x000004 0x000008
    [01] 00000003 00000318 0000000318 0000000318 0x00001c 0x00001c 0x000004 0x000001
    [02] 00000001 00000000 0000000000 0000000000 0x001150 0x001150 0x000004 0x001000
    [03] 00000001 00002000 0000002000 0000002000 0x003571 0x003571 0x000005 0x001000
    [04] 00000001 00006000 0000006000 0000006000 0x0026d0 0x0026d0 0x000004 0x001000
    [05] 00000001 00008d00 0000009d00 0000009d00 0x000580 0x000590 0x000006 0x001000
    [06] 00000002 00008d50 0000009d50 0000009d50 0x0001f0 0x0001f0 0x000006 0x000008
    [07] 00000004 00000338 0000000338 0000000338 0x000020 0x000020 0x000004 0x000008
    [08] 00000004 00000358 0000000358 0000000358 0x000044 0x000044 0x000004 0x000004
    [09] 6474e553 00000338 0000000338 0000000338 0x000020 0x000020 0x000004 0x000008
    [10] 6474e550 00007abc 0000007abc 0000007abc 0x00026c 0x00026c 0x000004 0x000004
    [11] 6474e551 00000000 0000000000 0000000000 0x000000 0x000000 0x000006 0x000010
    [12] 6474e552 00008d00 0000009d00 0000009d00 0x000300 0x000300 0x000004 0x000001
    ----------------------------------------------------------------
  >> func{parse_elf64_sect_bodys:(02423)} is call .
  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=00,sect_name="",pSectData=0x559e89504890,iLen=0x0}
    >> func{func_process:(02380)} is call .
      >>> {idx=0, name="", pData=0x559e89504890, iLen=0, pSectHeader=0x559e89514970}.

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=01,sect_name=".interp",pSectData=0x559e89504ba8,iLen=0x1c}
    >> func{func_sect_interp:(00735)} is call .
        No.[01]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e895149b0
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

0x00559e89504ba8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2f 6c 69 62 36 34 2f 6c  64 2d 6c 69 6e 75 78 2d|/lib64/ld-linux-|
      0x00000010|78 38 36 2d 36 34 2e 73  6f 2e 32 00 ** ** ** **|x86-64.so.2.****|
      =============================================================================

      ------------------------------------------------------------
      /lib64/ld-linux-x86-64.so.2
      ------------------------------------------------------------

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=02,sect_name=".note.gnu.property",pSectData=0x559e89504bc8,iLen=0x20}
    >> func{func_process:(02380)} is call .
      >>> {idx=2, name=".note.gnu.property", pData=0x559e89504bc8, iLen=32, pSectHeader=0x559e895149f0}.

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=03,sect_name=".note.gnu.build-id",pSectData=0x559e89504be8,iLen=0x24}
    >> func{func_sect_note_gnu_build_id:(00696)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=04,sect_name=".note.ABI-tag",pSectData=0x559e89504c0c,iLen=0x20}
    >> func{func_sect_note_ABI_tag:(00695)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=05,sect_name=".gnu.hash",pSectData=0x559e89504c30,iLen=0x28}
    >> func{func_sect_gnu_hash:(00697)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=06,sect_name=".dynsym",pSectData=0x559e89504c58,iLen=0x228}
    >> func{func_sect_dynsym:(00766)} is call .
        No.[06]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514af0
        {
             Elf64_Word    sh_name      = 0x61;
             Elf64_Word    sh_type      = 0xb;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x3c8;
             Elf64_Off     sh_offset    = 0x3c8;
             Elf64_Xword   sh_size      = 0x228;
             Elf64_Word    sh_link      = 0x7;
             Elf64_Word    sh_info      = 0x1;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x18;
        }

0x00559e89504c58|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000010|00 00 00 00 00 00 00 00  a4 00 00 00 12 00 00 00|................|
      0x00000020|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000030|2e 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000040|00 00 00 00 00 00 00 00  d1 00 00 00 20 00 00 00|............ ...|
      0x00000050|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000060|18 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000070|00 00 00 00 00 00 00 00  76 00 00 00 12 00 00 00|........v.......|
      0x00000080|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000090|52 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|R...............|
      0x000000a0|00 00 00 00 00 00 00 00  1d 00 00 00 12 00 00 00|................|
      0x000000b0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000c0|5a 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|Z...............|
      0x000000d0|00 00 00 00 00 00 00 00  36 00 00 00 12 00 00 00|........6.......|
      0x000000e0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000f0|92 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000100|00 00 00 00 00 00 00 00  44 00 00 00 12 00 00 00|........D.......|
      0x00000110|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000120|8b 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000130|00 00 00 00 00 00 00 00  ed 00 00 00 20 00 00 00|............ ...|
      0x00000140|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000150|a9 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000160|00 00 00 00 00 00 00 00  61 00 00 00 12 00 00 00|........a.......|
      0x00000170|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000180|0b 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000190|00 00 00 00 00 00 00 00  59 00 00 00 12 00 00 00|........Y.......|
      0x000001a0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000001b0|12 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000001c0|00 00 00 00 00 00 00 00  fc 00 00 00 20 00 00 00|............ ...|
      0x000001d0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000001e0|68 00 00 00 12 00 00 00  00 00 00 00 00 00 00 00|h...............|
      0x000001f0|00 00 00 00 00 00 00 00  4b 00 00 00 11 00 1a 00|........K.......|
      0x00000200|80 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000210|7c 00 00 00 22 00 00 00  00 00 00 00 00 00 00 00||..."...........|
      0x00000220|00 00 00 00 00 00 00 00  ** ** ** ** ** ** ** **|........********|
      =============================================================================

      Symbol table '.dynsym' contains 23 entries:
         Num:    Value          Size Type    Bind   Vis      Ndx  Name  NameStr
         000:                0     0  00      00    00       0000 0000 
         001:                0     0  02      01    00       0000 00a4 
         002:                0     0  02      01    00       0000 002e 
         003:                0     0  00      02    00       0000 00d1 
         004:                0     0  02      01    00       0000 0018 
         005:                0     0  02      01    00       0000 0076 
         006:                0     0  02      01    00       0000 0052 
         007:                0     0  02      01    00       0000 001d 
         008:                0     0  02      01    00       0000 005a 
         009:                0     0  02      01    00       0000 0036 
         010:                0     0  02      01    00       0000 0092 
         011:                0     0  02      01    00       0000 0044 
         012:                0     0  02      01    00       0000 008b 
         013:                0     0  00      02    00       0000 00ed 
         014:                0     0  02      01    00       0000 00a9 
         015:                0     0  02      01    00       0000 0061 
         016:                0     0  02      01    00       0000 000b 
         017:                0     0  02      01    00       0000 0059 
         018:                0     0  02      01    00       0000 0012 
         019:                0     0  00      02    00       0000 00fc 
         020:                0     0  02      01    00       0000 0068 
         021:             a280     8  01      01    00       001a 004b 
         022:                0     0  02      02    00       0000 007c 

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=07,sect_name=".dynstr",pSectData=0x559e89504e80,iLen=0x116}
    >> func{func_sect_dynstr:(00837)} is call .
        No.[07]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514b30
        {
             Elf64_Word    sh_name      = 0x69;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x5f0;
             Elf64_Off     sh_offset    = 0x5f0;
             Elf64_Xword   sh_size      = 0x116;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e89504e80|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 6c 69 62 63 2e 73 6f  2e 36 00 66 66 6c 75 73|.libc.so.6.fflus|
      0x00000010|68 00 66 6f 70 65 6e 00  70 75 74 73 00 5f 5f 73|h.fopen.puts.__s|
      0x00000020|74 61 63 6b 5f 63 68 6b  5f 66 61 69 6c 00 70 75|tack_chk_fail.pu|
      0x00000030|74 63 68 61 72 00 5f 5f  61 73 73 65 72 74 5f 66|tchar.__assert_f|
      0x00000040|61 69 6c 00 63 61 6c 6c  6f 63 00 73 74 64 6f 75|ail.calloc.stdou|
      0x00000050|74 00 66 63 6c 6f 73 65  00 76 70 72 69 6e 74 66|t.fclose.vprintf|
      0x00000060|00 6d 61 6c 6c 6f 63 00  5f 5f 63 74 79 70 65 5f|.malloc.__ctype_|
      0x00000070|62 5f 6c 6f 63 00 66 72  65 61 64 00 5f 5f 63 78|b_loc.fread.__cx|
      0x00000080|61 5f 66 69 6e 61 6c 69  7a 65 00 73 74 72 63 6d|a_finalize.strcm|
      0x00000090|70 00 5f 5f 6c 69 62 63  5f 73 74 61 72 74 5f 6d|p.__libc_start_m|
      0x000000a0|61 69 6e 00 66 72 65 65  00 5f 5f 78 73 74 61 74|ain.free.__xstat|
      0x000000b0|00 47 4c 49 42 43 5f 32  2e 33 00 47 4c 49 42 43|.GLIBC_2.3.GLIBC|
      0x000000c0|5f 32 2e 34 00 47 4c 49  42 43 5f 32 2e 32 2e 35|_2.4.GLIBC_2.2.5|
      0x000000d0|00 5f 49 54 4d 5f 64 65  72 65 67 69 73 74 65 72|._ITM_deregister|
      0x000000e0|54 4d 43 6c 6f 6e 65 54  61 62 6c 65 00 5f 5f 67|TMCloneTable.__g|
      0x000000f0|6d 6f 6e 5f 73 74 61 72  74 5f 5f 00 5f 49 54 4d|mon_start__._ITM|
      0x00000100|5f 72 65 67 69 73 74 65  72 54 4d 43 6c 6f 6e 65|_registerTMClone|
      0x00000110|54 61 62 6c 65 00 ** **  ** ** ** ** ** ** ** **|Table.**********|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x00559e89504e81; str={"libc.so.6"};
      >> ptr[001]=0x00559e89504e8b; str={"fflush"};
      >> ptr[002]=0x00559e89504e92; str={"fopen"};
      >> ptr[003]=0x00559e89504e98; str={"puts"};
      >> ptr[004]=0x00559e89504e9d; str={"__stack_chk_fail"};
      >> ptr[005]=0x00559e89504eae; str={"putchar"};
      >> ptr[006]=0x00559e89504eb6; str={"__assert_fail"};
      >> ptr[007]=0x00559e89504ec4; str={"calloc"};
      >> ptr[008]=0x00559e89504ecb; str={"stdout"};
      >> ptr[009]=0x00559e89504ed2; str={"fclose"};
      >> ptr[010]=0x00559e89504ed9; str={"vprintf"};
      >> ptr[011]=0x00559e89504ee1; str={"malloc"};
      >> ptr[012]=0x00559e89504ee8; str={"__ctype_b_loc"};
      >> ptr[013]=0x00559e89504ef6; str={"fread"};
      >> ptr[014]=0x00559e89504efc; str={"__cxa_finalize"};
      >> ptr[015]=0x00559e89504f0b; str={"strcmp"};
      >> ptr[016]=0x00559e89504f12; str={"__libc_start_main"};
      >> ptr[017]=0x00559e89504f24; str={"free"};
      >> ptr[018]=0x00559e89504f29; str={"__xstat"};
      >> ptr[019]=0x00559e89504f31; str={"GLIBC_2.3"};
      >> ptr[020]=0x00559e89504f3b; str={"GLIBC_2.4"};
      >> ptr[021]=0x00559e89504f45; str={"GLIBC_2.2.5"};
      >> ptr[022]=0x00559e89504f51; str={"_ITM_deregisterTMCloneTable"};
      >> ptr[023]=0x00559e89504f6d; str={"__gmon_start__"};
      >> ptr[024]=0x00559e89504f7c; str={"_ITM_registerTMCloneTable"};
      ===========================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=08,sect_name=".gnu.version",pSectData=0x559e89504f96,iLen=0x2e}
    >> func{func_sect_gnu_version:(00700)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=09,sect_name=".gnu.version_r",pSectData=0x559e89504fc8,iLen=0x40}
    >> func{func_sect_gnu_version_r:(00701)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=10,sect_name=".rela.dyn",pSectData=0x559e89505008,iLen=0x858}
    >> func{func_sect_rela_dyn:(00853)} is call .
        No.[10]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514bf0
        {
             Elf64_Word    sh_name      = 0x8d;
             Elf64_Word    sh_type      = 0x4;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x778;
             Elf64_Off     sh_offset    = 0x778;
             Elf64_Xword   sh_size      = 0x858;
             Elf64_Word    sh_link      = 0x6;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x18;
        }

0x00559e89505008|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 9d 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000010|20 23 00 00 00 00 00 00  08 9d 00 00 00 00 00 00| #..............|
      0x00000020|08 00 00 00 00 00 00 00  73 50 00 00 00 00 00 00|........sP......|
      0x00000030|10 9d 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000040|04 51 00 00 00 00 00 00  18 9d 00 00 00 00 00 00|.Q..............|
      0x00000050|08 00 00 00 00 00 00 00  84 51 00 00 00 00 00 00|.........Q......|
      0x00000060|20 9d 00 00 00 00 00 00  08 00 00 00 00 00 00 00| ...............|
      0x00000070|04 52 00 00 00 00 00 00  28 9d 00 00 00 00 00 00|.R......(.......|
      0x00000080|08 00 00 00 00 00 00 00  e0 22 00 00 00 00 00 00|........."......|
      0x00000090|30 9d 00 00 00 00 00 00  08 00 00 00 00 00 00 00|0...............|
      0x000000a0|c4 50 00 00 00 00 00 00  38 9d 00 00 00 00 00 00|.P......8.......|
      0x000000b0|08 00 00 00 00 00 00 00  44 51 00 00 00 00 00 00|........DQ......|
      0x000000c0|40 9d 00 00 00 00 00 00  08 00 00 00 00 00 00 00|@...............|
      0x000000d0|c4 51 00 00 00 00 00 00  48 9d 00 00 00 00 00 00|.Q......H.......|
      0x000000e0|08 00 00 00 00 00 00 00  44 52 00 00 00 00 00 00|........DR......|
      0x000000f0|08 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000100|08 a0 00 00 00 00 00 00  30 a0 00 00 00 00 00 00|........0.......|
      0x00000110|08 00 00 00 00 00 00 00  ca 6b 00 00 00 00 00 00|.........k......|
      0x00000120|38 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|8...............|
      0x00000130|76 39 00 00 00 00 00 00  40 a0 00 00 00 00 00 00|v9......@.......|
      0x00000140|08 00 00 00 00 00 00 00  d2 6b 00 00 00 00 00 00|.........k......|
      0x00000150|48 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|H...............|
      0x00000160|1c 36 00 00 00 00 00 00  50 a0 00 00 00 00 00 00|.6......P.......|
      0x00000170|08 00 00 00 00 00 00 00  e2 6b 00 00 00 00 00 00|.........k......|
      0x00000180|58 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|X...............|
      0x00000190|a0 36 00 00 00 00 00 00  60 a0 00 00 00 00 00 00|.6......`.......|
      0x000001a0|08 00 00 00 00 00 00 00  f0 6b 00 00 00 00 00 00|.........k......|
      0x000001b0|68 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|h...............|
      0x000001c0|e2 36 00 00 00 00 00 00  70 a0 00 00 00 00 00 00|.6......p.......|
      0x000001d0|08 00 00 00 00 00 00 00  03 6c 00 00 00 00 00 00|.........l......|
      0x000001e0|78 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|x...............|
      0x000001f0|24 37 00 00 00 00 00 00  80 a0 00 00 00 00 00 00|$7..............|
      0x00000200|08 00 00 00 00 00 00 00  0d 6c 00 00 00 00 00 00|.........l......|
      0x00000210|88 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000220|78 3a 00 00 00 00 00 00  90 a0 00 00 00 00 00 00|x:..............|
      0x00000230|08 00 00 00 00 00 00 00  15 6c 00 00 00 00 00 00|.........l......|
      0x00000240|98 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000250|34 3d 00 00 00 00 00 00  a0 a0 00 00 00 00 00 00|4=..............|
      0x00000260|08 00 00 00 00 00 00 00  1d 6c 00 00 00 00 00 00|.........l......|
      0x00000270|a8 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000280|66 37 00 00 00 00 00 00  b0 a0 00 00 00 00 00 00|f7..............|
      0x00000290|08 00 00 00 00 00 00 00  2a 6c 00 00 00 00 00 00|........*l......|
      0x000002a0|b8 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000002b0|a8 37 00 00 00 00 00 00  c0 a0 00 00 00 00 00 00|.7..............|
      0x000002c0|08 00 00 00 00 00 00 00  39 6c 00 00 00 00 00 00|........9l......|
      0x000002d0|c8 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000002e0|b2 3d 00 00 00 00 00 00  d0 a0 00 00 00 00 00 00|.=..............|
      0x000002f0|08 00 00 00 00 00 00 00  43 6c 00 00 00 00 00 00|........Cl......|
      0x00000300|d8 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000310|33 3f 00 00 00 00 00 00  e0 a0 00 00 00 00 00 00|3?..............|
      0x00000320|08 00 00 00 00 00 00 00  4d 6c 00 00 00 00 00 00|........Ml......|
      0x00000330|e8 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000340|c5 40 00 00 00 00 00 00  f0 a0 00 00 00 00 00 00|.@..............|
      0x00000350|08 00 00 00 00 00 00 00  53 6c 00 00 00 00 00 00|........Sl......|
      0x00000360|f8 a0 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000370|2d 41 00 00 00 00 00 00  00 a1 00 00 00 00 00 00|-A..............|
      0x00000380|08 00 00 00 00 00 00 00  58 6c 00 00 00 00 00 00|........Xl......|
      0x00000390|08 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000003a0|95 41 00 00 00 00 00 00  10 a1 00 00 00 00 00 00|.A..............|
      0x000003b0|08 00 00 00 00 00 00 00  61 6c 00 00 00 00 00 00|........al......|
      0x000003c0|18 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000003d0|fd 41 00 00 00 00 00 00  20 a1 00 00 00 00 00 00|.A...... .......|
      0x000003e0|08 00 00 00 00 00 00 00  6a 6c 00 00 00 00 00 00|........jl......|
      0x000003f0|28 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|(...............|
      0x00000400|65 42 00 00 00 00 00 00  30 a1 00 00 00 00 00 00|eB......0.......|
      0x00000410|08 00 00 00 00 00 00 00  70 6c 00 00 00 00 00 00|........pl......|
      0x00000420|38 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|8...............|
      0x00000430|c9 42 00 00 00 00 00 00  40 a1 00 00 00 00 00 00|.B......@.......|
      0x00000440|08 00 00 00 00 00 00 00  76 6c 00 00 00 00 00 00|........vl......|
      0x00000450|48 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|H...............|
      0x00000460|31 43 00 00 00 00 00 00  50 a1 00 00 00 00 00 00|1C......P.......|
      0x00000470|08 00 00 00 00 00 00 00  7e 6c 00 00 00 00 00 00|........~l......|
      0x00000480|58 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|X...............|
      0x00000490|ea 37 00 00 00 00 00 00  60 a1 00 00 00 00 00 00|.7......`.......|
      0x000004a0|08 00 00 00 00 00 00 00  8c 6c 00 00 00 00 00 00|.........l......|
      0x000004b0|68 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|h...............|
      0x000004c0|2c 38 00 00 00 00 00 00  70 a1 00 00 00 00 00 00|,8......p.......|
      0x000004d0|08 00 00 00 00 00 00 00  96 6c 00 00 00 00 00 00|.........l......|
      0x000004e0|78 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|x...............|
      0x000004f0|2a 44 00 00 00 00 00 00  80 a1 00 00 00 00 00 00|*D..............|
      0x00000500|08 00 00 00 00 00 00 00  a2 6c 00 00 00 00 00 00|.........l......|
      0x00000510|88 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000520|b7 44 00 00 00 00 00 00  90 a1 00 00 00 00 00 00|.D..............|
      0x00000530|08 00 00 00 00 00 00 00  ae 6c 00 00 00 00 00 00|.........l......|
      0x00000540|98 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000550|44 45 00 00 00 00 00 00  a0 a1 00 00 00 00 00 00|DE..............|
      0x00000560|08 00 00 00 00 00 00 00  b7 6c 00 00 00 00 00 00|.........l......|
      0x00000570|a8 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000580|ac 45 00 00 00 00 00 00  b0 a1 00 00 00 00 00 00|.E..............|
      0x00000590|08 00 00 00 00 00 00 00  bc 6c 00 00 00 00 00 00|.........l......|
      0x000005a0|b8 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000005b0|14 46 00 00 00 00 00 00  c0 a1 00 00 00 00 00 00|.F..............|
      0x000005c0|08 00 00 00 00 00 00 00  c5 6c 00 00 00 00 00 00|.........l......|
      0x000005d0|c8 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000005e0|7c 46 00 00 00 00 00 00  d0 a1 00 00 00 00 00 00||F..............|
      0x000005f0|08 00 00 00 00 00 00 00  cb 6c 00 00 00 00 00 00|.........l......|
      0x00000600|d8 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000610|e4 46 00 00 00 00 00 00  e0 a1 00 00 00 00 00 00|.F..............|
      0x00000620|08 00 00 00 00 00 00 00  d0 6c 00 00 00 00 00 00|.........l......|
      0x00000630|e8 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000640|4c 47 00 00 00 00 00 00  f0 a1 00 00 00 00 00 00|LG..............|
      0x00000650|08 00 00 00 00 00 00 00  d9 6c 00 00 00 00 00 00|.........l......|
      0x00000660|f8 a1 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000670|6e 38 00 00 00 00 00 00  00 a2 00 00 00 00 00 00|n8..............|
      0x00000680|08 00 00 00 00 00 00 00  e8 6c 00 00 00 00 00 00|.........l......|
      0x00000690|08 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000006a0|b0 38 00 00 00 00 00 00  10 a2 00 00 00 00 00 00|.8..............|
      0x000006b0|08 00 00 00 00 00 00 00  f4 6c 00 00 00 00 00 00|.........l......|
      0x000006c0|18 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000006d0|f2 38 00 00 00 00 00 00  20 a2 00 00 00 00 00 00|.8...... .......|
      0x000006e0|08 00 00 00 00 00 00 00  02 6d 00 00 00 00 00 00|.........m......|
      0x000006f0|28 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|(...............|
      0x00000700|34 39 00 00 00 00 00 00  30 a2 00 00 00 00 00 00|49......0.......|
      0x00000710|08 00 00 00 00 00 00 00  0e 6d 00 00 00 00 00 00|.........m......|
      0x00000720|38 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|8...............|
      0x00000730|b4 47 00 00 00 00 00 00  40 a2 00 00 00 00 00 00|.G......@.......|
      0x00000740|08 00 00 00 00 00 00 00  19 6d 00 00 00 00 00 00|.........m......|
      0x00000750|48 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|H...............|
      0x00000760|32 48 00 00 00 00 00 00  50 a2 00 00 00 00 00 00|2H......P.......|
      0x00000770|08 00 00 00 00 00 00 00  21 6d 00 00 00 00 00 00|........!m......|
      0x00000780|58 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|X...............|
      0x00000790|f1 49 00 00 00 00 00 00  60 a2 00 00 00 00 00 00|.I......`.......|
      0x000007a0|08 00 00 00 00 00 00 00  29 6d 00 00 00 00 00 00|........)m......|
      0x000007b0|68 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|h...............|
      0x000007c0|6f 4a 00 00 00 00 00 00  d8 9f 00 00 00 00 00 00|oJ..............|
      0x000007d0|06 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000007e0|e0 9f 00 00 00 00 00 00  06 00 00 00 0a 00 00 00|................|
      0x000007f0|00 00 00 00 00 00 00 00  e8 9f 00 00 00 00 00 00|................|
      0x00000800|06 00 00 00 0d 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000810|f0 9f 00 00 00 00 00 00  06 00 00 00 13 00 00 00|................|
      0x00000820|00 00 00 00 00 00 00 00  f8 9f 00 00 00 00 00 00|................|
      0x00000830|06 00 00 00 16 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000840|80 a2 00 00 00 00 00 00  05 00 00 00 15 00 00 00|................|
      0x00000850|00 00 00 00 00 00 00 00  ** ** ** ** ** ** ** **|........********|
      =============================================================================

    Relocation section '.rela.dyn' at offset ?? contains 89 entries:
      Idx  Offset          Info         Type      Sym. Value Sym. Name + Addend
      [00] 000000009d00 000000000008 0x00000008      test    sym.name  + 8992
      [01] 000000009d08 000000000008 0x00000008      test    sym.name  + 20595
      [02] 000000009d10 000000000008 0x00000008      test    sym.name  + 20740
      [03] 000000009d18 000000000008 0x00000008      test    sym.name  + 20868
      [04] 000000009d20 000000000008 0x00000008      test    sym.name  + 20996
      [05] 000000009d28 000000000008 0x00000008      test    sym.name  + 8928
      [06] 000000009d30 000000000008 0x00000008      test    sym.name  + 20676
      [07] 000000009d38 000000000008 0x00000008      test    sym.name  + 20804
      [08] 000000009d40 000000000008 0x00000008      test    sym.name  + 20932
      [09] 000000009d48 000000000008 0x00000008      test    sym.name  + 21060
      [10] 00000000a008 000000000008 0x00000008      test    sym.name  + 40968
      [11] 00000000a030 000000000008 0x00000008      test    sym.name  + 27594
      [12] 00000000a038 000000000008 0x00000008      test    sym.name  + 14710
      [13] 00000000a040 000000000008 0x00000008      test    sym.name  + 27602
      [14] 00000000a048 000000000008 0x00000008      test    sym.name  + 13852
      [15] 00000000a050 000000000008 0x00000008      test    sym.name  + 27618
      [16] 00000000a058 000000000008 0x00000008      test    sym.name  + 13984
      [17] 00000000a060 000000000008 0x00000008      test    sym.name  + 27632
      [18] 00000000a068 000000000008 0x00000008      test    sym.name  + 14050
      [19] 00000000a070 000000000008 0x00000008      test    sym.name  + 27651
      [20] 00000000a078 000000000008 0x00000008      test    sym.name  + 14116
      [21] 00000000a080 000000000008 0x00000008      test    sym.name  + 27661
      [22] 00000000a088 000000000008 0x00000008      test    sym.name  + 14968
      [23] 00000000a090 000000000008 0x00000008      test    sym.name  + 27669
      [24] 00000000a098 000000000008 0x00000008      test    sym.name  + 15668
      [25] 00000000a0a0 000000000008 0x00000008      test    sym.name  + 27677
      [26] 00000000a0a8 000000000008 0x00000008      test    sym.name  + 14182
      [27] 00000000a0b0 000000000008 0x00000008      test    sym.name  + 27690
      [28] 00000000a0b8 000000000008 0x00000008      test    sym.name  + 14248
      [29] 00000000a0c0 000000000008 0x00000008      test    sym.name  + 27705
      [30] 00000000a0c8 000000000008 0x00000008      test    sym.name  + 15794
      [31] 00000000a0d0 000000000008 0x00000008      test    sym.name  + 27715
      [32] 00000000a0d8 000000000008 0x00000008      test    sym.name  + 16179
      [33] 00000000a0e0 000000000008 0x00000008      test    sym.name  + 27725
      [34] 00000000a0e8 000000000008 0x00000008      test    sym.name  + 16581
      [35] 00000000a0f0 000000000008 0x00000008      test    sym.name  + 27731
      [36] 00000000a0f8 000000000008 0x00000008      test    sym.name  + 16685
      [37] 00000000a100 000000000008 0x00000008      test    sym.name  + 27736
      [38] 00000000a108 000000000008 0x00000008      test    sym.name  + 16789
      [39] 00000000a110 000000000008 0x00000008      test    sym.name  + 27745
      [40] 00000000a118 000000000008 0x00000008      test    sym.name  + 16893
      [41] 00000000a120 000000000008 0x00000008      test    sym.name  + 27754
      [42] 00000000a128 000000000008 0x00000008      test    sym.name  + 16997
      [43] 00000000a130 000000000008 0x00000008      test    sym.name  + 27760
      [44] 00000000a138 000000000008 0x00000008      test    sym.name  + 17097
      [45] 00000000a140 000000000008 0x00000008      test    sym.name  + 27766
      [46] 00000000a148 000000000008 0x00000008      test    sym.name  + 17201
      [47] 00000000a150 000000000008 0x00000008      test    sym.name  + 27774
      [48] 00000000a158 000000000008 0x00000008      test    sym.name  + 14314
      [49] 00000000a160 000000000008 0x00000008      test    sym.name  + 27788
      [50] 00000000a168 000000000008 0x00000008      test    sym.name  + 14380
      [51] 00000000a170 000000000008 0x00000008      test    sym.name  + 27798
      [52] 00000000a178 000000000008 0x00000008      test    sym.name  + 17450
      [53] 00000000a180 000000000008 0x00000008      test    sym.name  + 27810
      [54] 00000000a188 000000000008 0x00000008      test    sym.name  + 17591
      [55] 00000000a190 000000000008 0x00000008      test    sym.name  + 27822
      [56] 00000000a198 000000000008 0x00000008      test    sym.name  + 17732
      [57] 00000000a1a0 000000000008 0x00000008      test    sym.name  + 27831
      [58] 00000000a1a8 000000000008 0x00000008      test    sym.name  + 17836
      [59] 00000000a1b0 000000000008 0x00000008      test    sym.name  + 27836
      [60] 00000000a1b8 000000000008 0x00000008      test    sym.name  + 17940
      [61] 00000000a1c0 000000000008 0x00000008      test    sym.name  + 27845
      [62] 00000000a1c8 000000000008 0x00000008      test    sym.name  + 18044
      [63] 00000000a1d0 000000000008 0x00000008      test    sym.name  + 27851
      [64] 00000000a1d8 000000000008 0x00000008      test    sym.name  + 18148
      [65] 00000000a1e0 000000000008 0x00000008      test    sym.name  + 27856
      [66] 00000000a1e8 000000000008 0x00000008      test    sym.name  + 18252
      [67] 00000000a1f0 000000000008 0x00000008      test    sym.name  + 27865
      [68] 00000000a1f8 000000000008 0x00000008      test    sym.name  + 14446
      [69] 00000000a200 000000000008 0x00000008      test    sym.name  + 27880
      [70] 00000000a208 000000000008 0x00000008      test    sym.name  + 14512
      [71] 00000000a210 000000000008 0x00000008      test    sym.name  + 27892
      [72] 00000000a218 000000000008 0x00000008      test    sym.name  + 14578
      [73] 00000000a220 000000000008 0x00000008      test    sym.name  + 27906
      [74] 00000000a228 000000000008 0x00000008      test    sym.name  + 14644
      [75] 00000000a230 000000000008 0x00000008      test    sym.name  + 27918
      [76] 00000000a238 000000000008 0x00000008      test    sym.name  + 18356
      [77] 00000000a240 000000000008 0x00000008      test    sym.name  + 27929
      [78] 00000000a248 000000000008 0x00000008      test    sym.name  + 18482
      [79] 00000000a250 000000000008 0x00000008      test    sym.name  + 27937
      [80] 00000000a258 000000000008 0x00000008      test    sym.name  + 18929
      [81] 00000000a260 000000000008 0x00000008      test    sym.name  + 27945
      [82] 00000000a268 000000000008 0x00000008      test    sym.name  + 19055
      [83] 000000009fd8 000300000006 0x00000006      test    sym.name  + 0
      [84] 000000009fe0 000a00000006 0x00000006      test    sym.name  + 0
      [85] 000000009fe8 000d00000006 0x00000006      test    sym.name  + 0
      [86] 000000009ff0 001300000006 0x00000006      test    sym.name  + 0
      [87] 000000009ff8 001600000006 0x00000006      test    sym.name  + 0
      [88] 00000000a280 001500000005 0x00000005      test    sym.name  + 0

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=11,sect_name=".rela.plt",pSectData=0x559e89505860,iLen=0x180}
    >> func{func_sect_rela_plt:(00886)} is call .
        No.[11]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514c30
        {
             Elf64_Word    sh_name      = 0x97;
             Elf64_Word    sh_type      = 0x4;
             Elf64_Xword   sh_flags     = 0x42;
             Elf64_Addr    sh_addr      = 0xfd0;
             Elf64_Off     sh_offset    = 0xfd0;
             Elf64_Xword   sh_size      = 0x180;
             Elf64_Word    sh_link      = 0x6;
             Elf64_Word    sh_info      = 0x18;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x18;
        }

0x00559e89505860|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|58 9f 00 00 00 00 00 00  07 00 00 00 01 00 00 00|X...............|
      0x00000010|00 00 00 00 00 00 00 00  60 9f 00 00 00 00 00 00|........`.......|
      0x00000020|07 00 00 00 02 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000030|68 9f 00 00 00 00 00 00  07 00 00 00 04 00 00 00|h...............|
      0x00000040|00 00 00 00 00 00 00 00  70 9f 00 00 00 00 00 00|........p.......|
      0x00000050|07 00 00 00 05 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000060|78 9f 00 00 00 00 00 00  07 00 00 00 06 00 00 00|x...............|
      0x00000070|00 00 00 00 00 00 00 00  80 9f 00 00 00 00 00 00|................|
      0x00000080|07 00 00 00 07 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000090|88 9f 00 00 00 00 00 00  07 00 00 00 08 00 00 00|................|
      0x000000a0|00 00 00 00 00 00 00 00  90 9f 00 00 00 00 00 00|................|
      0x000000b0|07 00 00 00 09 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000c0|98 9f 00 00 00 00 00 00  07 00 00 00 0b 00 00 00|................|
      0x000000d0|00 00 00 00 00 00 00 00  a0 9f 00 00 00 00 00 00|................|
      0x000000e0|07 00 00 00 0c 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000f0|a8 9f 00 00 00 00 00 00  07 00 00 00 0e 00 00 00|................|
      0x00000100|00 00 00 00 00 00 00 00  b0 9f 00 00 00 00 00 00|................|
      0x00000110|07 00 00 00 0f 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000120|b8 9f 00 00 00 00 00 00  07 00 00 00 10 00 00 00|................|
      0x00000130|00 00 00 00 00 00 00 00  c0 9f 00 00 00 00 00 00|................|
      0x00000140|07 00 00 00 11 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000150|c8 9f 00 00 00 00 00 00  07 00 00 00 12 00 00 00|................|
      0x00000160|00 00 00 00 00 00 00 00  d0 9f 00 00 00 00 00 00|................|
      0x00000170|07 00 00 00 14 00 00 00  00 00 00 00 00 00 00 00|................|
      =============================================================================


Relocation section '.rela.plt' at offset ?? contains 16 entries:
  Idx  Offset          Info         Type      Sym. Value Sym. Name + Addend
  [00] 000000009f58 000100000007 0x00000007      test    sym.name  + 0
  [01] 000000009f60 000200000007 0x00000007      test    sym.name  + 0
  [02] 000000009f68 000400000007 0x00000007      test    sym.name  + 0
  [03] 000000009f70 000500000007 0x00000007      test    sym.name  + 0
  [04] 000000009f78 000600000007 0x00000007      test    sym.name  + 0
  [05] 000000009f80 000700000007 0x00000007      test    sym.name  + 0
  [06] 000000009f88 000800000007 0x00000007      test    sym.name  + 0
  [07] 000000009f90 000900000007 0x00000007      test    sym.name  + 0
  [08] 000000009f98 000b00000007 0x00000007      test    sym.name  + 0
  [09] 000000009fa0 000c00000007 0x00000007      test    sym.name  + 0
  [10] 000000009fa8 000e00000007 0x00000007      test    sym.name  + 0
  [11] 000000009fb0 000f00000007 0x00000007      test    sym.name  + 0
  [12] 000000009fb8 001000000007 0x00000007      test    sym.name  + 0
  [13] 000000009fc0 001100000007 0x00000007      test    sym.name  + 0
  [14] 000000009fc8 001200000007 0x00000007      test    sym.name  + 0
  [15] 000000009fd0 001400000007 0x00000007      test    sym.name  + 0

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=12,sect_name=".init",pSectData=0x559e89506890,iLen=0x1b}
    >> func{func_sect_init:(00923)} is call .
        No.[12]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514c70
        {
             Elf64_Word    sh_name      = 0xa1;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x6;
             Elf64_Addr    sh_addr      = 0x2000;
             Elf64_Off     sh_offset    = 0x2000;
             Elf64_Xword   sh_size      = 0x1b;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x4;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e89506890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|f3 0f 1e fa 48 83 ec 08  48 8b 05 d9 7f 00 00 48|....H...H......H|
      0x00000010|85 c0 74 02 ff d0 48 83  c4 08 c3 ** ** ** ** **|..t...H....*****|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=13,sect_name=".plt",pSectData=0x559e895068b0,iLen=0x110}
    >> func{func_sect_plt:(00946)} is call .
        No.[13]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514cb0
        {
             Elf64_Word    sh_name      = 0x9c;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x6;
             Elf64_Addr    sh_addr      = 0x2020;
             Elf64_Off     sh_offset    = 0x2020;
             Elf64_Xword   sh_size      = 0x110;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x10;
             Elf64_Xword   sh_entsize   = 0x10;
        }

0x00559e895068b0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|ff 35 22 7f 00 00 f2 ff  25 23 7f 00 00 0f 1f 00|.5".....%#......|
      0x00000010|f3 0f 1e fa 68 00 00 00  00 f2 e9 e1 ff ff ff 90|....h...........|
      0x00000020|f3 0f 1e fa 68 01 00 00  00 f2 e9 d1 ff ff ff 90|....h...........|
      0x00000030|f3 0f 1e fa 68 02 00 00  00 f2 e9 c1 ff ff ff 90|....h...........|
      0x00000040|f3 0f 1e fa 68 03 00 00  00 f2 e9 b1 ff ff ff 90|....h...........|
      0x00000050|f3 0f 1e fa 68 04 00 00  00 f2 e9 a1 ff ff ff 90|....h...........|
      0x00000060|f3 0f 1e fa 68 05 00 00  00 f2 e9 91 ff ff ff 90|....h...........|
      0x00000070|f3 0f 1e fa 68 06 00 00  00 f2 e9 81 ff ff ff 90|....h...........|
      0x00000080|f3 0f 1e fa 68 07 00 00  00 f2 e9 71 ff ff ff 90|....h......q....|
      0x00000090|f3 0f 1e fa 68 08 00 00  00 f2 e9 61 ff ff ff 90|....h......a....|
      0x000000a0|f3 0f 1e fa 68 09 00 00  00 f2 e9 51 ff ff ff 90|....h......Q....|
      0x000000b0|f3 0f 1e fa 68 0a 00 00  00 f2 e9 41 ff ff ff 90|....h......A....|
      0x000000c0|f3 0f 1e fa 68 0b 00 00  00 f2 e9 31 ff ff ff 90|....h......1....|
      0x000000d0|f3 0f 1e fa 68 0c 00 00  00 f2 e9 21 ff ff ff 90|....h......!....|
      0x000000e0|f3 0f 1e fa 68 0d 00 00  00 f2 e9 11 ff ff ff 90|....h...........|
      0x000000f0|f3 0f 1e fa 68 0e 00 00  00 f2 e9 01 ff ff ff 90|....h...........|
      0x00000100|f3 0f 1e fa 68 0f 00 00  00 f2 e9 f1 fe ff ff 90|....h...........|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=14,sect_name=".plt.got",pSectData=0x559e895069c0,iLen=0x10}
    >> func{func_sect_plt_got:(01019)} is call .
        No.[14]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514cf0
        {
             Elf64_Word    sh_name      = 0xa7;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x6;
             Elf64_Addr    sh_addr      = 0x2130;
             Elf64_Off     sh_offset    = 0x2130;
             Elf64_Xword   sh_size      = 0x10;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x10;
             Elf64_Xword   sh_entsize   = 0x10;
        }

0x00559e895069c0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|f3 0f 1e fa f2 ff 25 bd  7e 00 00 0f 1f 44 00 00|......%.~....D..|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=15,sect_name=".plt.sec",pSectData=0x559e895069d0,iLen=0x100}
    >> func{func_sect_plt_sec:(01037)} is call .
        No.[15]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514d30
        {
             Elf64_Word    sh_name      = 0xb0;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x6;
             Elf64_Addr    sh_addr      = 0x2140;
             Elf64_Off     sh_offset    = 0x2140;
             Elf64_Xword   sh_size      = 0x100;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x10;
             Elf64_Xword   sh_entsize   = 0x10;
        }

0x00559e895069d0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|f3 0f 1e fa f2 ff 25 0d  7e 00 00 0f 1f 44 00 00|......%.~....D..|
      0x00000010|f3 0f 1e fa f2 ff 25 05  7e 00 00 0f 1f 44 00 00|......%.~....D..|
      0x00000020|f3 0f 1e fa f2 ff 25 fd  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x00000030|f3 0f 1e fa f2 ff 25 f5  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x00000040|f3 0f 1e fa f2 ff 25 ed  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x00000050|f3 0f 1e fa f2 ff 25 e5  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x00000060|f3 0f 1e fa f2 ff 25 dd  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x00000070|f3 0f 1e fa f2 ff 25 d5  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x00000080|f3 0f 1e fa f2 ff 25 cd  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x00000090|f3 0f 1e fa f2 ff 25 c5  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x000000a0|f3 0f 1e fa f2 ff 25 bd  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x000000b0|f3 0f 1e fa f2 ff 25 b5  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x000000c0|f3 0f 1e fa f2 ff 25 ad  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x000000d0|f3 0f 1e fa f2 ff 25 a5  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x000000e0|f3 0f 1e fa f2 ff 25 9d  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      0x000000f0|f3 0f 1e fa f2 ff 25 95  7d 00 00 0f 1f 44 00 00|......%.}....D..|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=16,sect_name=".text",pSectData=0x559e89506ad0,iLen=0x3324}
    >> func{func_sect_text:(01120)} is call .
        No.[16]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514d70
        {
             Elf64_Word    sh_name      = 0xb9;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x6;
             Elf64_Addr    sh_addr      = 0x2240;
             Elf64_Off     sh_offset    = 0x2240;
             Elf64_Xword   sh_size      = 0x3324;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x10;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e89506ad0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|f3 0f 1e fa 31 ed 49 89  d1 5e 48 89 e2 48 83 e4|....1.I..^H..H..|
      0x00000010|f0 50 54 4c 8d 05 e6 32  00 00 48 8d 0d 6f 32 00|.PTL...2..H..o2.|
      0x00000020|00 48 8d 3d ff 30 00 00  ff 15 72 7d 00 00 f4 90|.H.=.0....r}....|
      0x00000030|48 8d 3d 09 80 00 00 48  8d 05 02 80 00 00 48 39|H.=....H......H9|
      0x00000040|f8 74 15 48 8b 05 4e 7d  00 00 48 85 c0 74 09 ff|.t.H..N}..H..t..|
      0x00000050|e0 0f 1f 80 00 00 00 00  c3 0f 1f 80 00 00 00 00|................|
      0x00000060|48 8d 3d d9 7f 00 00 48  8d 35 d2 7f 00 00 48 29|H.=....H.5....H)|
      0x00000070|fe 48 89 f0 48 c1 ee 3f  48 c1 f8 03 48 01 c6 48|.H..H..?H...H..H|
      0x00000080|d1 fe 74 14 48 8b 05 25  7d 00 00 48 85 c0 74 08|..t.H..%}..H..t.|
      0x00000090|ff e0 66 0f 1f 44 00 00  c3 0f 1f 80 00 00 00 00|..f..D..........|
      0x000000a0|f3 0f 1e fa 80 3d 9d 7f  00 00 00 75 2b 55 48 83|.....=.....u+UH.|
      0x000000b0|3d 02 7d 00 00 00 48 89  e5 74 0c 48 8b 3d 06 7d|=.}...H..t.H.=.}|
      0x000000c0|00 00 e8 29 fe ff ff e8  64 ff ff ff c6 05 75 7f|...)....d.....u.|
      0x000000d0|00 00 01 5d c3 0f 1f 00  c3 0f 1f 80 00 00 00 00|...]............|
      0x000000e0|f3 0f 1e fa e9 77 ff ff  ff f3 0f 1e fa 55 48 89|.....w.......UH.|
      0x000000f0|e5 90 5d c3 f3 0f 1e fa  55 48 89 e5 90 5d c3 f3|..].....UH...]..|
      0x00000100|0f 1e fa 55 48 89 e5 90  5d c3 f3 0f 1e fa 55 48|...UH...].....UH|
      0x00000110|89 e5 90 5d c3 f3 0f 1e  fa 55 48 89 e5 48 83 ec|...].....UH..H..|
      0x00000120|30 89 7d ec 48 89 75 e0  48 89 55 d8 48 8b 55 d8|0.}.H.u.H.U.H.U.|
      0x00000130|48 8b 45 e0 48 89 d6 48  89 c7 e8 91 fe ff ff 89|H.E.H..H........|
      0x00000140|45 fc 48 8b 05 f7 7e 00  00 ** ** ** ** ** ** **|E.H...~..*******|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=17,sect_name=".fini",pSectData=0x559e89509df4,iLen=0xd}
    >> func{func_sect_fini:(01241)} is call .
        No.[17]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514db0
        {
             Elf64_Word    sh_name      = 0xbf;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x6;
             Elf64_Addr    sh_addr      = 0x5564;
             Elf64_Off     sh_offset    = 0x5564;
             Elf64_Xword   sh_size      = 0xd;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x4;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e89509df4|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|f3 0f 1e fa 48 83 ec 08  48 83 c4 08 c3 ** ** **|....H...H....***|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=18,sect_name=".rodata",pSectData=0x559e8950a890,iLen=0x1abb}
    >> func{func_sect_rodata:(01259)} is call .
        No.[18]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514df0
        {
             Elf64_Word    sh_name      = 0xc5;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x6000;
             Elf64_Off     sh_offset    = 0x6000;
             Elf64_Xword   sh_size      = 0x1abb;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x10;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e8950a890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|01 00 02 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000010|0a 00 25 30 31 36 70 00  7c 30 30 20 30 31 20 30|..%016p.|00 01 0|
      0x00000020|32 20 30 33 20 30 34 20  30 35 20 30 36 20 30 37|2 03 04 05 06 07|
      0x00000030|20 20 30 38 20 30 39 20  30 41 20 30 42 20 30 43|  08 09 0A 0B 0C|
      0x00000040|20 30 44 20 30 45 20 30  46 7c 30 31 32 33 34 35| 0D 0E 0F|012345|
      0x00000050|36 37 38 39 41 42 43 44  45 46 7c 0a 00 00 00 00|6789ABCDEF|.....|
      0x00000060|20 20 20 20 20 20 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|      ==========|
      0x00000070|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x00000080|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x00000090|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x000000a0|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x000000b0|3d 3d 3d 0a 00 20 20 20  20 20 20 30 78 25 30 38|===..      0x%08|
      0x000000c0|78 7c 00 1b 5b 33 32 6d  00 25 30 32 78 20 00 2a|x|..[32m.%02x .*|
      0x000000d0|2a 20 00 20 00 25 30 32  78 00 2a 2a 00 1b 5b 30|* . .%02x.**..[0|
      0x000000e0|6d 00 7c 00 1b 5b 33 37  6d 2e 1b 5b 30 6d 00 25|m.|..[37m..[0m.%|
      0x000000f0|63 00 2a 00 00 00 00 00  20 20 3e 3e 20 67 65 74|c.*.....  >> get|
      0x00000100|5f 65 6c 66 36 34 5f 64  61 74 61 28 22 25 73 22|_elf64_data("%s"|
      0x00000110|2c 20 6c 65 6e 29 20 65  6e 74 72 79 3b 0a 00 72|, len) entry;..r|
      0x00000120|62 00 20 20 3e 3e 20 67  65 74 5f 65 6c 66 36 34|b.  >> get_elf64|
      0x00000130|5f 64 61 74 61 28 29 20  65 78 69 74 3b 0a 00 00|_data() exit;...|
      0x00000140|20 20 20 20 20 20 20 20  4e 6f 2e 5b 25 30 32 64|        No.[%02d|
      0x00000150|5d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|]---------------|
      0x00000160|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000170|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 0a 00 00|-------------...|
      0x00000180|20 20 20 20 20 20 20 20  73 74 72 75 63 74 20 53|        struct S|
      0x00000190|5f 45 4c 46 36 34 5f 53  65 63 74 48 65 61 64 65|_ELF64_SectHeade|
      0x000001a0|72 5f 74 20 2a 20 70 53  65 63 74 48 65 61 64 65|r_t * pSectHeade|
      0x000001b0|72 20 3d 20 25 70 0a 00  20 20 20 20 20 20 20 20|r = %p..        |
      0x000001c0|7b 0a 00 00 00 00 00 00  20 20 20 20 20 20 20 20|{.......        |
      0x000001d0|20 20 20 20 20 45 6c 66  36 34 5f 57 6f 72 64 20|     Elf64_Word |
      0x000001e0|20 20 20 73 68 5f 6e 61  6d 65 20 20 20 20 20 20|   sh_name      |
      0x000001f0|3d 20 30 78 25 78 3b 0a  00 00 00 00 00 00 00 00|= 0x%x;.........|
      0x00000200|20 20 20 20 20 20 20 20  20 20 20 20 20 45 6c 66|             Elf|
      0x00000210|36 34 5f 57 6f 72 64 20  20 20 20 73 68 5f 74 79|64_Word    sh_ty|
      0x00000220|70 65 20 20 20 20 20 20  3d 20 30 78 25 78 3b 0a|pe      = 0x%x;.|
      0x00000230|00 00 00 00 00 00 00 00  20 20 20 20 20 20 20 20|........        |
      0x00000240|20 20 20 20 20 45 6c 66  36 34 5f 58 77 6f 72 64|     Elf64_Xword|
      0x00000250|20 20 20 73 68 5f 66 6c  61 67 73 20 20 20 20 20|   sh_flags     |
      0x00000260|3d 20 30 78 25 6c 6c 78  3b 0a 00 00 00 00 00 00|= 0x%llx;.......|
      0x00000270|20 20 20 20 20 20 20 20  20 20 20 20 20 45 6c 66|             Elf|
      0x00000280|36 34 5f 41 64 64 72 20  20 20 20 73 68 5f 61 64|64_Addr    sh_ad|
      0x00000290|64 72 20 20 20 20 20 20  3d 20 30 78 25 6c 6c 78|dr      = 0x%llx|
      0x000002a0|3b 0a 00 00 00 00 00 00  20 20 20 20 20 20 20 20|;.......        |
      0x000002b0|20 20 20 20 20 45 6c 66  36 34 5f 4f 66 66 20 20|     Elf64_Off  |
      0x000002c0|20 20 20 73 68 5f 6f 66  66 73 65 74 20 20 20 20|   sh_offset    |
      0x000002d0|3d 20 30 78 25 6c 6c 78  3b 0a 00 00 00 00 00 00|= 0x%llx;.......|
      0x000002e0|20 20 20 20 20 20 20 20  20 20 20 20 20 45 6c 66|             Elf|
      0x000002f0|36 34 5f 58 77 6f 72 64  20 20 20 73 68 5f 73 69|64_Xword   sh_si|
      0x00000300|7a 65 20 20 20 20 20 20  3d 20 30 78 25 6c 6c 78|ze      = 0x%llx|
      0x00000310|3b 0a 00 00 00 00 00 00  20 20 20 20 20 20 20 20|;.......        |
      0x00000320|20 20 20 20 20 45 6c 66  36 34 5f 57 6f 72 64 20|     Elf64_Word |
      0x00000330|20 20 20 73 68 5f 6c 69  6e 6b 20 20 20 20 20 20|   sh_link      |
      0x00000340|3d 20 30 78 25 78 3b 0a  00 00 00 00 00 00 00 00|= 0x%x;.........|
      0x00000350|20 20 20 20 20 20 20 20  20 20 20 20 20 45 6c 66|             Elf|
      0x00000360|36 34 5f 57 6f 72 64 20  20 20 20 73 68 5f 69 6e|64_Word    sh_in|
      0x00000370|66 6f 20 20 20 20 20 20  3d 20 30 78 25 78 3b 0a|fo      = 0x%x;.|
      0x00000380|00 00 00 00 00 00 00 00  20 20 20 20 20 20 20 20|........        |
      0x00000390|20 20 20 20 20 45 6c 66  36 34 5f 58 77 6f 72 64|     Elf64_Xword|
      0x000003a0|20 20 20 73 68 5f 61 64  64 72 61 6c 69 67 6e 20|   sh_addralign |
      0x000003b0|3d 20 30 78 25 6c 6c 78  3b 0a 00 00 00 00 00 00|= 0x%llx;.......|
      0x000003c0|20 20 20 20 20 20 20 20  20 20 20 20 20 45 6c 66|             Elf|
      0x000003d0|36 34 5f 58 77 6f 72 64  20 20 20 73 68 5f 65 6e|64_Xword   sh_en|
      0x000003e0|74 73 69 7a 65 20 20 20  3d 20 30 78 25 6c 6c 78|tsize   = 0x%llx|
      0x000003f0|3b 0a 00 20 20 20 20 20  20 20 20 7d 0a 00 00 00|;..        }....|
      0x00000400|20 20 20 20 20 20 20 20  73 74 72 75 63 74 20 53|        struct S|
      0x00000410|5f 45 4c 46 36 34 5f 50  72 6f 67 48 65 61 64 65|_ELF64_ProgHeade|
      0x00000420|72 5f 74 20 0a 00 00 00  20 20 20 20 20 20 20 20|r_t ....        |
      0x00000430|20 20 20 20 20 45 6c 66  36 34 5f 57 6f 72 64 20|     Elf64_Word |
      0x00000440|20 20 20 70 5f 74 79 70  65 20 20 20 20 3d 20 30|   p_type    = 0|
      0x00000450|78 25 78 3b 20 20 0a 00  20 20 20 20 20 20 20 20|x%x;  ..        |
      0x00000460|20 20 20 20 20 45 6c 66  36 34 5f 57 6f 72 64 20|     Elf64_Word |
      0x00000470|20 20 20 70 5f 66 6c 61  67 73 20 20 20 3d 20 30|   p_flags   = 0|
      0x00000480|78 25 78 3b 20 20 0a 00  20 20 20 20 20 20 20 20|x%x;  ..        |
      0x00000490|20 20 20 20 20 45 6c 66  36 34 5f 4f 66 66 20 20|     Elf64_Off  |
      0x000004a0|20 20 20 70 5f 6f 66 66  73 65 74 20 20 3d 20 30|   p_offset  = 0|
      0x000004b0|78 25 6c 6c 78 3b 0a 00  20 20 20 20 20 20 20 20|x%llx;..        |
      0x000004c0|20 20 20 20 20 45 6c 66  36 34 5f 41 64 64 72 20|     Elf64_Addr |
      0x000004d0|20 20 20 70 5f 76 61 64  64 72 20 20 20 3d 20 30|   p_vaddr   = 0|
      0x000004e0|78 25 6c 6c 78 3b 0a 00  20 20 20 20 20 20 20 20|x%llx;..        |
      0x000004f0|20 20 20 20 20 45 6c 66  36 34 5f 41 64 64 72 20|     Elf64_Addr |
      0x00000500|20 20 20 70 5f 70 61 64  64 72 20 20 20 3d 20 30|   p_paddr   = 0|
      0x00000510|78 25 6c 6c 78 3b 0a 00  20 20 20 20 20 20 20 20|x%llx;..        |
      0x00000520|20 20 20 20 20 45 6c 66  36 34 5f 58 77 6f 72 64|     Elf64_Xword|
      0x00000530|20 20 20 70 5f 66 69 6c  65 73 7a 20 20 3d 20 30|   p_filesz  = 0|
      0x00000540|78 25 6c 6c 78 3b 0a 00  20 20 20 20 20 20 20 20|x%llx;..        |
      0x00000550|20 20 20 20 20 45 6c 66  36 34 5f 58 77 6f 72 64|     Elf64_Xword|
      0x00000560|20 20 20 70 5f 6d 65 6d  73 7a 20 20 20 3d 20 30|   p_memsz   = 0|
      0x00000570|78 25 6c 6c 78 3b 0a 00  20 20 20 20 20 20 20 20|x%llx;..        |
      0x00000580|20 20 20 20 20 45 6c 66  36 34 5f 58 77 6f 72 64|     Elf64_Xword|
      0x00000590|20 20 20 70 5f 61 6c 69  67 6e 20 20 20 3d 20 30|   p_align   = 0|
      0x000005a0|78 25 6c 6c 78 3b 0a 00  20 20 3e 3e 20 66 75 6e|x%llx;..  >> fun|
      0x000005b0|63 7b 25 73 3a 28 25 30  35 64 29 7d 20 69 73 20|c{%s:(%05d)} is |
      0x000005c0|63 61 6c 6c 2e 7b 70 45  6c 66 44 61 74 61 3d 25|call.{pElfData=%|
      0x000005d0|70 7d 2e 0a 00 00 00 00  20 20 20 20 20 20 20 20|p}......        |
      0x000005e0|73 74 72 75 63 74 20 53  5f 45 4c 46 36 34 5f 45|struct S_ELF64_E|
      0x000005f0|4c 46 48 65 61 64 65 72  5f 74 20 70 45 6c 66 48|LFHeader_t pElfH|
      0x00000600|65 61 64 65 72 20 3d 20  7b 25 70 7d 20 0a 00 00|eader = {%p} ...|
      0x00000610|20 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20|                |
      0x00000620|20 75 6e 73 69 67 6e 65  64 20 63 68 61 72 20 65| unsigned char e|
      0x00000630|5f 69 64 65 6e 74 5b 31  36 5d 20 3d 20 7b 00 7d|_ident[16] = {.}|
      0x00000640|3b 0a 00 00 00 00 00 00  20 20 20 20 20 20 20 20|;.......        |
      0x00000650|20 20 20 20 20 20 20 20  20 45 6c 66 36 34 5f 48|         Elf64_H|
      0x00000660|61 6c 66 20 20 20 20 65  5f 74 79 70 65 20 20 20|alf    e_type   |
      0x00000670|20 20 20 3d 20 30 78 25  30 34 78 3b 0a 00 00 00|   = 0x%04x;....|
      0x00000680|20 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20|                |
      0x00000690|20 45 6c 66 36 34 5f 48  61 6c 66 20 20 20 20 65| Elf64_Half    e|
      0x000006a0|5f 6d 61 63 68 69 6e 65  20 20 20 3d 20 30 78 25|_machine   = 0x%|
      0x000006b0|30 34 78 3b 0a 00 00 00  20 20 20 20 20 20 20 20|04x;....        |
      0x000006c0|20 20 20 20 20 20 20 20  20 45 6c 66 36 34 5f 57|         Elf64_W|
      0x000006d0|6f 72 64 20 20 20 20 65  5f 76 65 72 73 69 6f 6e|ord    e_version|
      0x000006e0|20 20 20 3d 20 30 78 25  78 20 20 3b 0a 00 00 00|   = 0x%x  ;....|
      0x000006f0|20 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20|                |
      0x00000700|20 45 6c 66 36 34 5f 41  64 64 72 20 20 20 20 65| Elf64_Addr    e|
      0x00000710|5f 65 6e 74 72 79 20 20  20 20 20 3d 20 30 78 25|_entry     = 0x%|
      0x00000720|6c 6c 78 3b 0a 00 00 00  20 20 20 20 20 20 20 20|llx;....        |
      0x00000730|20 20 20 20 20 20 20 20  20 45 6c 66 36 34 5f 4f|         Elf64_O|
      0x00000740|66 66 20 20 20 20 20 65  5f 70 68 6f 66 66 20 20|ff     e_phoff  |
      0x00000750|20 20 20 3d 20 30 78 25  6c 6c 78 3b 0a 00 00 00|   = 0x%llx;....|
      0x00000760|20 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20|                |
      0x00000770|20 45 6c 66 36 34 5f 4f  66 66 20 20 20 20 20 65| Elf64_Off     e|
      0x00000780|5f 73 68 6f 66 66 20 20  20 20 20 3d 20 30 78 25|_shoff     = 0x%|
      0x00000790|6c 6c 78 3b 0a 00 00 00  20 20 20 20 20 20 20 20|llx;....        |
      0x000007a0|20 20 20 20 20 20 20 20  20 45 6c 66 36 34 5f 57|         Elf64_W|
      0x000007b0|6f 72 64 20 20 20 20 65  5f 66 6c 61 67 73 20 20|ord    e_flags  |
      0x000007c0|20 20 20 3d 20 30 78 25  78 20 20 3b 0a 00 00 00|   = 0x%x  ;....|
      0x000007d0|20 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20|                |
      0x000007e0|20 45 6c 66 36 34 5f 48  61 6c 66 20 20 20 20 65| Elf64_Half    e|
      0x000007f0|5f 65 68 73 69 7a 65 20  20 20 20 3d 20 30 78 25|_ehsize    = 0x%|
      0x00000800|30 34 78 3b 0a 00 00 00  20 20 20 20 20 20 20 20|04x;....        |
      0x00000810|20 20 20 20 20 20 20 20  20 45 6c 66 36 34 5f 48|         Elf64_H|
      0x00000820|61 6c 66 20 20 20 20 65  5f 70 68 65 6e 74 73 69|alf    e_phentsi|
      0x00000830|7a 65 20 3d 20 30 78 25  30 34 78 3b 0a 00 00 00|ze = 0x%04x;....|
      0x00000840|20 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20|                |
      0x00000850|20 45 6c 66 36 34 5f 48  61 6c 66 20 20 20 20 65| Elf64_Half    e|
      0x00000860|5f 70 68 6e 75 6d 20 20  20 20 20 3d 20 30 78 25|_phnum     = 0x%|
      0x00000870|30 34 78 3b 0a 00 00 00  20 20 20 20 20 20 20 20|04x;....        |
      0x00000880|20 20 20 20 20 20 20 20  20 45 6c 66 36 34 5f 48|         Elf64_H|
      0x00000890|61 6c 66 20 20 20 20 65  5f 73 68 65 6e 74 73 69|alf    e_shentsi|
      0x000008a0|7a 65 20 3d 20 30 78 25  30 34 78 3b 0a 00 00 00|ze = 0x%04x;....|
      0x000008b0|20 20 20 20 20 20 20 20  20 20 20 20 20 20 20 20|                |
      0x000008c0|20 45 6c 66 36 34 5f 48  61 6c 66 20 20 20 20 65| Elf64_Half    e|
      0x000008d0|5f 73 68 6e 75 6d 20 20  20 20 20 3d 20 30 78 25|_shnum     = 0x%|
      0x000008e0|30 34 78 3b 0a 00 00 00  20 20 20 20 20 20 20 20|04x;....        |
      0x000008f0|20 20 20 20 20 20 20 20  20 45 6c 66 36 34 5f 48|         Elf64_H|
      0x00000900|61 6c 66 20 20 20 20 65  5f 73 68 73 74 72 6e 64|alf    e_shstrnd|
      0x00000910|78 20 20 3d 20 30 78 25  30 34 78 3b 0a 00 20 20|x  = 0x%04x;..  |
      0x00000920|20 20 20 20 20 20 7d 3b  0a 00 00 00 00 00 00 00|      };........|
      0x00000930|20 20 3e 3e 20 66 75 6e  63 7b 25 73 3a 28 25 30|  >> func{%s:(%0|
      0x00000940|35 64 29 7d 20 69 73 20  63 61 6c 6c 20 2e 0a 00|5d)} is call ...|
      0x00000950|6d 79 72 65 61 64 65 6c  66 2d 30 2e 31 2e 30 38|myreadelf-0.1.08|
      0x00000960|2e 63 00 70 53 65 63 74  48 65 61 64 65 72 20 21|.c.pSectHeader !|
      0x00000970|3d 20 4e 55 4c 4c 00 0a  0a 00 00 00 00 00 00 00|= NULL..........|
      0x00000980|1b 5b 31 6d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|.[1m------------|
      0x00000990|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x000009a0|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x000009b0|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x000009c0|2d 2d 2d 2d 1b 5b 30 6d  0a 00 53 65 63 74 69 6f|----.[0m..Sectio|
      0x000009d0|6e 20 48 65 61 64 65 72  73 3a 20 20 0a 00 00 00|n Headers:  ....|
      0x000009e0|20 20 5b 4e 72 5d 20 4e  61 6d 65 20 20 20 20 20|  [Nr] Name     |
      0x000009f0|20 20 20 20 20 20 20 54  79 70 65 20 20 20 20 20|       Type     |
      0x00000a00|20 41 64 64 72 65 73 73  20 20 20 20 20 4f 66 66| Address     Off|
      0x00000a10|73 65 74 20 20 53 69 7a  65 20 20 20 20 45 6e 74|set  Size    Ent|
      0x00000a20|53 69 7a 65 20 46 6c 61  67 73 20 20 4c 69 6e 6b|Size Flags  Link|
      0x00000a30|20 20 20 49 6e 66 6f 20  20 20 41 6c 69 67 6e 0a|   Info   Align.|
      0x00000a40|00 00 00 00 00 00 00 00  20 20 5b 25 30 32 64 5d|........  [%02d]|
      0x00000a50|20 25 2d 31 35 2e 31 35  73 20 25 30 38 78 20 20| %-15.15s %08x  |
      0x00000a60|25 30 31 30 6c 6c 78 20  20 25 36 2e 36 6c 6c 64|%010llx  %6.6lld|
      0x00000a70|20 20 25 36 2e 36 6c 6c  64 20 20 25 36 2e 36 6c|  %6.6lld  %6.6l|
      0x00000a80|6c 64 20 20 30 78 25 30  34 6c 6c 78 20 30 78 25|ld  0x%04llx 0x%|
      0x00000a90|30 34 78 20 30 78 25 30  34 78 20 30 78 25 30 34|04x 0x%04x 0x%04|
      0x00000aa0|6c 6c 78 0a 00 70 50 72  6f 67 48 65 61 64 65 72|llx..pProgHeader|
      0x00000ab0|20 21 3d 20 4e 55 4c 4c  00 00 00 00 00 00 00 00| != NULL........|
      0x00000ac0|20 20 20 20 1b 5b 31 6d  2d 2d 2d 2d 2d 2d 2d 2d|    .[1m--------|
      0x00000ad0|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000ae0|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000af0|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000b00|2d 2d 2d 2d 2d 2d 2d 2d  1b 5b 30 6d 0a 00 20 20|--------.[0m..  |
      0x00000b10|20 20 50 72 6f 67 72 61  6d 20 48 65 61 64 65 72|  Program Header|
      0x00000b20|73 3a 0a 00 00 00 00 00  20 20 20 20 5b 4e 6f 5d|s:......    [No]|
      0x00000b30|20 54 79 70 65 20 20 20  20 20 4f 66 66 73 65 74| Type     Offset|
      0x00000b40|20 20 20 56 69 72 74 41  64 64 72 20 20 20 50 68|   VirtAddr   Ph|
      0x00000b50|79 73 41 64 64 72 20 20  20 46 69 6c 65 53 69 7a|ysAddr   FileSiz|
      0x00000b60|20 20 4d 65 6d 53 69 7a  20 20 20 46 6c 61 67 73|  MemSiz   Flags|
      0x00000b70|20 20 20 20 41 6c 69 67  6e 0a 00 00 00 00 00 00|    Align.......|
      0x00000b80|20 20 20 20 5b 25 30 32  64 5d 20 25 30 38 78 20|    [%02d] %08x |
      0x00000b90|25 30 38 6c 6c 78 20 25  30 31 30 6c 6c 78 20 25|%08llx %010llx %|
      0x00000ba0|30 31 30 6c 6c 78 20 30  78 25 30 36 6c 6c 78 20|010llx 0x%06llx |
      0x00000bb0|30 78 25 30 36 6c 6c 78  20 30 78 25 30 36 78 20|0x%06llx 0x%06x |
      0x00000bc0|30 78 25 30 36 6c 6c 78  0a 00 2e 69 6e 74 65 72|0x%06llx...inter|
      0x00000bd0|70 00 2e 6e 6f 74 65 2e  67 6e 75 2e 70 72 6f 70|p..note.gnu.prop|
      0x00000be0|65 00 2e 6e 6f 74 65 2e  41 42 49 2d 74 61 67 00|e..note.ABI-tag.|
      0x00000bf0|2e 6e 6f 74 65 2e 67 6e  75 2e 62 75 69 6c 64 2d|.note.gnu.build-|
      0x00000c00|69 64 00 2e 67 6e 75 2e  68 61 73 68 00 2e 64 79|id..gnu.hash..dy|
      0x00000c10|6e 73 79 6d 00 2e 64 79  6e 73 74 72 00 2e 67 6e|nsym..dynstr..gn|
      0x00000c20|75 2e 76 65 72 73 69 6f  6e 00 2e 67 6e 75 2e 76|u.version..gnu.v|
      0x00000c30|65 72 73 69 6f 6e 5f 72  00 2e 72 65 6c 61 2e 64|ersion_r..rela.d|
      0x00000c40|79 6e 00 2e 72 65 6c 61  2e 70 6c 74 00 2e 69 6e|yn..rela.plt..in|
      0x00000c50|69 74 00 2e 70 6c 74 00  2e 70 6c 74 2e 67 6f 74|it..plt..plt.got|
      0x00000c60|00 2e 70 6c 74 2e 73 65  63 00 2e 74 65 78 74 00|..plt.sec..text.|
      0x00000c70|2e 66 69 6e 69 00 2e 72  6f 64 61 74 61 00 2e 65|.fini..rodata..e|
      0x00000c80|68 5f 66 72 61 6d 65 5f  68 64 72 00 2e 65 68 5f|h_frame_hdr..eh_|
      0x00000c90|66 72 61 6d 65 00 2e 69  6e 69 74 5f 61 72 72 61|frame..init_arra|
      0x00000ca0|79 00 2e 66 69 6e 69 5f  61 72 72 61 79 00 2e 64|y..fini_array..d|
      0x00000cb0|79 6e 61 6d 69 63 00 2e  67 6f 74 00 2e 67 6f 74|ynamic..got..got|
      0x00000cc0|2e 70 6c 74 00 2e 64 61  74 61 00 2e 62 73 73 00|.plt..data..bss.|
      0x00000cd0|2e 63 6f 6d 6d 65 6e 74  00 2e 64 65 62 75 67 5f|.comment..debug_|
      0x00000ce0|61 72 61 6e 67 65 73 00  2e 64 65 62 75 67 5f 69|aranges..debug_i|
      0x00000cf0|6e 66 6f 00 2e 64 65 62  75 67 5f 61 62 62 72 65|nfo..debug_abbre|
      0x00000d00|76 00 2e 64 65 62 75 67  5f 6c 69 6e 65 00 2e 64|v..debug_line..d|
      0x00000d10|65 62 75 67 5f 73 74 72  00 2e 73 79 6d 74 61 62|ebug_str..symtab|
      0x00000d20|00 2e 73 74 72 74 61 62  00 2e 73 68 73 74 72 74|..strtab..shstrt|
      0x00000d30|61 62 00 00 00 00 00 00  20 20 20 20 3e 3e 20 66|ab......    >> f|
      0x00000d40|75 6e 63 7b 25 73 3a 28  25 30 35 64 29 7d 20 69|unc{%s:(%05d)} i|
      0x00000d50|73 20 63 61 6c 6c 20 2e  0a 00 00 00 00 00 00 00|s call .........|
      0x00000d60|20 20 20 20 20 20 1b 5b  31 6d 2d 2d 2d 2d 2d 2d|      .[1m------|
      0x00000d70|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000d80|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000d90|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000da0|2d 2d 2d 2d 2d 2d 0a 00  20 20 20 20 20 20 00 00|------..      ..|
      0x00000db0|20 20 20 20 20 20 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|      ----------|
      0x00000dc0|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000dd0|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000de0|2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d|----------------|
      0x00000df0|2d 2d 1b 5b 30 6d 0a 00  20 20 20 20 20 20 53 79|--.[0m..      Sy|
      0x00000e00|6d 62 6f 6c 20 74 61 62  6c 65 20 27 2e 64 79 6e|mbol table '.dyn|
      0x00000e10|73 79 6d 27 20 63 6f 6e  74 61 69 6e 73 20 25 64|sym' contains %d|
      0x00000e20|20 65 6e 74 72 69 65 73  3a 0a 00 00 00 00 00 00| entries:.......|
      0x00000e30|20 20 20 20 20 20 20 20  20 4e 75 6d 3a 20 20 20|         Num:   |
      0x00000e40|20 56 61 6c 75 65 20 20  20 20 20 20 20 20 20 20| Value          |
      0x00000e50|53 69 7a 65 20 54 79 70  65 20 20 20 20 42 69 6e|Size Type    Bin|
      0x00000e60|64 20 20 20 56 69 73 20  20 20 20 20 20 4e 64 78|d   Vis      Ndx|
      0x00000e70|20 20 4e 61 6d 65 20 20  4e 61 6d 65 53 74 72 0a|  Name  NameStr.|
      0x00000e80|00 00 00 00 00 00 00 00  20 20 20 20 20 20 20 20|........        |
      0x00000e90|20 1b 5b 31 6d 25 30 33  64 3a 20 25 31 36 6c 6c| .[1m%03d: %16ll|
      0x00000ea0|78 20 25 35 6c 6c 78 20  20 25 30 32 78 20 20 20|x %5llx  %02x   |
      0x00000eb0|20 20 20 25 30 32 78 20  20 20 20 25 30 32 78 20|   %02x    %02x |
      0x00000ec0|20 20 20 20 20 20 25 30  34 78 20 25 30 34 78 20|      %04x %04x |
      0x00000ed0|1b 5b 30 6d 0a 00 00 00  20 20 20 20 20 20 3d 3d|.[0m....      ==|
      0x00000ee0|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x00000ef0|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x00000f00|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x00000f10|3d 3d 3d 3d 3d 3d 3d 3d  3d 0a 00 00 00 00 00 00|=========.......|
      0x00000f20|20 20 20 20 20 20 3e 3e  20 70 74 72 5b 25 30 33|      >> ptr[%03|
      0x00000f30|64 5d 3d 25 30 31 36 70  3b 20 73 74 72 3d 7b 22|d]=%016p; str={"|
      0x00000f40|25 73 22 7d 3b 0a 00 00  20 20 20 20 52 65 6c 6f|%s"};...    Relo|
      0x00000f50|63 61 74 69 6f 6e 20 73  65 63 74 69 6f 6e 20 27|cation section '|
      0x00000f60|2e 72 65 6c 61 2e 64 79  6e 27 20 61 74 20 6f 66|.rela.dyn' at of|
      0x00000f70|66 73 65 74 20 3f 3f 20  63 6f 6e 74 61 69 6e 73|fset ?? contains|
      0x00000f80|20 25 64 20 65 6e 74 72  69 65 73 3a 0a 00 00 00| %d entries:....|
      0x00000f90|20 20 20 20 20 20 49 64  78 20 20 4f 66 66 73 65|      Idx  Offse|
      0x00000fa0|74 20 20 20 20 20 20 20  20 20 20 49 6e 66 6f 20|t          Info |
      0x00000fb0|20 20 20 20 20 20 20 20  54 79 70 65 20 20 20 20|        Type    |
      0x00000fc0|20 20 53 79 6d 2e 20 56  61 6c 75 65 20 53 79 6d|  Sym. Value Sym|
      0x00000fd0|2e 20 4e 61 6d 65 20 2b  20 41 64 64 65 6e 64 0a|. Name + Addend.|
      0x00000fe0|00 00 00 00 00 00 00 00  20 20 20 20 20 20 5b 25|........      [%|
      0x00000ff0|30 32 64 5d 1b 5b 31 6d  20 25 30 31 32 6c 6c 78|02d].[1m %012llx|
      0x00001000|20 25 30 31 32 6c 6c 78  20 30 78 25 30 38 6c 6c| %012llx 0x%08ll|
      0x00001010|78 20 20 20 20 20 20 74  65 73 74 20 20 20 20 73|x      test    s|
      0x00001020|79 6d 2e 6e 61 6d 65 20  20 2b 20 25 6c 6c 64 1b|ym.name  + %lld.|
      0x00001030|5b 30 6d 0a 00 00 00 00  52 65 6c 6f 63 61 74 69|[0m.....Relocati|
      0x00001040|6f 6e 20 73 65 63 74 69  6f 6e 20 27 2e 72 65 6c|on section '.rel|
      0x00001050|61 2e 70 6c 74 27 20 61  74 20 6f 66 66 73 65 74|a.plt' at offset|
      0x00001060|20 3f 3f 20 63 6f 6e 74  61 69 6e 73 20 25 64 20| ?? contains %d |
      0x00001070|65 6e 74 72 69 65 73 3a  0a 00 00 00 00 00 00 00|entries:........|
      0x00001080|20 20 49 64 78 20 20 4f  66 66 73 65 74 20 20 20|  Idx  Offset   |
      0x00001090|20 20 20 20 20 20 20 49  6e 66 6f 20 20 20 20 20|       Info     |
      0x000010a0|20 20 20 20 54 79 70 65  20 20 20 20 20 20 53 79|    Type      Sy|
      0x000010b0|6d 2e 20 56 61 6c 75 65  20 53 79 6d 2e 20 4e 61|m. Value Sym. Na|
      0x000010c0|6d 65 20 2b 20 41 64 64  65 6e 64 0a 00 00 00 00|me + Addend.....|
      0x000010d0|20 20 5b 25 30 32 64 5d  1b 5b 31 6d 20 25 30 31|  [%02d].[1m %01|
      0x000010e0|32 6c 6c 78 20 25 30 31  32 6c 6c 78 20 30 78 25|2llx %012llx 0x%|
      0x000010f0|30 38 6c 6c 78 20 20 20  20 20 20 74 65 73 74 20|08llx      test |
      0x00001100|20 20 20 73 79 6d 2e 6e  61 6d 65 20 20 2b 20 25|   sym.name  + %|
      0x00001110|6c 6c 64 1b 5b 30 6d 0a  00 00 00 00 00 00 00 00|lld.[0m.........|
      0x00001120|20 20 3e 3e 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|  >>============|
      0x00001130|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x00001140|3d 3d 3d 3d 3d 3d 3d 3d  3d 3d 3d 3d 3d 3d 3d 3d|================|
      0x00001150|3d 0a 00 20 20 20 20 20  20 3e 3e 20 70 74 72 5b|=..      >> ptr[|
      0x00001160|25 30 33 64 5d 20 3d 20  25 30 31 36 70 3b 0a 00|%03d] = %016p;..|
      0x00001170|53 79 6d 62 6f 6c 20 74  61 62 6c 65 20 27 2e 73|Symbol table '.s|
      0x00001180|79 6d 74 61 62 27 20 63  6f 6e 74 61 69 6e 73 20|ymtab' contains |
      0x00001190|25 64 20 65 6e 74 72 69  65 73 3a 0a 00 00 00 00|%d entries:.....|
      0x000011a0|20 20 20 4e 75 6d 3a 20  20 20 20 56 61 6c 75 65|   Num:    Value|
      0x000011b0|20 20 53 69 7a 65 20 54  79 70 65 20 20 20 20 42|  Size Type    B|
      0x000011c0|69 6e 64 20 20 20 56 69  73 20 20 20 20 20 20 4e|ind   Vis      N|
      0x000011d0|64 78 20 20 4e 61 6d 65  20 20 4e 61 6d 65 53 74|dx  Name  NameSt|
      0x000011e0|72 00 00 00 00 00 00 00  20 20 20 1b 5b 31 6d 25|r.......   .[1m%|
      0x000011f0|30 33 64 3a 20 25 38 6c  6c 78 20 25 35 6c 6c 64|03d: %8llx %5lld|
      0x00001200|20 20 25 30 32 78 20 20  20 20 20 20 25 30 32 78|  %02x      %02x|
      0x00001210|20 20 20 20 25 30 32 78  20 20 20 20 20 20 20 25|    %02x       %|
      0x00001220|30 34 78 20 25 30 34 78  20 20 25 73 1b 5b 30 6d|04x %04x  %s.[0m|
      0x00001230|0a 00 74 65 6d 70 73 74  72 00 00 00 00 00 00 00|..tempstr.......|
      0x00001240|20 20 20 20 20 20 3e 3e  3e 20 7b 69 64 78 3d 25|      >>> {idx=%|
      0x00001250|64 2c 20 6e 61 6d 65 3d  22 25 73 22 2c 20 70 44|d, name="%s", pD|
      0x00001260|61 74 61 3d 25 70 2c 20  69 4c 65 6e 3d 25 64 2c|ata=%p, iLen=%d,|
      0x00001270|20 70 53 65 63 74 48 65  61 64 65 72 3d 25 70 7d| pSectHeader=%p}|
      0x00001280|2e 00 00 00 00 00 00 00  20 20 3e 3e 20 66 75 6e|........  >> fun|
      0x00001290|63 7b 25 73 3a 28 25 30  35 64 29 7d 20 69 73 20|c{%s:(%05d)} is |
      0x000012a0|63 61 6c 6c 2e 20 0a 20  20 20 20 20 20 1b 5b 31|call. .      .[1|
      0x000012b0|6d 7b 69 64 78 3d 25 30  32 64 2c 73 65 63 74 5f|m{idx=%02d,sect_|
      0x000012c0|6e 61 6d 65 3d 22 25 73  22 2c 70 53 65 63 74 44|name="%s",pSectD|
      0x000012d0|61 74 61 3d 25 70 2c 69  4c 65 6e 3d 30 78 25 78|ata=%p,iLen=0x%x|
      0x000012e0|7d 1b 5b 30 6d 0a 00 00  20 20 3e 3e 20 62 75 69|}.[0m...  >> bui|
      0x000012f0|6c 64 5f 65 6c 66 36 34  5f 6f 62 6a 28 25 70 2c|ld_elf64_obj(%p,|
      0x00001300|20 25 64 29 20 65 6e 74  72 79 3b 0a 00 20 20 3e| %d) entry;..  >|
      0x00001310|3e 20 62 75 69 6c 64 5f  65 6c 66 36 34 5f 6f 62|> build_elf64_ob|
      0x00001320|6a 28 29 20 65 78 69 74  3b 0a 00 00 00 00 00 00|j() exit;.......|
      0x00001330|1b 5b 31 3b 33 32 6d 23  23 23 23 23 23 23 23 23|.[1;32m#########|
      0x00001340|23 23 23 23 23 23 23 23  23 23 23 23 23 23 23 23|################|
      0x00001350|23 23 23 23 23 23 23 23  23 23 23 23 23 23 23 23|################|
      0x00001360|23 23 23 23 23 23 23 7b  7d 23 23 23 23 23 23 23|#######{}#######|
      0x00001370|23 23 23 23 23 23 23 23  23 23 23 23 23 23 23 23|################|
      0x00001380|23 23 23 23 23 23 23 23  23 23 23 23 23 23 23 23|################|
      0x00001390|23 23 23 23 23 23 23 23  23 23 23 1b 5b 30 6d 0a|###########.[0m.|
      0x000013a0|00 20 20 1b 5b 31 3b 33  31 6d 23 3d 3d 3d 3d 3e|.  .[1;31m#====>|
      0x000013b0|3e 3e 3e 1b 5b 30 6d 0a  00 00 00 00 00 00 00 00|>>>.[0m.........|
      0x000013c0|20 20 3e 3e 20 66 75 6e  63 7b 25 73 3a 28 25 30|  >> func{%s:(%0|
      0x000013d0|35 64 29 40 28 25 73 29  7d 20 69 73 20 63 61 6c|5d)@(%s)} is cal|
      0x000013e0|6c 20 2e 0a 00 20 20 1b  5b 31 3b 33 31 6d 23 3c|l ...  .[1;31m#<|
      0x000013f0|3c 3c 3c 3d 3d 3d 3d 1b  5b 30 6d 0a 00 00 00 00|<<<====.[0m.....|
      0x00001400|20 20 3e 3e 20 66 75 6e  63 3a 25 73 28 25 64 2c|  >> func:%s(%d,|
      0x00001410|20 25 70 29 20 69 73 20  63 61 6c 6c 65 64 2e 20| %p) is called. |
      0x00001420|28 40 66 69 6c 65 3a 25  73 2c 6c 69 6e 65 3a 25|(@file:%s,line:%|
      0x00001430|30 34 64 29 2e 0a 00 00  20 20 20 20 3e 3e 3e 20|04d)....    >>> |
      0x00001440|61 72 67 76 5b 25 30 32  64 5d 28 61 64 64 72 3d|argv[%02d](addr=|
      0x00001450|25 70 29 20 3d 20 7b 22  25 73 22 7d 2e 0a 00 00|%p) = {"%s"}....|
      0x00001460|20 20 3e 3e 20 66 75 6e  63 3a 25 73 28 29 20 69|  >> func:%s() i|
      0x00001470|73 20 63 61 6c 6c 65 64  2e 20 40 6c 69 6e 65 3a|s called. @line:|
      0x00001480|28 25 30 34 64 29 2e 0a  00 00 00 00 00 00 00 00|(%04d)..........|
      0x00001490|20 20 3e 3e 20 74 68 65  20 61 70 70 20 73 74 61|  >> the app sta|
      0x000014a0|72 74 69 6e 67 20 2e 2e  2e 20 2e 2e 2e 0a 00 00|rting ... ......|
      0x000014b0|20 20 20 3e 3e 3e 20 1b  5b 33 31 6d 67 65 74 5f|   >>> .[31mget_|
      0x000014c0|65 6c 66 36 34 5f 64 61  74 61 28 25 73 29 20 72|elf64_data(%s) r|
      0x000014d0|65 74 28 4e 55 4c 4c 29  2e 1b 5b 30 6d 0a 00 20|et(NULL)..[0m.. |
      0x000014e0|20 3e 3e 20 74 68 65 20  61 70 70 20 65 78 69 74| >> the app exit|
      0x000014f0|2e 0a 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001500|70 61 72 73 65 5f 65 6c  66 36 34 5f 65 6c 66 5f|parse_elf64_elf_|
      0x00001510|68 65 61 64 65 72 00 00  00 00 00 00 00 00 00 00|header..........|
      0x00001520|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
      0x00001530|5f 68 65 61 64 65 72 73  00 00 00 00 00 00 00 00|_headers........|
      0x00001540|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
      0x00001550|5f 68 65 61 64 65 72 73  00 00 00 00 00 00 00 00|_headers........|
      0x00001560|70 61 72 73 65 5f 65 6c  66 36 34 5f 70 72 6f 67|parse_elf64_prog|
      0x00001570|5f 68 65 61 64 65 72 73  00 00 00 00 00 00 00 00|_headers........|
      0x00001580|70 61 72 73 65 5f 65 6c  66 36 34 5f 70 72 6f 67|parse_elf64_prog|
      0x00001590|5f 68 65 61 64 65 72 73  00 00 00 00 00 00 00 00|_headers........|
      0x000015a0|66 75 6e 63 5f 73 65 63  74 5f 6e 6f 74 65 5f 67|func_sect_note_g|
      0x000015b0|6e 75 5f 70 72 6f 70 65  00 00 00 00 00 00 00 00|nu_prope........|
      0x000015c0|66 75 6e 63 5f 73 65 63  74 5f 6e 6f 74 65 5f 67|func_sect_note_g|
      0x000015d0|6e 75 5f 62 75 69 6c 64  00 00 00 00 00 00 00 00|nu_build........|
      0x000015e0|66 75 6e 63 5f 73 65 63  74 5f 6e 6f 74 65 5f 41|func_sect_note_A|
      0x000015f0|42 49 5f 74 61 67 00 00  00 00 00 00 00 00 00 00|BI_tag..........|
      0x00001600|66 75 6e 63 5f 73 65 63  74 5f 6e 6f 74 65 5f 67|func_sect_note_g|
      0x00001610|6e 75 5f 62 75 69 6c 64  5f 69 64 00 00 00 00 00|nu_build_id.....|
      0x00001620|66 75 6e 63 5f 73 65 63  74 5f 67 6e 75 5f 68 61|func_sect_gnu_ha|
      0x00001630|73 68 00 00 00 00 00 00  00 00 00 00 00 00 00 00|sh..............|
      0x00001640|66 75 6e 63 5f 73 65 63  74 5f 67 6e 75 5f 76 65|func_sect_gnu_ve|
      0x00001650|72 73 69 6f 6e 00 00 00  00 00 00 00 00 00 00 00|rsion...........|
      0x00001660|66 75 6e 63 5f 73 65 63  74 5f 67 6e 75 5f 76 65|func_sect_gnu_ve|
      0x00001670|72 73 69 6f 6e 5f 72 00  00 00 00 00 00 00 00 00|rsion_r.........|
      0x00001680|66 75 6e 63 5f 73 65 63  74 5f 65 68 5f 66 72 61|func_sect_eh_fra|
      0x00001690|6d 65 5f 68 64 72 00 00  00 00 00 00 00 00 00 00|me_hdr..........|
      0x000016a0|66 75 6e 63 5f 73 65 63  74 5f 65 68 5f 66 72 61|func_sect_eh_fra|
      0x000016b0|6d 65 00 00 00 00 00 00  00 00 00 00 00 00 00 00|me..............|
      0x000016c0|66 75 6e 63 5f 73 65 63  74 5f 64 65 62 75 67 5f|func_sect_debug_|
      0x000016d0|61 72 61 6e 67 65 73 00  00 00 00 00 00 00 00 00|aranges.........|
      0x000016e0|66 75 6e 63 5f 73 65 63  74 5f 64 65 62 75 67 5f|func_sect_debug_|
      0x000016f0|69 6e 66 6f 00 00 00 00  00 00 00 00 00 00 00 00|info............|
      0x00001700|66 75 6e 63 5f 73 65 63  74 5f 64 65 62 75 67 5f|func_sect_debug_|
      0x00001710|61 62 62 72 65 76 00 00  00 00 00 00 00 00 00 00|abbrev..........|
      0x00001720|66 75 6e 63 5f 73 65 63  74 5f 64 65 62 75 67 5f|func_sect_debug_|
      0x00001730|6c 69 6e 65 00 00 00 00  00 00 00 00 00 00 00 00|line............|
      0x00001740|66 75 6e 63 5f 73 65 63  74 5f 69 6e 74 65 72 70|func_sect_interp|
      0x00001750|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001760|66 75 6e 63 5f 73 65 63  74 5f 64 79 6e 73 79 6d|func_sect_dynsym|
      0x00001770|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001780|66 75 6e 63 5f 73 65 63  74 5f 64 79 6e 73 74 72|func_sect_dynstr|
      0x00001790|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000017a0|66 75 6e 63 5f 73 65 63  74 5f 72 65 6c 61 5f 64|func_sect_rela_d|
      0x000017b0|79 6e 00 00 00 00 00 00  00 00 00 00 00 00 00 00|yn..............|
      0x000017c0|66 75 6e 63 5f 73 65 63  74 5f 72 65 6c 61 5f 70|func_sect_rela_p|
      0x000017d0|6c 74 00 00 00 00 00 00  66 75 6e 63 5f 73 65 63|lt......func_sec|
      0x000017e0|74 5f 69 6e 69 74 00 00  66 75 6e 63 5f 73 65 63|t_init..func_sec|
      0x000017f0|74 5f 70 6c 74 00 00 00  00 00 00 00 00 00 00 00|t_plt...........|
      0x00001800|66 75 6e 63 5f 73 65 63  74 5f 70 6c 74 5f 67 6f|func_sect_plt_go|
      0x00001810|74 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|t...............|
      0x00001820|66 75 6e 63 5f 73 65 63  74 5f 70 6c 74 5f 73 65|func_sect_plt_se|
      0x00001830|63 00 00 00 00 00 00 00  66 75 6e 63 5f 73 65 63|c.......func_sec|
      0x00001840|74 5f 74 65 78 74 00 00  66 75 6e 63 5f 73 65 63|t_text..func_sec|
      0x00001850|74 5f 66 69 6e 69 00 00  00 00 00 00 00 00 00 00|t_fini..........|
      0x00001860|66 75 6e 63 5f 73 65 63  74 5f 72 6f 64 61 74 61|func_sect_rodata|
      0x00001870|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001880|66 75 6e 63 5f 73 65 63  74 5f 69 6e 69 74 5f 61|func_sect_init_a|
      0x00001890|72 72 61 79 00 00 00 00  00 00 00 00 00 00 00 00|rray............|
      0x000018a0|66 75 6e 63 5f 73 65 63  74 5f 66 69 6e 69 5f 61|func_sect_fini_a|
      0x000018b0|72 72 61 79 00 00 00 00  00 00 00 00 00 00 00 00|rray............|
      0x000018c0|66 75 6e 63 5f 73 65 63  74 5f 64 79 6e 61 6d 69|func_sect_dynami|
      0x000018d0|63 00 00 00 00 00 00 00  66 75 6e 63 5f 73 65 63|c.......func_sec|
      0x000018e0|74 5f 67 6f 74 00 00 00  00 00 00 00 00 00 00 00|t_got...........|
      0x000018f0|66 75 6e 63 5f 73 65 63  74 5f 67 6f 74 5f 70 6c|func_sect_got_pl|
      0x00001900|74 00 00 00 00 00 00 00  66 75 6e 63 5f 73 65 63|t.......func_sec|
      0x00001910|74 5f 64 61 74 61 00 00  66 75 6e 63 5f 73 65 63|t_data..func_sec|
      0x00001920|74 5f 62 73 73 00 00 00  00 00 00 00 00 00 00 00|t_bss...........|
      0x00001930|66 75 6e 63 5f 73 65 63  74 5f 63 6f 6d 6d 65 6e|func_sect_commen|
      0x00001940|74 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|t...............|
      0x00001950|66 75 6e 63 5f 73 65 63  74 5f 64 65 62 75 67 5f|func_sect_debug_|
      0x00001960|73 74 72 00 00 00 00 00  00 00 00 00 00 00 00 00|str.............|
      0x00001970|66 75 6e 63 5f 73 65 63  74 5f 73 79 6d 74 61 62|func_sect_symtab|
      0x00001980|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001990|66 75 6e 63 5f 73 65 63  74 5f 73 74 72 74 61 62|func_sect_strtab|
      0x000019a0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000019b0|66 75 6e 63 5f 73 65 63  74 5f 73 68 73 74 72 74|func_sect_shstrt|
      0x000019c0|61 62 00 00 00 00 00 00  66 75 6e 63 5f 70 72 6f|ab......func_pro|
      0x000019d0|63 65 73 73 00 00 00 00  00 00 00 00 00 00 00 00|cess............|
      0x000019e0|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
      0x000019f0|5f 62 6f 64 79 00 00 00  00 00 00 00 00 00 00 00|_body...........|
      0x00001a00|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
      0x00001a10|5f 62 6f 64 79 73 00 00  00 00 00 00 00 00 00 00|_bodys..........|
      0x00001a20|62 65 66 6f 72 65 5f 6d  61 69 6e 5f 66 75 6e 63|before_main_func|
      0x00001a30|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001a40|61 66 74 65 72 5f 6d 61  69 6e 5f 66 75 6e 63 00|after_main_func.|
      0x00001a50|6d 79 5f 69 6e 69 74 30  31 00 00 00 00 00 00 00|my_init01.......|
      0x00001a60|6d 79 5f 66 69 6e 69 30  31 00 00 00 00 00 00 00|my_fini01.......|
      0x00001a70|6d 79 5f 69 6e 69 74 30  32 00 00 00 00 00 00 00|my_init02.......|
      0x00001a80|6d 79 5f 66 69 6e 69 30  32 00 00 00 00 00 00 00|my_fini02.......|
      0x00001a90|6d 79 5f 69 6e 69 74 30  33 00 00 00 00 00 00 00|my_init03.......|
      0x00001aa0|6d 79 5f 66 69 6e 69 30  33 00 00 00 00 00 00 00|my_fini03.......|
      0x00001ab0|70 61 72 73 65 5f 61 72  67 73 00 ** ** ** ** **|parse_args.*****|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=19,sect_name=".eh_frame_hdr",pSectData=0x559e8950c34c,iLen=0x26c}
    >> func{func_sect_eh_frame_hdr:(00711)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=20,sect_name=".eh_frame",pSectData=0x559e8950c5b8,iLen=0x9a8}
    >> func{func_sect_eh_frame:(00712)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=21,sect_name=".init_array",pSectData=0x559e8950d590,iLen=0x28}
    >> func{func_sect_init_array:(01330)} is call .
        No.[21]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514eb0
        {
             Elf64_Word    sh_name      = 0xe5;
             Elf64_Word    sh_type      = 0xe;
             Elf64_Xword   sh_flags     = 0x3;
             Elf64_Addr    sh_addr      = 0x9d00;
             Elf64_Off     sh_offset    = 0x8d00;
             Elf64_Xword   sh_size      = 0x28;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x8;
        }

0x00559e8950d590|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|20 23 00 00 00 00 00 00  73 50 00 00 00 00 00 00| #......sP......|
      0x00000010|04 51 00 00 00 00 00 00  84 51 00 00 00 00 00 00|.Q.......Q......|
      0x00000020|04 52 00 00 00 00 00 00  ** ** ** ** ** ** ** **|.R......********|
      =============================================================================

  >>=============================================
      >> ptr[000] = 0x00000000002320;
      >> ptr[001] = 0x00000000005073;
      >> ptr[002] = 0x00000000005104;
      >> ptr[003] = 0x00000000005184;
      >> ptr[004] = 0x00000000005204;
  >>=============================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=22,sect_name=".fini_array",pSectData=0x559e8950d5b8,iLen=0x28}
    >> func{func_sect_fini_array:(01375)} is call .
        No.[22]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514ef0
        {
             Elf64_Word    sh_name      = 0xf1;
             Elf64_Word    sh_type      = 0xf;
             Elf64_Xword   sh_flags     = 0x3;
             Elf64_Addr    sh_addr      = 0x9d28;
             Elf64_Off     sh_offset    = 0x8d28;
             Elf64_Xword   sh_size      = 0x28;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x8;
        }

0x00559e8950d5b8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|e0 22 00 00 00 00 00 00  c4 50 00 00 00 00 00 00|.".......P......|
      0x00000010|44 51 00 00 00 00 00 00  c4 51 00 00 00 00 00 00|DQ.......Q......|
      0x00000020|44 52 00 00 00 00 00 00  ** ** ** ** ** ** ** **|DR......********|
      =============================================================================

  >>=============================================
      >> ptr[000] = 0x000000000022e0;
      >> ptr[001] = 0x000000000050c4;
      >> ptr[002] = 0x00000000005144;
      >> ptr[003] = 0x000000000051c4;
      >> ptr[004] = 0x00000000005244;
  >>=============================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=23,sect_name=".dynamic",pSectData=0x559e8950d5e0,iLen=0x1f0}
    >> func{func_sect_dynamic:(01421)} is call .
        No.[23]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514f30
        {
             Elf64_Word    sh_name      = 0xfd;
             Elf64_Word    sh_type      = 0x6;
             Elf64_Xword   sh_flags     = 0x3;
             Elf64_Addr    sh_addr      = 0x9d50;
             Elf64_Off     sh_offset    = 0x8d50;
             Elf64_Xword   sh_size      = 0x1f0;
             Elf64_Word    sh_link      = 0x7;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x10;
        }

0x00559e8950d5e0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|01 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00|................|
      0x00000010|0c 00 00 00 00 00 00 00  00 20 00 00 00 00 00 00|......... ......|
      0x00000020|0d 00 00 00 00 00 00 00  64 55 00 00 00 00 00 00|........dU......|
      0x00000030|19 00 00 00 00 00 00 00  00 9d 00 00 00 00 00 00|................|
      0x00000040|1b 00 00 00 00 00 00 00  28 00 00 00 00 00 00 00|........(.......|
      0x00000050|1a 00 00 00 00 00 00 00  28 9d 00 00 00 00 00 00|........(.......|
      0x00000060|1c 00 00 00 00 00 00 00  28 00 00 00 00 00 00 00|........(.......|
      0x00000070|f5 fe ff 6f 00 00 00 00  a0 03 00 00 00 00 00 00|...o............|
      0x00000080|05 00 00 00 00 00 00 00  f0 05 00 00 00 00 00 00|................|
      0x00000090|06 00 00 00 00 00 00 00  c8 03 00 00 00 00 00 00|................|
      0x000000a0|0a 00 00 00 00 00 00 00  16 01 00 00 00 00 00 00|................|
      0x000000b0|0b 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00|................|
      0x000000c0|15 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000d0|03 00 00 00 00 00 00 00  40 9f 00 00 00 00 00 00|........@.......|
      0x000000e0|02 00 00 00 00 00 00 00  80 01 00 00 00 00 00 00|................|
      0x000000f0|14 00 00 00 00 00 00 00  07 00 00 00 00 00 00 00|................|
      0x00000100|17 00 00 00 00 00 00 00  d0 0f 00 00 00 00 00 00|................|
      0x00000110|07 00 00 00 00 00 00 00  78 07 00 00 00 00 00 00|........x.......|
      0x00000120|08 00 00 00 00 00 00 00  58 08 00 00 00 00 00 00|........X.......|
      0x00000130|09 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00|................|
      0x00000140|1e 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000150|fb ff ff 6f 00 00 00 00  01 00 00 08 00 00 00 00|...o............|
      0x00000160|fe ff ff 6f 00 00 00 00  38 07 00 00 00 00 00 00|...o....8.......|
      0x00000170|ff ff ff 6f 00 00 00 00  01 00 00 00 00 00 00 00|...o............|
      0x00000180|f0 ff ff 6f 00 00 00 00  06 07 00 00 00 00 00 00|...o............|
      0x00000190|f9 ff ff 6f 00 00 00 00  53 00 00 00 00 00 00 00|...o....S.......|
      0x000001a0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000001b0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000001c0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000001d0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000001e0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=24,sect_name=".got",pSectData=0x559e8950d7d0,iLen=0xc0}
    >> func{func_sect_got:(01432)} is call .
        No.[24]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514f70
        {
             Elf64_Word    sh_name      = 0xab;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x3;
             Elf64_Addr    sh_addr      = 0x9f40;
             Elf64_Off     sh_offset    = 0x8f40;
             Elf64_Xword   sh_size      = 0xc0;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x8;
        }

0x00559e8950d7d0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|50 9d 00 00 00 00 00 00  00 00 00 00 00 00 00 00|P...............|
      0x00000010|00 00 00 00 00 00 00 00  30 20 00 00 00 00 00 00|........0 ......|
      0x00000020|40 20 00 00 00 00 00 00  50 20 00 00 00 00 00 00|@ ......P ......|
      0x00000030|60 20 00 00 00 00 00 00  70 20 00 00 00 00 00 00|` ......p ......|
      0x00000040|80 20 00 00 00 00 00 00  90 20 00 00 00 00 00 00|. ....... ......|
      0x00000050|a0 20 00 00 00 00 00 00  b0 20 00 00 00 00 00 00|. ....... ......|
      0x00000060|c0 20 00 00 00 00 00 00  d0 20 00 00 00 00 00 00|. ....... ......|
      0x00000070|e0 20 00 00 00 00 00 00  f0 20 00 00 00 00 00 00|. ....... ......|
      0x00000080|00 21 00 00 00 00 00 00  10 21 00 00 00 00 00 00|.!.......!......|
      0x00000090|20 21 00 00 00 00 00 00  00 00 00 00 00 00 00 00| !..............|
      0x000000a0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000b0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=25,sect_name=".data",pSectData=0x559e8950d890,iLen=0x280}
    >> func{func_sect_data:(01486)} is call .
        No.[25]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514fb0
        {
             Elf64_Word    sh_name      = 0x106;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x3;
             Elf64_Addr    sh_addr      = 0xa000;
             Elf64_Off     sh_offset    = 0x9000;
             Elf64_Xword   sh_size      = 0x280;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x20;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e8950d890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 00 00 00 00 00 00 00  08 a0 00 00 00 00 00 00|................|
      0x00000010|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000020|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000030|ca 6b 00 00 00 00 00 00  76 39 00 00 00 00 00 00|.k......v9......|
      0x00000040|d2 6b 00 00 00 00 00 00  1c 36 00 00 00 00 00 00|.k.......6......|
      0x00000050|e2 6b 00 00 00 00 00 00  a0 36 00 00 00 00 00 00|.k.......6......|
      0x00000060|f0 6b 00 00 00 00 00 00  e2 36 00 00 00 00 00 00|.k.......6......|
      0x00000070|03 6c 00 00 00 00 00 00  24 37 00 00 00 00 00 00|.l......$7......|
      0x00000080|0d 6c 00 00 00 00 00 00  78 3a 00 00 00 00 00 00|.l......x:......|
      0x00000090|15 6c 00 00 00 00 00 00  34 3d 00 00 00 00 00 00|.l......4=......|
      0x000000a0|1d 6c 00 00 00 00 00 00  66 37 00 00 00 00 00 00|.l......f7......|
      0x000000b0|2a 6c 00 00 00 00 00 00  a8 37 00 00 00 00 00 00|*l.......7......|
      0x000000c0|39 6c 00 00 00 00 00 00  b2 3d 00 00 00 00 00 00|9l.......=......|
      0x000000d0|43 6c 00 00 00 00 00 00  33 3f 00 00 00 00 00 00|Cl......3?......|
      0x000000e0|4d 6c 00 00 00 00 00 00  c5 40 00 00 00 00 00 00|Ml.......@......|
      0x000000f0|53 6c 00 00 00 00 00 00  2d 41 00 00 00 00 00 00|Sl......-A......|
      0x00000100|58 6c 00 00 00 00 00 00  95 41 00 00 00 00 00 00|Xl.......A......|
      0x00000110|61 6c 00 00 00 00 00 00  fd 41 00 00 00 00 00 00|al.......A......|
      0x00000120|6a 6c 00 00 00 00 00 00  65 42 00 00 00 00 00 00|jl......eB......|
      0x00000130|70 6c 00 00 00 00 00 00  c9 42 00 00 00 00 00 00|pl.......B......|
      0x00000140|76 6c 00 00 00 00 00 00  31 43 00 00 00 00 00 00|vl......1C......|
      0x00000150|7e 6c 00 00 00 00 00 00  ea 37 00 00 00 00 00 00|~l.......7......|
      0x00000160|8c 6c 00 00 00 00 00 00  2c 38 00 00 00 00 00 00|.l......,8......|
      0x00000170|96 6c 00 00 00 00 00 00  2a 44 00 00 00 00 00 00|.l......*D......|
      0x00000180|a2 6c 00 00 00 00 00 00  b7 44 00 00 00 00 00 00|.l.......D......|
      0x00000190|ae 6c 00 00 00 00 00 00  44 45 00 00 00 00 00 00|.l......DE......|
      0x000001a0|b7 6c 00 00 00 00 00 00  ac 45 00 00 00 00 00 00|.l.......E......|
      0x000001b0|bc 6c 00 00 00 00 00 00  14 46 00 00 00 00 00 00|.l.......F......|
      0x000001c0|c5 6c 00 00 00 00 00 00  7c 46 00 00 00 00 00 00|.l......|F......|
      0x000001d0|cb 6c 00 00 00 00 00 00  e4 46 00 00 00 00 00 00|.l.......F......|
      0x000001e0|d0 6c 00 00 00 00 00 00  4c 47 00 00 00 00 00 00|.l......LG......|
      0x000001f0|d9 6c 00 00 00 00 00 00  6e 38 00 00 00 00 00 00|.l......n8......|
      0x00000200|e8 6c 00 00 00 00 00 00  b0 38 00 00 00 00 00 00|.l.......8......|
      0x00000210|f4 6c 00 00 00 00 00 00  f2 38 00 00 00 00 00 00|.l.......8......|
      0x00000220|02 6d 00 00 00 00 00 00  34 39 00 00 00 00 00 00|.m......49......|
      0x00000230|0e 6d 00 00 00 00 00 00  b4 47 00 00 00 00 00 00|.m.......G......|
      0x00000240|19 6d 00 00 00 00 00 00  32 48 00 00 00 00 00 00|.m......2H......|
      0x00000250|21 6d 00 00 00 00 00 00  f1 49 00 00 00 00 00 00|!m.......I......|
      0x00000260|29 6d 00 00 00 00 00 00  6f 4a 00 00 00 00 00 00|)m......oJ......|
      0x00000270|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=26,sect_name=".bss",pSectData=0x559e8950db10,iLen=0x10}
    >> func{func_sect_bss:(01558)} is call .
        No.[26]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89514ff0
        {
             Elf64_Word    sh_name      = 0x10c;
             Elf64_Word    sh_type      = 0x8;
             Elf64_Xword   sh_flags     = 0x3;
             Elf64_Addr    sh_addr      = 0xa280;
             Elf64_Off     sh_offset    = 0x9280;
             Elf64_Xword   sh_size      = 0x10;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e8950db10|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|47 43 43 3a 20 28 55 62  75 6e 74 75 20 39 2e 34|GCC: (Ubuntu 9.4|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=27,sect_name=".comment",pSectData=0x559e8950db10,iLen=0x2b}
    >> func{func_sect_comment:(01593)} is call .
        No.[27]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89515030
        {
             Elf64_Word    sh_name      = 0x111;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x30;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0x9280;
             Elf64_Xword   sh_size      = 0x2b;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x1;
        }

0x00559e8950db10|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|47 43 43 3a 20 28 55 62  75 6e 74 75 20 39 2e 34|GCC: (Ubuntu 9.4|
      0x00000010|2e 30 2d 31 75 62 75 6e  74 75 31 7e 32 30 2e 30|.0-1ubuntu1~20.0|
      0x00000020|34 2e 31 29 20 39 2e 34  2e 30 00 ** ** ** ** **|4.1) 9.4.0.*****|
      =============================================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=28,sect_name=".debug_aranges",pSectData=0x559e8950db3b,iLen=0x30}
    >> func{func_sect_debug_aranges:(00721)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=29,sect_name=".debug_info",pSectData=0x559e8950db6b,iLen=0x2ddd}
    >> func{func_sect_debug_info:(00722)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=30,sect_name=".debug_abbrev",pSectData=0x559e89510948,iLen=0x2b4}
    >> func{func_sect_debug_abbrev:(00723)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=31,sect_name=".debug_line",pSectData=0x559e89510bfc,iLen=0xf48}
    >> func{func_sect_debug_line:(00724)} is call .

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=32,sect_name=".debug_str",pSectData=0x559e89511b44,iLen=0xdac}
    >> func{func_sect_debug_str:(01634)} is call .
        No.[32]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89515170
        {
             Elf64_Word    sh_name      = 0x14f;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x30;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xd2b4;
             Elf64_Xword   sh_size      = 0xdac;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x1;
        }

0x00559e89511b44|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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
      0x00000320|5f 61 72 65 61 00 70 53  65 63 52 65 6c 61 70 6c|_area.pSecRelapl|
      0x00000330|74 42 6f 64 79 00 6c 6f  6e 67 20 6c 6f 6e 67 20|tBody.long long |
      0x00000340|75 6e 73 69 67 6e 65 64  20 69 6e 74 00 73 74 5f|unsigned int.st_|
      0x00000350|62 6c 6f 63 6b 73 00 66  75 6e 63 5f 73 65 63 74|blocks.func_sect|
      0x00000360|5f 6e 6f 74 65 5f 41 42  49 5f 74 61 67 00 78 6c|_note_ABI_tag.xl|
      0x00000370|6f 67 5f 63 6f 72 65 00  70 5f 66 69 6c 65 73 7a|og_core.p_filesz|
      0x00000380|00 73 74 5f 6d 74 69 6d  65 00 66 75 6e 63 5f 73|.st_mtime.func_s|
      0x00000390|65 63 74 5f 69 6e 69 74  5f 61 72 72 61 79 00 44|ect_init_array.D|
      0x000003a0|75 6d 70 50 74 72 32 53  74 72 00 5f 49 4f 5f 62|umpPtr2Str._IO_b|
      0x000003b0|61 63 6b 75 70 5f 62 61  73 65 00 50 72 6f 67 48|ackup_base.ProgH|
      0x000003c0|65 61 64 65 72 4f 62 6a  73 00 73 5f 65 6c 66 36|eaderObjs.s_elf6|
      0x000003d0|34 5f 6f 62 6a 5f 74 00  70 53 79 6d 54 61 62 44|4_obj_t.pSymTabD|
      0x000003e0|61 74 61 00 78 6c 6f 67  5f 70 74 72 64 75 6d 70|ata.xlog_ptrdump|
      0x000003f0|00 70 50 72 6f 67 48 65  61 64 65 72 44 61 74 61|.pProgHeaderData|
      0x00000400|00 5f 49 53 6c 6f 77 65  72 00 5f 66 69 6c 65 6e|._ISlower._filen|
      0x00000410|6f 00 73 74 61 74 00 70  70 50 72 6f 67 48 65 61|o.stat.ppProgHea|
      0x00000420|64 65 72 73 00 45 6c 66  48 65 61 64 65 72 4f 62|ders.ElfHeaderOb|
      0x00000430|6a 00 66 75 6e 63 5f 73  65 63 74 5f 6e 6f 74 65|j.func_sect_note|
      0x00000440|5f 67 6e 75 5f 62 75 69  6c 64 00 5f 5f 67 6e 75|_gnu_build.__gnu|
      0x00000450|63 5f 76 61 5f 6c 69 73  74 00 66 75 6e 63 5f 73|c_va_list.func_s|
      0x00000460|65 63 74 5f 67 6e 75 5f  68 61 73 68 00 65 78 69|ect_gnu_hash.exi|
      0x00000470|74 00 5f 5f 6d 6f 64 65  5f 74 00 70 44 61 74 61|t.__mode_t.pData|
      0x00000480|00 70 61 72 73 65 5f 65  6c 66 36 34 5f 73 65 63|.parse_elf64_sec|
      0x00000490|74 5f 68 65 61 64 65 72  73 00 5f 49 53 78 64 69|t_headers._ISxdi|
      0x000004a0|67 69 74 00 5f 49 4f 5f  72 65 61 64 5f 62 61 73|git._IO_read_bas|
      0x000004b0|65 00 70 61 72 73 65 5f  65 6c 66 36 34 5f 73 65|e.parse_elf64_se|
      0x000004c0|63 74 5f 68 65 61 64 65  72 00 66 75 6e 63 5f 73|ct_header.func_s|
      0x000004d0|65 63 74 5f 6e 6f 74 65  5f 67 6e 75 5f 70 72 6f|ect_note_gnu_pro|
      0x000004e0|70 65 00 73 74 5f 67 69  64 00 61 72 67 63 00 73|pe.st_gid.argc.s|
      0x000004f0|74 64 69 6e 00 47 4e 55  20 43 31 31 20 39 2e 34|tdin.GNU C11 9.4|
      0x00000500|2e 30 20 2d 6d 74 75 6e  65 3d 67 65 6e 65 72 69|.0 -mtune=generi|
      0x00000510|63 20 2d 6d 61 72 63 68  3d 78 38 36 2d 36 34 20|c -march=x86-64 |
      0x00000520|2d 67 20 2d 4f 30 20 2d  73 74 64 3d 63 31 31 20|-g -O0 -std=c11 |
      0x00000530|2d 66 61 73 79 6e 63 68  72 6f 6e 6f 75 73 2d 75|-fasynchronous-u|
      0x00000540|6e 77 69 6e 64 2d 74 61  62 6c 65 73 20 2d 66 73|nwind-tables -fs|
      0x00000550|74 61 63 6b 2d 70 72 6f  74 65 63 74 6f 72 2d 73|tack-protector-s|
      0x00000560|74 72 6f 6e 67 20 2d 66  73 74 61 63 6b 2d 63 6c|trong -fstack-cl|
      0x00000570|61 73 68 2d 70 72 6f 74  65 63 74 69 6f 6e 20 2d|ash-protection -|
      0x00000580|66 63 66 2d 70 72 6f 74  65 63 74 69 6f 6e 00 73|fcf-protection.s|
      0x00000590|74 5f 6d 6f 64 65 00 45  6c 66 36 34 5f 48 61 6c|t_mode.Elf64_Hal|
      0x000005a0|66 00 73 74 5f 6e 6c 69  6e 6b 00 73 68 5f 65 6e|f.st_nlink.sh_en|
      0x000005b0|74 73 69 7a 65 00 6d 79  72 65 61 64 65 6c 66 2d|tsize.myreadelf-|
      0x000005c0|30 2e 31 2e 30 38 2e 63  00 66 75 6e 63 5f 73 65|0.1.08.c.func_se|
      0x000005d0|63 74 5f 70 6c 74 5f 73  65 63 00 72 5f 69 6e 66|ct_plt_sec.r_inf|
      0x000005e0|6f 00 53 65 63 74 48 65  61 64 65 72 4f 62 6a 73|o.SectHeaderObjs|
      0x000005f0|00 70 44 79 6e 53 74 72  44 61 74 61 00 66 75 6e|.pDynStrData.fun|
      0x00000600|63 5f 73 65 63 74 5f 62  73 73 00 66 69 6c 65 6e|c_sect_bss.filen|
      0x00000610|61 6d 65 00 65 5f 66 6c  61 67 73 00 5f 49 4f 5f|ame.e_flags._IO_|
      0x00000620|6d 61 72 6b 65 72 00 5f  49 4f 5f 72 65 61 64 5f|marker._IO_read_|
      0x00000630|70 74 72 00 70 5f 61 6c  69 67 6e 00 66 75 6e 63|ptr.p_align.func|
      0x00000640|5f 73 65 63 74 5f 72 65  6c 61 5f 70 6c 74 00 73|_sect_rela_plt.s|
      0x00000650|74 5f 61 74 69 6d 65 00  73 68 5f 69 6e 66 6f 00|t_atime.sh_info.|
      0x00000660|65 5f 73 68 73 74 72 6e  64 78 00 5f 5f 50 52 45|e_shstrndx.__PRE|
      0x00000670|54 54 59 5f 46 55 4e 43  54 49 4f 4e 5f 5f 00 66|TTY_FUNCTION__.f|
      0x00000680|75 6e 63 5f 73 65 63 74  5f 72 6f 64 61 74 61 00|unc_sect_rodata.|
      0x00000690|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
      0x000006a0|5f 62 6f 64 79 73 00 75  69 6e 74 38 5f 74 00 66|_bodys.uint8_t.f|
      0x000006b0|75 6e 63 5f 73 65 63 74  5f 69 6e 69 74 00 73 74|unc_sect_init.st|
      0x000006c0|5f 69 6e 6f 00 53 5f 45  6c 66 36 34 5f 52 65 6c|_ino.S_Elf64_Rel|
      0x000006d0|61 5f 74 00 66 75 6e 63  5f 73 65 63 74 5f 64 79|a_t.func_sect_dy|
      0x000006e0|6e 73 74 72 00 70 45 6c  66 48 65 61 64 65 72 00|nstr.pElfHeader.|
      0x000006f0|45 6c 66 36 34 5f 58 77  6f 72 64 00 5f 49 4f 5f|Elf64_Xword._IO_|
      0x00000700|77 72 69 74 65 5f 62 61  73 65 00 70 53 65 63 74|write_base.pSect|
      0x00000710|4e 61 6d 65 73 00 6c 6f  6e 67 20 6c 6f 6e 67 20|Names.long long |
      0x00000720|69 6e 74 00 66 75 6e 63  5f 73 65 63 74 5f 70 6c|int.func_sect_pl|
      0x00000730|74 5f 67 6f 74 00 73 74  5f 6d 74 69 6d 65 6e 73|t_got.st_mtimens|
      0x00000740|65 63 00 45 6c 66 36 34  5f 4f 66 66 00 5f 49 4f|ec.Elf64_Off._IO|
      0x00000750|5f 73 61 76 65 5f 62 61  73 65 00 5f 5f 64 65 76|_save_base.__dev|
      0x00000760|5f 74 00 66 75 6e 63 5f  73 65 63 74 5f 70 6c 74|_t.func_sect_plt|
      0x00000770|00 5f 49 53 63 6e 74 72  6c 00 70 53 65 63 74 48|._IScntrl.pSectH|
      0x00000780|65 61 64 65 72 44 61 74  61 00 2f 68 6f 6d 65 2f|eaderData./home/|
      0x00000790|78 61 64 6d 69 6e 2f 78  77 6b 73 2e 67 69 74 2e|xadmin/xwks.git.|
      0x000007a0|31 2f 6d 79 72 65 61 64  65 6c 66 2d 63 31 31 00|1/myreadelf-c11.|
      0x000007b0|70 53 65 63 74 48 65 61  64 65 72 00 70 5f 66 6c|pSectHeader.p_fl|
      0x000007c0|61 67 73 00 66 75 6e 63  5f 73 65 63 74 5f 67 6e|ags.func_sect_gn|
      0x000007d0|75 5f 76 65 72 73 69 6f  6e 5f 72 00 70 53 65 63|u_version_r.pSec|
      0x000007e0|74 44 61 74 61 00 5f 5f  73 79 73 63 61 6c 6c 5f|tData.__syscall_|
      0x000007f0|73 6c 6f 6e 67 5f 74 00  5f 49 53 64 69 67 69 74|slong_t._ISdigit|
      0x00000800|00 70 70 56 6f 69 64 50  74 72 00 78 6c 6f 67 5f|.ppVoidPtr.xlog_|
      0x00000810|69 6e 66 6f 5f 78 00 70  61 72 73 65 5f 65 6c 66|info_x.parse_elf|
      0x00000820|36 34 5f 65 6c 66 5f 68  65 61 64 65 72 00 5f 49|64_elf_header._I|
      0x00000830|53 73 70 61 63 65 00 5f  66 72 65 65 72 65 73 5f|Sspace._freeres_|
      0x00000840|62 75 66 00 78 6c 6f 67  5f 75 6e 69 6e 69 74 00|buf.xlog_uninit.|
      0x00000850|70 5f 74 79 70 65 00 66  75 6e 63 5f 73 65 63 74|p_type.func_sect|
      0x00000860|5f 65 68 5f 66 72 61 6d  65 5f 68 64 72 00 73 74|_eh_frame_hdr.st|
      0x00000870|61 74 62 75 66 00 5f 5f  70 61 64 30 00 5f 5f 70|atbuf.__pad0.__p|
      0x00000880|61 64 35 00 73 68 5f 6f  66 66 73 65 74 00 5f 5f|ad5.sh_offset.__|
      0x00000890|67 6c 69 62 63 5f 72 65  73 65 72 76 65 64 00 66|glibc_reserved.f|
      0x000008a0|75 6e 63 5f 73 65 63 74  5f 73 74 72 74 61 62 00|unc_sect_strtab.|
      0x000008b0|70 5f 76 61 64 64 72 00  62 65 66 6f 72 65 5f 6d|p_vaddr.before_m|
      0x000008c0|61 69 6e 5f 66 75 6e 63  00 70 5f 6d 65 6d 73 7a|ain_func.p_memsz|
      0x000008d0|00 5f 76 74 61 62 6c 65  5f 6f 66 66 73 65 74 00|._vtable_offset.|
      0x000008e0|66 75 6e 63 5f 73 65 63  74 5f 64 65 62 75 67 5f|func_sect_debug_|
      0x000008f0|69 6e 66 6f 00 61 72 67  76 00 73 68 5f 6e 61 6d|info.argv.sh_nam|
      0x00000900|65 00 5f 5f 67 69 64 5f  74 00 73 74 5f 63 74 69|e.__gid_t.st_cti|
      0x00000910|6d 65 6e 73 65 63 00 78  6c 6f 67 5f 68 65 78 64|mensec.xlog_hexd|
      0x00000920|75 6d 70 00 70 50 72 6f  67 48 65 61 64 65 72 00|ump.pProgHeader.|
      0x00000930|70 4e 61 6d 65 00 66 75  6e 63 5f 73 65 63 74 5f|pName.func_sect_|
      0x00000940|72 65 6c 61 5f 64 79 6e  00 72 5f 6f 66 66 73 65|rela_dyn.r_offse|
      0x00000950|74 00 73 74 5f 6f 74 68  65 72 00 65 5f 73 68 6e|t.st_other.e_shn|
      0x00000960|75 6d 00 6d 79 5f 66 69  6e 69 30 33 00 73 74 5f|um.my_fini03.st_|
      0x00000970|73 68 6e 64 78 00 5f 49  53 70 75 6e 63 74 00 5f|shndx._ISpunct._|
      0x00000980|5f 73 79 73 63 61 6c 6c  5f 75 6c 6f 6e 67 5f 74|_syscall_ulong_t|
      0x00000990|00 5f 49 4f 5f 72 65 61  64 5f 65 6e 64 00 6c 6f|._IO_read_end.lo|
      0x000009a0|67 5f 73 77 69 74 63 68  00 53 5f 45 6c 66 36 34|g_switch.S_Elf64|
      0x000009b0|5f 53 79 6d 45 6e 74 5f  74 00 5f 49 53 70 72 69|_SymEnt_t._ISpri|
      0x000009c0|6e 74 00 73 68 6f 72 74  20 69 6e 74 00 65 5f 70|nt.short int.e_p|
      0x000009d0|68 65 6e 74 73 69 7a 65  00 70 5f 70 61 64 64 72|hentsize.p_paddr|
      0x000009e0|00 70 70 52 65 6c 61 45  6e 74 00 78 6c 6f 67 5f|.ppRelaEnt.xlog_|
      0x000009f0|69 6e 69 74 00 65 5f 70  68 6e 75 6d 00 66 75 6e|init.e_phnum.fun|
      0x00000a00|63 5f 73 65 63 74 5f 67  6f 74 5f 70 6c 74 00 73|c_sect_got_plt.s|
      0x00000a10|68 5f 73 69 7a 65 00 5f  49 4f 5f 77 69 64 65 5f|h_size._IO_wide_|
      0x00000a20|64 61 74 61 00 6d 79 5f  66 69 6e 69 30 31 00 6d|data.my_fini01.m|
      0x00000a30|79 5f 66 69 6e 69 30 32  00 70 73 74 72 5f 6e 61|y_fini02.pstr_na|
      0x00000a40|6d 65 00 5f 5f 76 61 5f  6c 69 73 74 5f 74 61 67|me.__va_list_tag|
      0x00000a50|00 5f 5f 62 6c 6b 73 69  7a 65 5f 74 00 73 68 5f|.__blksize_t.sh_|
      0x00000a60|61 64 64 72 00 69 5f 6c  65 6e 00 66 75 6e 63 5f|addr.i_len.func_|
      0x00000a70|73 65 63 74 5f 63 6f 6d  6d 65 6e 74 00 66 70 5f|sect_comment.fp_|
      0x00000a80|6f 66 66 73 65 74 00 73  74 5f 63 74 69 6d 65 00|offset.st_ctime.|
      0x00000a90|69 50 74 72 4d 61 78 43  6e 74 00 5f 49 53 67 72|iPtrMaxCnt._ISgr|
      0x00000aa0|61 70 68 00 69 50 74 72  43 6e 74 00 70 53 48 4e|aph.iPtrCnt.pSHN|
      0x00000ab0|61 6d 65 00 69 5f 72 6f  77 00 78 6c 6f 67 5f 69|ame.i_row.xlog_i|
      0x00000ac0|6e 66 6f 00 5f 6f 6c 64  5f 6f 66 66 73 65 74 00|nfo._old_offset.|
      0x00000ad0|5f 49 4f 5f 46 49 4c 45  00 70 66 75 6e 63 5f 70|_IO_FILE.pfunc_p|
      0x00000ae0|72 6f 63 65 73 73 00 72  65 67 5f 73 61 76 65 5f|rocess.reg_save_|
      0x00000af0|61 72 65 61 00 73 68 5f  74 79 70 65 00 5f 49 53|area.sh_type._IS|
      0x00000b00|61 6c 70 68 61 00 66 75  6e 63 5f 73 65 63 74 5f|alpha.func_sect_|
      0x00000b10|65 68 5f 66 72 61 6d 65  00 69 5f 65 6c 66 36 34|eh_frame.i_elf64|
      0x00000b20|5f 6c 65 6e 00 72 5f 61  64 64 65 6e 64 00 65 5f|_len.r_addend.e_|
      0x00000b30|69 64 65 6e 74 00 66 75  6e 63 5f 73 65 63 74 5f|ident.func_sect_|
      0x00000b40|64 65 62 75 67 5f 61 72  61 6e 67 65 73 00 73 69|debug_aranges.si|
      0x00000b50|7a 65 5f 72 65 61 64 6f  6b 00 66 75 6e 63 5f 73|ze_readok.func_s|
      0x00000b60|65 63 74 5f 66 69 6e 69  5f 61 72 72 61 79 00 75|ect_fini_array.u|
      0x00000b70|6e 73 69 67 6e 65 64 20  63 68 61 72 00 73 65 63|nsigned char.sec|
      0x00000b80|74 5f 66 75 6e 63 73 00  70 53 65 63 74 4e 61 6d|t_funcs.pSectNam|
      0x00000b90|65 00 5f 49 4f 5f 77 72  69 74 65 5f 70 74 72 00|e._IO_write_ptr.|
      0x00000ba0|66 75 6e 63 5f 73 65 63  74 5f 73 68 73 74 72 74|func_sect_shstrt|
      0x00000bb0|61 62 00 70 45 6c 66 44  61 74 61 00 50 72 74 53|ab.pElfData.PrtS|
      0x00000bc0|65 63 74 48 65 61 64 65  72 00 65 5f 74 79 70 65|ectHeader.e_type|
      0x00000bd0|00 70 53 65 63 74 5f 53  68 53 74 72 54 61 62 5f|.pSect_ShStrTab_|
      0x00000be0|48 65 61 64 65 72 00 78  6c 6f 67 5f 6d 75 74 65|Header.xlog_mute|
      0x00000bf0|78 5f 75 6e 6c 6f 63 6b  00 73 68 5f 66 6c 61 67|x_unlock.sh_flag|
      0x00000c00|73 00 5f 5f 74 69 6d 65  5f 74 00 65 5f 6d 61 63|s.__time_t.e_mac|
      0x00000c10|68 69 6e 65 00 5f 49 53  61 6c 6e 75 6d 00 73 74|hine._ISalnum.st|
      0x00000c20|5f 76 61 6c 75 65 00 5f  5f 75 69 64 5f 74 00 73|_value.__uid_t.s|
      0x00000c30|74 5f 73 69 7a 65 00 66  75 6e 63 5f 73 65 63 74|t_size.func_sect|
      0x00000c40|5f 64 65 62 75 67 5f 6c  69 6e 65 00 73 74 5f 75|_debug_line.st_u|
      0x00000c50|69 64 00 5f 5f 6f 66 66  5f 74 00 5f 49 53 62 6c|id.__off_t._ISbl|
      0x00000c60|61 6e 6b 00 73 74 5f 64  65 76 00 70 53 65 63 74|ank.st_dev.pSect|
      0x00000c70|48 65 61 64 65 72 73 44  61 74 61 00 73 68 6f 72|HeadersData.shor|
      0x00000c80|74 20 75 6e 73 69 67 6e  65 64 20 69 6e 74 00 78|t unsigned int.x|
      0x00000c90|6c 6f 67 5f 6d 75 74 65  78 5f 6c 6f 63 6b 00 6d|log_mutex_lock.m|
      0x00000ca0|61 69 6e 00 68 46 69 6c  65 00 5f 5f 62 75 69 6c|ain.hFile.__buil|
      0x00000cb0|74 69 6e 5f 76 61 5f 6c  69 73 74 00 53 5f 45 4c|tin_va_list.S_EL|
      0x00000cc0|46 36 34 5f 50 72 6f 67  48 65 61 64 65 72 5f 74|F64_ProgHeader_t|
      0x00000cd0|00 66 75 6e 63 5f 73 65  63 74 5f 64 79 6e 61 6d|.func_sect_dynam|
      0x00000ce0|69 63 00 5f 5f 66 75 6e  63 5f 5f 00 70 70 53 65|ic.__func__.ppSe|
      0x00000cf0|63 74 48 65 61 64 65 72  73 00 45 6c 66 36 34 5f|ctHeaders.Elf64_|
      0x00000d00|53 78 77 6f 72 64 00 5f  5f 62 6c 6b 63 6e 74 5f|Sxword.__blkcnt_|
      0x00000d10|74 00 69 4c 65 6e 00 5f  63 68 61 69 6e 00 5f 49|t.iLen._chain._I|
      0x00000d20|53 75 70 70 65 72 00 73  74 5f 72 64 65 76 00 73|Supper.st_rdev.s|
      0x00000d30|68 5f 61 64 64 72 61 6c  69 67 6e 00 45 6c 66 36|h_addralign.Elf6|
      0x00000d40|34 5f 57 6f 72 64 00 5f  66 6c 61 67 73 32 00 73|4_Word._flags2.s|
      0x00000d50|74 5f 6e 61 6d 65 00 70  53 65 63 52 65 6c 61 64|t_name.pSecRelad|
      0x00000d60|79 6e 42 6f 64 79 00 50  72 74 50 72 6f 67 48 65|ynBody.PrtProgHe|
      0x00000d70|61 64 65 72 00 5f 63 75  72 5f 63 6f 6c 75 6d 6e|ader._cur_column|
      0x00000d80|00 70 44 61 74 61 53 74  61 72 74 00 5f 5f 6f 66|.pDataStart.__of|
      0x00000d90|66 36 34 5f 74 00 5f 75  6e 75 73 65 64 32 00 5f|f64_t._unused2._|
      0x00000da0|49 4f 5f 62 75 66 5f 62  61 73 65 00 ** ** ** **|IO_buf_base.****|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x00559e89511b44; str={"Elf64_Addr"};
      >> ptr[001]=0x00559e89511b4f; str={"parse_elf64_prog_header"};
      >> ptr[002]=0x00559e89511b67; str={"func_sect_note_gnu_build_id"};
      >> ptr[003]=0x00559e89511b83; str={"get_elf64_data"};
      >> ptr[004]=0x00559e89511b92; str={"test_char"};
      >> ptr[005]=0x00559e89511b9c; str={"_shortbuf"};
      >> ptr[006]=0x00559e89511ba6; str={"sh_link"};
      >> ptr[007]=0x00559e89511bae; str={"_IO_lock_t"};
      >> ptr[008]=0x00559e89511bb9; str={"gp_offset"};
      >> ptr[009]=0x00559e89511bc3; str={"parse_elf64_sect_body"};
      >> ptr[010]=0x00559e89511bd9; str={"stderr"};
      >> ptr[011]=0x00559e89511be0; str={"_IO_buf_end"};
      >> ptr[012]=0x00559e89511bec; str={"iCnt"};
      >> ptr[013]=0x00559e89511bf1; str={"st_atimensec"};
      >> ptr[014]=0x00559e89511bfe; str={"e_shoff"};
      >> ptr[015]=0x00559e89511c06; str={"pDynsymData"};
      >> ptr[016]=0x00559e89511c12; str={"after_main_func"};
      >> ptr[017]=0x00559e89511c22; str={"func_sect_fini"};
      >> ptr[018]=0x00559e89511c31; str={"S_ELF64_SectHeader_t"};
      >> ptr[019]=0x00559e89511c46; str={"_IO_write_end"};
      >> ptr[020]=0x00559e89511c54; str={"func_sect_dynsym"};
      >> ptr[021]=0x00559e89511c65; str={"func_sect_interp"};
      >> ptr[022]=0x00559e89511c76; str={"parse_elf64_prog_headers"};
      >> ptr[023]=0x00559e89511c8f; str={"_freeres_list"};
      >> ptr[024]=0x00559e89511c9d; str={"st_blksize"};
      >> ptr[025]=0x00559e89511ca8; str={"e_version"};
      >> ptr[026]=0x00559e89511cb2; str={"iret"};
      >> ptr[027]=0x00559e89511cb7; str={"S_Elf64_SectFunc_t"};
      >> ptr[028]=0x00559e89511cca; str={"elf64_obj_size"};
      >> ptr[029]=0x00559e89511cd9; str={"e_phoff"};
      >> ptr[030]=0x00559e89511ce1; str={"st_info"};
      >> ptr[031]=0x00559e89511ce9; str={"_markers"};
      >> ptr[032]=0x00559e89511cf2; str={"e_ehsize"};
      >> ptr[033]=0x00559e89511cfb; str={"__nlink_t"};
      >> ptr[034]=0x00559e89511d05; str={"func_sect_data"};
      >> ptr[035]=0x00559e89511d14; str={"p_elf64_obj"};
      >> ptr[036]=0x00559e89511d20; str={"S_ELF64_ELFHeader_t"};
      >> ptr[037]=0x00559e89511d34; str={"func_sect_got"};
      >> ptr[038]=0x00559e89511d42; str={"ui_level"};
      >> ptr[039]=0x00559e89511d4b; str={"e_shentsize"};
      >> ptr[040]=0x00559e89511d57; str={"func_sect_symtab"};
      >> ptr[041]=0x00559e89511d68; str={"__ino_t"};
      >> ptr[042]=0x00559e89511d70; str={"func_sect_debug_abbrev"};
      >> ptr[043]=0x00559e89511d87; str={"build_elf64_obj"};
      >> ptr[044]=0x00559e89511d97; str={"e_entry"};
      >> ptr[045]=0x00559e89511d9f; str={"func_sect_debug_str"};
      >> ptr[046]=0x00559e89511db3; str={"uint32_t"};
      >> ptr[047]=0x00559e89511dbc; str={"my_init01"};
      >> ptr[048]=0x00559e89511dc6; str={"my_init02"};
      >> ptr[049]=0x00559e89511dd0; str={"my_init03"};
      >> ptr[050]=0x00559e89511dda; str={"stdout"};
      >> ptr[051]=0x00559e89511de1; str={"_IO_save_end"};
      >> ptr[052]=0x00559e89511dee; str={"p_elf64_data"};
      >> ptr[053]=0x00559e89511dfb; str={"func_sect_gnu_version"};
      >> ptr[054]=0x00559e89511e11; str={"ppSymEnt"};
      >> ptr[055]=0x00559e89511e1a; str={"p_data"};
      >> ptr[056]=0x00559e89511e21; str={"_IO_codecvt"};
      >> ptr[057]=0x00559e89511e2d; str={"func_sect_text"};
      >> ptr[058]=0x00559e89511e3c; str={"pProgHeadersData"};
      >> ptr[059]=0x00559e89511e4d; str={"parse_args"};
      >> ptr[060]=0x00559e89511e58; str={"overflow_arg_area"};
      >> ptr[061]=0x00559e89511e6a; str={"pSecRelapltBody"};
      >> ptr[062]=0x00559e89511e7a; str={"long long unsigned int"};
      >> ptr[063]=0x00559e89511e91; str={"st_blocks"};
      >> ptr[064]=0x00559e89511e9b; str={"func_sect_note_ABI_tag"};
      >> ptr[065]=0x00559e89511eb2; str={"xlog_core"};
      >> ptr[066]=0x00559e89511ebc; str={"p_filesz"};
      >> ptr[067]=0x00559e89511ec5; str={"st_mtime"};
      >> ptr[068]=0x00559e89511ece; str={"func_sect_init_array"};
      >> ptr[069]=0x00559e89511ee3; str={"DumpPtr2Str"};
      >> ptr[070]=0x00559e89511eef; str={"_IO_backup_base"};
      >> ptr[071]=0x00559e89511eff; str={"ProgHeaderObjs"};
      >> ptr[072]=0x00559e89511f0e; str={"s_elf64_obj_t"};
      >> ptr[073]=0x00559e89511f1c; str={"pSymTabData"};
      >> ptr[074]=0x00559e89511f28; str={"xlog_ptrdump"};
      >> ptr[075]=0x00559e89511f35; str={"pProgHeaderData"};
      >> ptr[076]=0x00559e89511f45; str={"_ISlower"};
      >> ptr[077]=0x00559e89511f4e; str={"_fileno"};
      >> ptr[078]=0x00559e89511f56; str={"stat"};
      >> ptr[079]=0x00559e89511f5b; str={"ppProgHeaders"};
      >> ptr[080]=0x00559e89511f69; str={"ElfHeaderObj"};
      >> ptr[081]=0x00559e89511f76; str={"func_sect_note_gnu_build"};
      >> ptr[082]=0x00559e89511f8f; str={"__gnuc_va_list"};
      >> ptr[083]=0x00559e89511f9e; str={"func_sect_gnu_hash"};
      >> ptr[084]=0x00559e89511fb1; str={"exit"};
      >> ptr[085]=0x00559e89511fb6; str={"__mode_t"};
      >> ptr[086]=0x00559e89511fbf; str={"pData"};
      >> ptr[087]=0x00559e89511fc5; str={"parse_elf64_sect_headers"};
      >> ptr[088]=0x00559e89511fde; str={"_ISxdigit"};
      >> ptr[089]=0x00559e89511fe8; str={"_IO_read_base"};
      >> ptr[090]=0x00559e89511ff6; str={"parse_elf64_sect_header"};
      >> ptr[091]=0x00559e8951200e; str={"func_sect_note_gnu_prope"};
      >> ptr[092]=0x00559e89512027; str={"st_gid"};
      >> ptr[093]=0x00559e8951202e; str={"argc"};
      >> ptr[094]=0x00559e89512033; str={"stdin"};
      >> ptr[095]=0x00559e89512039; str={"GNU C11 9.4.0 -mtune=generic -march=x86-64 -g -O0 -std=c11 -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection"};
      >> ptr[096]=0x00559e895120d3; str={"st_mode"};
      >> ptr[097]=0x00559e895120db; str={"Elf64_Half"};
      >> ptr[098]=0x00559e895120e6; str={"st_nlink"};
      >> ptr[099]=0x00559e895120ef; str={"sh_entsize"};
      >> ptr[100]=0x00559e895120fa; str={"myreadelf-0.1.08.c"};
      >> ptr[101]=0x00559e8951210d; str={"func_sect_plt_sec"};
      >> ptr[102]=0x00559e8951211f; str={"r_info"};
      >> ptr[103]=0x00559e89512126; str={"SectHeaderObjs"};
      >> ptr[104]=0x00559e89512135; str={"pDynStrData"};
      >> ptr[105]=0x00559e89512141; str={"func_sect_bss"};
      >> ptr[106]=0x00559e8951214f; str={"filename"};
      >> ptr[107]=0x00559e89512158; str={"e_flags"};
      >> ptr[108]=0x00559e89512160; str={"_IO_marker"};
      >> ptr[109]=0x00559e8951216b; str={"_IO_read_ptr"};
      >> ptr[110]=0x00559e89512178; str={"p_align"};
      >> ptr[111]=0x00559e89512180; str={"func_sect_rela_plt"};
      >> ptr[112]=0x00559e89512193; str={"st_atime"};
      >> ptr[113]=0x00559e8951219c; str={"sh_info"};
      >> ptr[114]=0x00559e895121a4; str={"e_shstrndx"};
      >> ptr[115]=0x00559e895121af; str={"__PRETTY_FUNCTION__"};
      >> ptr[116]=0x00559e895121c3; str={"func_sect_rodata"};
      >> ptr[117]=0x00559e895121d4; str={"parse_elf64_sect_bodys"};
      >> ptr[118]=0x00559e895121eb; str={"uint8_t"};
      >> ptr[119]=0x00559e895121f3; str={"func_sect_init"};
      >> ptr[120]=0x00559e89512202; str={"st_ino"};
      >> ptr[121]=0x00559e89512209; str={"S_Elf64_Rela_t"};
      >> ptr[122]=0x00559e89512218; str={"func_sect_dynstr"};
      >> ptr[123]=0x00559e89512229; str={"pElfHeader"};
      >> ptr[124]=0x00559e89512234; str={"Elf64_Xword"};
      >> ptr[125]=0x00559e89512240; str={"_IO_write_base"};
      >> ptr[126]=0x00559e8951224f; str={"pSectNames"};
      >> ptr[127]=0x00559e8951225a; str={"long long int"};
      >> ptr[128]=0x00559e89512268; str={"func_sect_plt_got"};
      >> ptr[129]=0x00559e8951227a; str={"st_mtimensec"};
      >> ptr[130]=0x00559e89512287; str={"Elf64_Off"};
      >> ptr[131]=0x00559e89512291; str={"_IO_save_base"};
      >> ptr[132]=0x00559e8951229f; str={"__dev_t"};
      >> ptr[133]=0x00559e895122a7; str={"func_sect_plt"};
      >> ptr[134]=0x00559e895122b5; str={"_IScntrl"};
      >> ptr[135]=0x00559e895122be; str={"pSectHeaderData"};
      >> ptr[136]=0x00559e895122ce; str={"/home/xadmin/xwks.git.1/myreadelf-c11"};
      >> ptr[137]=0x00559e895122f4; str={"pSectHeader"};
      >> ptr[138]=0x00559e89512300; str={"p_flags"};
      >> ptr[139]=0x00559e89512308; str={"func_sect_gnu_version_r"};
      >> ptr[140]=0x00559e89512320; str={"pSectData"};
      >> ptr[141]=0x00559e8951232a; str={"__syscall_slong_t"};
      >> ptr[142]=0x00559e8951233c; str={"_ISdigit"};
      >> ptr[143]=0x00559e89512345; str={"ppVoidPtr"};
      >> ptr[144]=0x00559e8951234f; str={"xlog_info_x"};
      >> ptr[145]=0x00559e8951235b; str={"parse_elf64_elf_header"};
      >> ptr[146]=0x00559e89512372; str={"_ISspace"};
      >> ptr[147]=0x00559e8951237b; str={"_freeres_buf"};
      >> ptr[148]=0x00559e89512388; str={"xlog_uninit"};
      >> ptr[149]=0x00559e89512394; str={"p_type"};
      >> ptr[150]=0x00559e8951239b; str={"func_sect_eh_frame_hdr"};
      >> ptr[151]=0x00559e895123b2; str={"statbuf"};
      >> ptr[152]=0x00559e895123ba; str={"__pad0"};
      >> ptr[153]=0x00559e895123c1; str={"__pad5"};
      >> ptr[154]=0x00559e895123c8; str={"sh_offset"};
      >> ptr[155]=0x00559e895123d2; str={"__glibc_reserved"};
      >> ptr[156]=0x00559e895123e3; str={"func_sect_strtab"};
      >> ptr[157]=0x00559e895123f4; str={"p_vaddr"};
      >> ptr[158]=0x00559e895123fc; str={"before_main_func"};
      >> ptr[159]=0x00559e8951240d; str={"p_memsz"};
      >> ptr[160]=0x00559e89512415; str={"_vtable_offset"};
      >> ptr[161]=0x00559e89512424; str={"func_sect_debug_info"};
      >> ptr[162]=0x00559e89512439; str={"argv"};
      >> ptr[163]=0x00559e8951243e; str={"sh_name"};
      >> ptr[164]=0x00559e89512446; str={"__gid_t"};
      >> ptr[165]=0x00559e8951244e; str={"st_ctimensec"};
      >> ptr[166]=0x00559e8951245b; str={"xlog_hexdump"};
      >> ptr[167]=0x00559e89512468; str={"pProgHeader"};
      >> ptr[168]=0x00559e89512474; str={"pName"};
      >> ptr[169]=0x00559e8951247a; str={"func_sect_rela_dyn"};
      >> ptr[170]=0x00559e8951248d; str={"r_offset"};
      >> ptr[171]=0x00559e89512496; str={"st_other"};
      >> ptr[172]=0x00559e8951249f; str={"e_shnum"};
      >> ptr[173]=0x00559e895124a7; str={"my_fini03"};
      >> ptr[174]=0x00559e895124b1; str={"st_shndx"};
      >> ptr[175]=0x00559e895124ba; str={"_ISpunct"};
      >> ptr[176]=0x00559e895124c3; str={"__syscall_ulong_t"};
      >> ptr[177]=0x00559e895124d5; str={"_IO_read_end"};
      >> ptr[178]=0x00559e895124e2; str={"log_switch"};
      >> ptr[179]=0x00559e895124ed; str={"S_Elf64_SymEnt_t"};
      >> ptr[180]=0x00559e895124fe; str={"_ISprint"};
      >> ptr[181]=0x00559e89512507; str={"short int"};
      >> ptr[182]=0x00559e89512511; str={"e_phentsize"};
      >> ptr[183]=0x00559e8951251d; str={"p_paddr"};
      >> ptr[184]=0x00559e89512525; str={"ppRelaEnt"};
      >> ptr[185]=0x00559e8951252f; str={"xlog_init"};
      >> ptr[186]=0x00559e89512539; str={"e_phnum"};
      >> ptr[187]=0x00559e89512541; str={"func_sect_got_plt"};
      >> ptr[188]=0x00559e89512553; str={"sh_size"};
      >> ptr[189]=0x00559e8951255b; str={"_IO_wide_data"};
      >> ptr[190]=0x00559e89512569; str={"my_fini01"};
      >> ptr[191]=0x00559e89512573; str={"my_fini02"};
      >> ptr[192]=0x00559e8951257d; str={"pstr_name"};
      >> ptr[193]=0x00559e89512587; str={"__va_list_tag"};
      >> ptr[194]=0x00559e89512595; str={"__blksize_t"};
      >> ptr[195]=0x00559e895125a1; str={"sh_addr"};
      >> ptr[196]=0x00559e895125a9; str={"i_len"};
      >> ptr[197]=0x00559e895125af; str={"func_sect_comment"};
      >> ptr[198]=0x00559e895125c1; str={"fp_offset"};
      >> ptr[199]=0x00559e895125cb; str={"st_ctime"};
      >> ptr[200]=0x00559e895125d4; str={"iPtrMaxCnt"};
      >> ptr[201]=0x00559e895125df; str={"_ISgraph"};
      >> ptr[202]=0x00559e895125e8; str={"iPtrCnt"};
      >> ptr[203]=0x00559e895125f0; str={"pSHName"};
      >> ptr[204]=0x00559e895125f8; str={"i_row"};
      >> ptr[205]=0x00559e895125fe; str={"xlog_info"};
      >> ptr[206]=0x00559e89512608; str={"_old_offset"};
      >> ptr[207]=0x00559e89512614; str={"_IO_FILE"};
      >> ptr[208]=0x00559e8951261d; str={"pfunc_process"};
      >> ptr[209]=0x00559e8951262b; str={"reg_save_area"};
      >> ptr[210]=0x00559e89512639; str={"sh_type"};
      >> ptr[211]=0x00559e89512641; str={"_ISalpha"};
      >> ptr[212]=0x00559e8951264a; str={"func_sect_eh_frame"};
      >> ptr[213]=0x00559e8951265d; str={"i_elf64_len"};
      >> ptr[214]=0x00559e89512669; str={"r_addend"};
      >> ptr[215]=0x00559e89512672; str={"e_ident"};
      >> ptr[216]=0x00559e8951267a; str={"func_sect_debug_aranges"};
      >> ptr[217]=0x00559e89512692; str={"size_readok"};
      >> ptr[218]=0x00559e8951269e; str={"func_sect_fini_array"};
      >> ptr[219]=0x00559e895126b3; str={"unsigned char"};
      >> ptr[220]=0x00559e895126c1; str={"sect_funcs"};
      >> ptr[221]=0x00559e895126cc; str={"pSectName"};
      >> ptr[222]=0x00559e895126d6; str={"_IO_write_ptr"};
      >> ptr[223]=0x00559e895126e4; str={"func_sect_shstrtab"};
      >> ptr[224]=0x00559e895126f7; str={"pElfData"};
      >> ptr[225]=0x00559e89512700; str={"PrtSectHeader"};
      >> ptr[226]=0x00559e8951270e; str={"e_type"};
      >> ptr[227]=0x00559e89512715; str={"pSect_ShStrTab_Header"};
      >> ptr[228]=0x00559e8951272b; str={"xlog_mutex_unlock"};
      >> ptr[229]=0x00559e8951273d; str={"sh_flags"};
      >> ptr[230]=0x00559e89512746; str={"__time_t"};
      >> ptr[231]=0x00559e8951274f; str={"e_machine"};
      >> ptr[232]=0x00559e89512759; str={"_ISalnum"};
      >> ptr[233]=0x00559e89512762; str={"st_value"};
      >> ptr[234]=0x00559e8951276b; str={"__uid_t"};
      >> ptr[235]=0x00559e89512773; str={"st_size"};
      >> ptr[236]=0x00559e8951277b; str={"func_sect_debug_line"};
      >> ptr[237]=0x00559e89512790; str={"st_uid"};
      >> ptr[238]=0x00559e89512797; str={"__off_t"};
      >> ptr[239]=0x00559e8951279f; str={"_ISblank"};
      >> ptr[240]=0x00559e895127a8; str={"st_dev"};
      >> ptr[241]=0x00559e895127af; str={"pSectHeadersData"};
      >> ptr[242]=0x00559e895127c0; str={"short unsigned int"};
      >> ptr[243]=0x00559e895127d3; str={"xlog_mutex_lock"};
      >> ptr[244]=0x00559e895127e3; str={"main"};
      >> ptr[245]=0x00559e895127e8; str={"hFile"};
      >> ptr[246]=0x00559e895127ee; str={"__builtin_va_list"};
      >> ptr[247]=0x00559e89512800; str={"S_ELF64_ProgHeader_t"};
      >> ptr[248]=0x00559e89512815; str={"func_sect_dynamic"};
      >> ptr[249]=0x00559e89512827; str={"__func__"};
      >> ptr[250]=0x00559e89512830; str={"ppSectHeaders"};
      >> ptr[251]=0x00559e8951283e; str={"Elf64_Sxword"};
      >> ptr[252]=0x00559e8951284b; str={"__blkcnt_t"};
      >> ptr[253]=0x00559e89512856; str={"iLen"};
      >> ptr[254]=0x00559e8951285b; str={"_chain"};
      >> ptr[255]=0x00559e89512862; str={"_ISupper"};
      >> ptr[256]=0x00559e8951286b; str={"st_rdev"};
      >> ptr[257]=0x00559e89512873; str={"sh_addralign"};
      >> ptr[258]=0x00559e89512880; str={"Elf64_Word"};
      >> ptr[259]=0x00559e8951288b; str={"_flags2"};
      >> ptr[260]=0x00559e89512893; str={"st_name"};
      >> ptr[261]=0x00559e8951289b; str={"pSecReladynBody"};
      >> ptr[262]=0x00559e895128ab; str={"PrtProgHeader"};
      >> ptr[263]=0x00559e895128b9; str={"_cur_column"};
      >> ptr[264]=0x00559e895128c5; str={"pDataStart"};
      >> ptr[265]=0x00559e895128d0; str={"__off64_t"};
      >> ptr[266]=0x00559e895128da; str={"_unused2"};
      >> ptr[267]=0x00559e895128e3; str={"_IO_buf_base"};
      >> ptr[268]=0x00559e895128f0; str={"]"};
      ===========================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=33,sect_name=".debug_ranges",pSectData=0x559e895128f0,iLen=0x30}
    >> func{func_process:(02380)} is call .
      >>> {idx=33, name=".debug_ranges", pData=0x559e895128f0, iLen=48, pSectHeader=0x559e895151b0}.

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=34,sect_name=".symtab",pSectData=0x559e89512920,iLen=0x13e0}
    >> func{func_sect_symtab:(02156)} is call .
        No.[34]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e895151f0
        {
             Elf64_Word    sh_name      = 0x1;
             Elf64_Word    sh_type      = 0x2;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xe090;
             Elf64_Xword   sh_size      = 0x13e0;
             Elf64_Word    sh_link      = 0x23;
             Elf64_Word    sh_info      = 0x6b;
             Elf64_Xword   sh_addralign = 0x8;
             Elf64_Xword   sh_entsize   = 0x18;
        }

0x00559e89512920|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000010|00 00 00 00 00 00 00 00  00 00 00 00 03 00 01 00|................|
      0x00000020|18 03 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000030|00 00 00 00 03 00 02 00  38 03 00 00 00 00 00 00|........8.......|
      0x00000040|00 00 00 00 00 00 00 00  00 00 00 00 03 00 03 00|................|
      0x00000050|58 03 00 00 00 00 00 00  00 00 00 00 00 00 00 00|X...............|
      0x00000060|00 00 00 00 03 00 04 00  7c 03 00 00 00 00 00 00|........|.......|
      0x00000070|00 00 00 00 00 00 00 00  00 00 00 00 03 00 05 00|................|
      0x00000080|a0 03 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000090|00 00 00 00 03 00 06 00  c8 03 00 00 00 00 00 00|................|
      0x000000a0|00 00 00 00 00 00 00 00  00 00 00 00 03 00 07 00|................|
      0x000000b0|f0 05 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000000c0|00 00 00 00 03 00 08 00  06 07 00 00 00 00 00 00|................|
      0x000000d0|00 00 00 00 00 00 00 00  00 00 00 00 03 00 09 00|................|
      0x000000e0|38 07 00 00 00 00 00 00  00 00 00 00 00 00 00 00|8...............|
      0x000000f0|00 00 00 00 03 00 0a 00  78 07 00 00 00 00 00 00|........x.......|
      0x00000100|00 00 00 00 00 00 00 00  00 00 00 00 03 00 0b 00|................|
      0x00000110|d0 0f 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000120|00 00 00 00 03 00 0c 00  00 20 00 00 00 00 00 00|......... ......|
      0x00000130|00 00 00 00 00 00 00 00  00 00 00 00 03 00 0d 00|................|
      0x00000140|20 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00|  ..............|
      0x00000150|00 00 00 00 03 00 0e 00  30 21 00 00 00 00 00 00|........0!......|
      0x00000160|00 00 00 00 00 00 00 00  00 00 00 00 03 00 0f 00|................|
      0x00000170|40 21 00 00 00 00 00 00  00 00 00 00 00 00 00 00|@!..............|
      0x00000180|00 00 00 00 03 00 10 00  40 22 00 00 00 00 00 00|........@"......|
      0x00000190|00 00 00 00 00 00 00 00  00 00 00 00 03 00 11 00|................|
      0x000001a0|64 55 00 00 00 00 00 00  00 00 00 00 00 00 00 00|dU..............|
      0x000001b0|00 00 00 00 03 00 12 00  00 60 00 00 00 00 00 00|.........`......|
      0x000001c0|00 00 00 00 00 00 00 00  00 00 00 00 03 00 13 00|................|
      0x000001d0|bc 7a 00 00 00 00 00 00  00 00 00 00 00 00 00 00|.z..............|
      0x000001e0|00 00 00 00 03 00 14 00  28 7d 00 00 00 00 00 00|........(}......|
      0x000001f0|00 00 00 00 00 00 00 00  00 00 00 00 03 00 15 00|................|
      0x00000200|00 9d 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000210|00 00 00 00 03 00 16 00  28 9d 00 00 00 00 00 00|........(.......|
      0x00000220|00 00 00 00 00 00 00 00  00 00 00 00 03 00 17 00|................|
      0x00000230|50 9d 00 00 00 00 00 00  00 00 00 00 00 00 00 00|P...............|
      0x00000240|00 00 00 00 03 00 18 00  40 9f 00 00 00 00 00 00|........@.......|
      0x00000250|00 00 00 00 00 00 00 00  00 00 00 00 03 00 19 00|................|
      0x00000260|00 a0 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000270|00 00 00 00 03 00 1a 00  80 a2 00 00 00 00 00 00|................|
      0x00000280|00 00 00 00 00 00 00 00  00 00 00 00 03 00 1b 00|................|
      0x00000290|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000002a0|00 00 00 00 03 00 1c 00  00 00 00 00 00 00 00 00|................|
      0x000002b0|00 00 00 00 00 00 00 00  00 00 00 00 03 00 1d 00|................|
      0x000002c0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000002d0|00 00 00 00 03 00 1e 00  00 00 00 00 00 00 00 00|................|
      0x000002e0|00 00 00 00 00 00 00 00  00 00 00 00 03 00 1f 00|................|
      0x000002f0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000300|00 00 00 00 03 00 20 00  00 00 00 00 00 00 00 00|...... .........|
      0x00000310|00 00 00 00 00 00 00 00  00 00 00 00 03 00 21 00|..............!.|
      0x00000320|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000330|01 00 00 00 04 00 f1 ff  00 00 00 00 00 00 00 00|................|
      0x00000340|00 00 00 00 00 00 00 00  0c 00 00 00 02 00 10 00|................|
      0x00000350|70 22 00 00 00 00 00 00  00 00 00 00 00 00 00 00|p"..............|
      0x00000360|0e 00 00 00 02 00 10 00  a0 22 00 00 00 00 00 00|........."......|
      0x00000370|00 00 00 00 00 00 00 00  21 00 00 00 02 00 10 00|........!.......|
      0x00000380|e0 22 00 00 00 00 00 00  00 00 00 00 00 00 00 00|."..............|
      0x00000390|37 00 00 00 01 00 1a 00  88 a2 00 00 00 00 00 00|7...............|
      0x000003a0|01 00 00 00 00 00 00 00  46 00 00 00 01 00 16 00|........F.......|
      0x000003b0|28 9d 00 00 00 00 00 00  00 00 00 00 00 00 00 00|(...............|
      0x000003c0|6d 00 00 00 02 00 10 00  20 23 00 00 00 00 00 00|m....... #......|
      0x000003d0|00 00 00 00 00 00 00 00  79 00 00 00 01 00 15 00|........y.......|
      0x000003e0|00 9d 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000003f0|98 00 00 00 04 00 f1 ff  00 00 00 00 00 00 00 00|................|
      0x00000400|00 00 00 00 00 00 00 00  ab 00 00 00 01 00 12 00|................|
      0x00000410|00 75 00 00 00 00 00 00  17 00 00 00 00 00 00 00|.u..............|
      0x00000420|b9 00 00 00 01 00 12 00  20 75 00 00 00 00 00 00|........ u......|
      0x00000430|19 00 00 00 00 00 00 00  c7 00 00 00 01 00 12 00|................|
      0x00000440|40 75 00 00 00 00 00 00  19 00 00 00 00 00 00 00|@u..............|
      0x00000450|e0 00 00 00 01 00 12 00  60 75 00 00 00 00 00 00|........`u......|
      0x00000460|19 00 00 00 00 00 00 00  ee 00 00 00 01 00 12 00|................|
      0x00000470|80 75 00 00 00 00 00 00  19 00 00 00 00 00 00 00|.u..............|
      0x00000480|07 01 00 00 01 00 12 00  a0 75 00 00 00 00 00 00|.........u......|
      0x00000490|19 00 00 00 00 00 00 00  15 01 00 00 01 00 12 00|................|
      0x000004a0|c0 75 00 00 00 00 00 00  19 00 00 00 00 00 00 00|.u..............|
      0x000004b0|23 01 00 00 01 00 12 00  e0 75 00 00 00 00 00 00|#........u......|
      0x000004c0|17 00 00 00 00 00 00 00  31 01 00 00 01 00 12 00|........1.......|
      0x000004d0|00 76 00 00 00 00 00 00  1c 00 00 00 00 00 00 00|.v..............|
      0x000004e0|3f 01 00 00 01 00 12 00  20 76 00 00 00 00 00 00|?....... v......|
      0x000004f0|13 00 00 00 00 00 00 00  4d 01 00 00 01 00 12 00|........M.......|
      0x00000500|40 76 00 00 00 00 00 00  16 00 00 00 00 00 00 00|@v..............|
      0x00000510|5b 01 00 00 01 00 12 00  60 76 00 00 00 00 00 00|[.......`v......|
      0x00000520|18 00 00 00 00 00 00 00  69 01 00 00 01 00 12 00|........i.......|
      0x00000530|80 76 00 00 00 00 00 00  17 00 00 00 00 00 00 00|.v..............|
      0x00000540|77 01 00 00 01 00 12 00  a0 76 00 00 00 00 00 00|w........v......|
      0x00000550|13 00 00 00 00 00 00 00  85 01 00 00 01 00 12 00|................|
      0x00000560|c0 76 00 00 00 00 00 00  18 00 00 00 00 00 00 00|.v..............|
      0x00000570|93 01 00 00 01 00 12 00  e0 76 00 00 00 00 00 00|.........v......|
      0x00000580|15 00 00 00 00 00 00 00  a1 01 00 00 01 00 12 00|................|
      0x00000590|00 77 00 00 00 00 00 00  17 00 00 00 00 00 00 00|.w..............|
      0x000005a0|af 01 00 00 01 00 12 00  20 77 00 00 00 00 00 00|........ w......|
      0x000005b0|15 00 00 00 00 00 00 00  bd 01 00 00 01 00 12 00|................|
      0x000005c0|40 77 00 00 00 00 00 00  11 00 00 00 00 00 00 00|@w..............|
      0x000005d0|cb 01 00 00 01 00 12 00  60 77 00 00 00 00 00 00|........`w......|
      0x000005e0|11 00 00 00 00 00 00 00  d9 01 00 00 01 00 12 00|................|
      0x000005f0|80 77 00 00 00 00 00 00  11 00 00 00 00 00 00 00|.w..............|
      0x00000600|e7 01 00 00 01 00 12 00  a0 77 00 00 00 00 00 00|.........w......|
      0x00000610|13 00 00 00 00 00 00 00  f5 01 00 00 01 00 12 00|................|
      0x00000620|c0 77 00 00 00 00 00 00  13 00 00 00 00 00 00 00|.w..............|
      0x00000630|03 02 00 00 01 00 12 00  d8 77 00 00 00 00 00 00|.........w......|
      0x00000640|0f 00 00 00 00 00 00 00  11 02 00 00 01 00 12 00|................|
      0x00000650|e8 77 00 00 00 00 00 00  0e 00 00 00 00 00 00 00|.w..............|
      0x00000660|1f 02 00 00 01 00 12 00  00 78 00 00 00 00 00 00|.........x......|
      0x00000670|12 00 00 00 00 00 00 00  2d 02 00 00 01 00 12 00|........-.......|
      0x00000680|20 78 00 00 00 00 00 00  12 00 00 00 00 00 00 00| x..............|
      0x00000690|3b 02 00 00 01 00 12 00  38 78 00 00 00 00 00 00|;.......8x......|
      0x000006a0|0f 00 00 00 00 00 00 00  49 02 00 00 01 00 12 00|........I.......|
      0x000006b0|48 78 00 00 00 00 00 00  0f 00 00 00 00 00 00 00|Hx..............|
      0x000006c0|57 02 00 00 01 00 12 00  60 78 00 00 00 00 00 00|W.......`x......|
      0x000006d0|11 00 00 00 00 00 00 00  65 02 00 00 01 00 12 00|........e.......|
      0x000006e0|80 78 00 00 00 00 00 00  15 00 00 00 00 00 00 00|.x..............|
      0x000006f0|73 02 00 00 01 00 12 00  a0 78 00 00 00 00 00 00|s........x......|
      0x00000700|15 00 00 00 00 00 00 00  81 02 00 00 01 00 12 00|................|
      0x00000710|c0 78 00 00 00 00 00 00  12 00 00 00 00 00 00 00|.x..............|
      0x00000720|8f 02 00 00 01 00 12 00  d8 78 00 00 00 00 00 00|.........x......|
      0x00000730|0e 00 00 00 00 00 00 00  9d 02 00 00 01 00 12 00|................|
      0x00000740|f0 78 00 00 00 00 00 00  12 00 00 00 00 00 00 00|.x..............|
      0x00000750|ab 02 00 00 01 00 12 00  08 79 00 00 00 00 00 00|.........y......|
      0x00000760|0f 00 00 00 00 00 00 00  b9 02 00 00 01 00 12 00|................|
      0x00000770|18 79 00 00 00 00 00 00  0e 00 00 00 00 00 00 00|.y..............|
      0x00000780|c7 02 00 00 01 00 12 00  30 79 00 00 00 00 00 00|........0y......|
      0x00000790|12 00 00 00 00 00 00 00  d5 02 00 00 01 00 12 00|................|
      0x000007a0|50 79 00 00 00 00 00 00  14 00 00 00 00 00 00 00|Py..............|
      0x000007b0|e3 02 00 00 01 00 12 00  70 79 00 00 00 00 00 00|........py......|
      0x000007c0|11 00 00 00 00 00 00 00  f1 02 00 00 01 00 12 00|................|
      0x000007d0|90 79 00 00 00 00 00 00  11 00 00 00 00 00 00 00|.y..............|
      0x000007e0|ff 02 00 00 01 00 12 00  b0 79 00 00 00 00 00 00|.........y......|
      0x000007f0|13 00 00 00 00 00 00 00  0d 03 00 00 01 00 12 00|................|
      0x00000800|c8 79 00 00 00 00 00 00  0d 00 00 00 00 00 00 00|.y..............|
      0x00000810|1b 03 00 00 01 00 12 00  e0 79 00 00 00 00 00 00|.........y......|
      0x00000820|16 00 00 00 00 00 00 00  29 03 00 00 01 00 12 00|........).......|
      0x00000830|00 7a 00 00 00 00 00 00  17 00 00 00 00 00 00 00|.z..............|
      0x00000840|37 03 00 00 01 00 12 00  20 7a 00 00 00 00 00 00|7....... z......|
      0x00000850|11 00 00 00 00 00 00 00  45 03 00 00 01 00 12 00|........E.......|
      0x00000860|40 7a 00 00 00 00 00 00  10 00 00 00 00 00 00 00|@z..............|
      0x00000870|53 03 00 00 01 00 12 00  50 7a 00 00 00 00 00 00|S.......Pz......|
      0x00000880|0a 00 00 00 00 00 00 00  61 03 00 00 01 00 12 00|........a.......|
      0x00000890|60 7a 00 00 00 00 00 00  0a 00 00 00 00 00 00 00|`z..............|
      0x000008a0|6f 03 00 00 01 00 12 00  70 7a 00 00 00 00 00 00|o.......pz......|
      0x000008b0|0a 00 00 00 00 00 00 00  7d 03 00 00 01 00 12 00|........}.......|
      0x000008c0|80 7a 00 00 00 00 00 00  0a 00 00 00 00 00 00 00|.z..............|
      0x000008d0|8b 03 00 00 01 00 12 00  90 7a 00 00 00 00 00 00|.........z......|
      0x000008e0|0a 00 00 00 00 00 00 00  99 03 00 00 01 00 12 00|................|
      0x000008f0|a0 7a 00 00 00 00 00 00  0a 00 00 00 00 00 00 00|.z..............|
      0x00000900|a7 03 00 00 01 00 12 00  b0 7a 00 00 00 00 00 00|.........z......|
      0x00000910|0b 00 00 00 00 00 00 00  01 00 00 00 04 00 f1 ff|................|
      0x00000920|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000930|b5 03 00 00 01 00 14 00  cc 86 00 00 00 00 00 00|................|
      0x00000940|00 00 00 00 00 00 00 00  00 00 00 00 04 00 f1 ff|................|
      0x00000950|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000960|75 04 00 00 02 00 10 00  50 55 00 00 00 00 00 00|u.......PU......|
      0x00000970|14 00 00 00 00 00 00 00  c3 03 00 00 00 00 15 00|................|
      0x00000980|28 9d 00 00 00 00 00 00  00 00 00 00 00 00 00 00|(...............|
      0x00000990|d4 03 00 00 01 00 17 00  50 9d 00 00 00 00 00 00|........P.......|
      0x000009a0|00 00 00 00 00 00 00 00  dd 03 00 00 00 00 15 00|................|
      0x000009b0|00 9d 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000009c0|f0 03 00 00 00 00 13 00  bc 7a 00 00 00 00 00 00|.........z......|
      0x000009d0|00 00 00 00 00 00 00 00  03 04 00 00 01 00 18 00|................|
      0x000009e0|40 9f 00 00 00 00 00 00  00 00 00 00 00 00 00 00|@...............|
      0x000009f0|22 08 00 00 02 00 0c 00  00 20 00 00 00 00 00 00|"........ ......|
      0x00000a00|00 00 00 00 00 00 00 00  19 04 00 00 12 00 10 00|................|
      0x00000a10|40 55 00 00 00 00 00 00  05 00 00 00 00 00 00 00|@U..............|
      0x00000a20|29 04 00 00 12 00 10 00  1c 36 00 00 00 00 00 00|)........6......|
      0x00000a30|42 00 00 00 00 00 00 00  42 04 00 00 12 00 10 00|B.......B.......|
      0x00000a40|3f 23 00 00 00 00 00 00  0b 00 00 00 00 00 00 00|?#..............|
      0x00000a50|52 04 00 00 12 00 10 00  7c 46 00 00 00 00 00 00|R.......|F......|
      0x00000a60|68 00 00 00 00 00 00 00  61 04 00 00 12 00 10 00|h.......a.......|
      0x00000a70|4a 23 00 00 00 00 00 00  0b 00 00 00 00 00 00 00|J#..............|
      0x00000a80|73 04 00 00 12 02 10 00  50 55 00 00 00 00 00 00|s.......PU......|
      0x00000a90|14 00 00 00 00 00 00 00  7a 04 00 00 12 00 00 00|........z.......|
      0x00000aa0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000ab0|8c 04 00 00 12 00 10 00  2d 41 00 00 00 00 00 00|........-A......|
      0x00000ac0|68 00 00 00 00 00 00 00  9a 04 00 00 12 00 00 00|h...............|
      0x00000ad0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000ae0|af 04 00 00 12 00 10 00  99 43 00 00 00 00 00 00|.........C......|
      0x00000af0|91 00 00 00 00 00 00 00  bc 04 00 00 12 00 10 00|................|
      0x00000b00|a0 36 00 00 00 00 00 00  42 00 00 00 00 00 00 00|.6......B.......|
      0x00000b10|d3 04 00 00 20 00 00 00  00 00 00 00 00 00 00 00|.... ...........|
      0x00000b20|00 00 00 00 00 00 00 00  ef 04 00 00 11 00 1a 00|................|
      0x00000b30|80 a2 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000b40|03 05 00 00 12 00 10 00  6e 38 00 00 00 00 00 00|........n8......|
      0x00000b50|42 00 00 00 00 00 00 00  41 07 00 00 20 00 19 00|B.......A... ...|
      0x00000b60|00 a0 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000b70|1b 05 00 00 12 00 10 00  b7 44 00 00 00 00 00 00|.........D......|
      0x00000b80|8d 00 00 00 00 00 00 00  30 05 00 00 12 00 10 00|........0.......|
      0x00000b90|8d 4c 00 00 00 00 00 00  e7 00 00 00 00 00 00 00|.L..............|
      0x00000ba0|47 05 00 00 12 00 00 00  00 00 00 00 00 00 00 00|G...............|
      0x00000bb0|00 00 00 00 00 00 00 00  59 05 00 00 12 00 00 00|........Y.......|
      0x00000bc0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000bd0|6c 05 00 00 12 00 10 00  44 51 00 00 00 00 00 00|l.......DQ......|
      0x00000be0|40 00 00 00 00 00 00 00  76 05 00 00 12 00 10 00|@.......v.......|
      0x00000bf0|44 52 00 00 00 00 00 00  40 00 00 00 00 00 00 00|DR......@.......|
      0x00000c00|80 05 00 00 12 00 10 00  98 33 00 00 00 00 00 00|.........3......|
      0x00000c10|21 00 00 00 00 00 00 00  98 05 00 00 12 00 10 00|!...............|
      0x00000c20|4c 47 00 00 00 00 00 00  68 00 00 00 00 00 00 00|LG......h.......|
      0x00000c30|aa 05 00 00 12 00 10 00  b0 24 00 00 00 00 00 00|.........$......|
      0x00000c40|bb 03 00 00 00 00 00 00  b7 05 00 00 12 00 10 00|................|
      0x00000c50|b4 47 00 00 00 00 00 00  7e 00 00 00 00 00 00 00|.G......~.......|
      0x00000c60|cb 05 00 00 12 00 10 00  96 23 00 00 00 00 00 00|.........#......|
      0x00000c70|1a 01 00 00 00 00 00 00  d7 05 00 00 12 00 10 00|................|
      0x00000c80|6f 4a 00 00 00 00 00 00  81 00 00 00 00 00 00 00|oJ..............|
      0x00000c90|ea 05 00 00 10 00 19 00  80 a2 00 00 00 00 00 00|................|
      0x00000ca0|00 00 00 00 00 00 00 00  f1 05 00 00 12 00 10 00|................|
      0x00000cb0|95 41 00 00 00 00 00 00  68 00 00 00 00 00 00 00|.A......h.......|
      0x00000cc0|03 06 00 00 12 00 10 00  bd 2c 00 00 00 00 00 00|.........,......|
      0x00000cd0|3e 01 00 00 00 00 00 00  11 06 00 00 12 00 00 00|>...............|
      0x00000ce0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000cf0|25 06 00 00 12 00 10 00  f2 38 00 00 00 00 00 00|%........8......|
      0x00000d00|42 00 00 00 00 00 00 00  3c 06 00 00 12 00 10 00|B.......<.......|
      0x00000d10|a8 37 00 00 00 00 00 00  42 00 00 00 00 00 00 00|.7......B.......|
      0x00000d20|bc 07 00 00 12 02 11 00  64 55 00 00 00 00 00 00|........dU......|
      0x00000d30|00 00 00 00 00 00 00 00  54 06 00 00 12 00 00 00|........T.......|
      0x00000d40|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000d50|cb 08 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000d60|00 00 00 00 00 00 00 00  70 06 00 00 12 00 10 00|........p.......|
      0x00000d70|84 51 00 00 00 00 00 00  40 00 00 00 00 00 00 00|.Q......@.......|
      0x00000d80|7a 06 00 00 12 00 10 00  34 3d 00 00 00 00 00 00|z.......4=......|
      0x00000d90|7e 00 00 00 00 00 00 00  8b 06 00 00 12 00 10 00|~...............|
      0x00000da0|b0 38 00 00 00 00 00 00  42 00 00 00 00 00 00 00|.8......B.......|
      0x00000db0|a0 06 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000dc0|00 00 00 00 00 00 00 00  bb 06 00 00 12 00 10 00|................|
      0x00000dd0|e2 36 00 00 00 00 00 00  42 00 00 00 00 00 00 00|.6......B.......|
      0x00000de0|d7 06 00 00 12 00 10 00  f1 49 00 00 00 00 00 00|.........I......|
      0x00000df0|7e 00 00 00 00 00 00 00  e8 06 00 00 12 00 10 00|~...............|
      0x00000e00|84 52 00 00 00 00 00 00  e3 00 00 00 00 00 00 00|.R..............|
      0x00000e10|f3 06 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000e20|00 00 00 00 00 00 00 00  12 07 00 00 12 00 00 00|................|
      0x00000e30|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000e40|26 07 00 00 12 00 10 00  a9 30 00 00 00 00 00 00|&........0......|
      0x00000e50|ef 02 00 00 00 00 00 00  3f 07 00 00 10 00 19 00|........?.......|
      0x00000e60|00 a0 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000e70|4c 07 00 00 12 00 00 00  00 00 00 00 00 00 00 00|L...............|
      0x00000e80|00 00 00 00 00 00 00 00  60 07 00 00 12 00 10 00|........`.......|
      0x00000e90|24 37 00 00 00 00 00 00  42 00 00 00 00 00 00 00|$7......B.......|
      0x00000ea0|73 07 00 00 12 00 10 00  32 48 00 00 00 00 00 00|s.......2H......|
      0x00000eb0|bf 01 00 00 00 00 00 00  84 07 00 00 12 00 10 00|................|
      0x00000ec0|f0 4a 00 00 00 00 00 00  7e 00 00 00 00 00 00 00|.J......~.......|
      0x00000ed0|91 07 00 00 12 00 10 00  b2 3d 00 00 00 00 00 00|.........=......|
      0x00000ee0|81 01 00 00 00 00 00 00  a4 07 00 00 20 00 00 00|............ ...|
      0x00000ef0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000f00|b3 07 00 00 12 00 10 00  c9 42 00 00 00 00 00 00|.........B......|
      0x00000f10|68 00 00 00 00 00 00 00  c2 07 00 00 11 02 19 00|h...............|
      0x00000f20|08 a0 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000f30|cf 07 00 00 12 00 10 00  2a 44 00 00 00 00 00 00|........*D......|
      0x00000f40|8d 00 00 00 00 00 00 00  e4 07 00 00 11 00 12 00|................|
      0x00000f50|00 60 00 00 00 00 00 00  04 00 00 00 00 00 00 00|.`..............|
      0x00000f60|f3 07 00 00 12 00 10 00  66 37 00 00 00 00 00 00|........f7......|
      0x00000f70|42 00 00 00 00 00 00 00  09 08 00 00 12 00 00 00|B...............|
      0x00000f80|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000f90|1e 08 00 00 12 00 10 00  29 23 00 00 00 00 00 00|........)#......|
      0x00000fa0|0b 00 00 00 00 00 00 00  28 08 00 00 12 00 10 00|........(.......|
      0x00000fb0|44 2b 00 00 00 00 00 00  79 01 00 00 00 00 00 00|D+......y.......|
      0x00000fc0|36 08 00 00 12 00 10 00  5f 3c 00 00 00 00 00 00|6......._<......|
      0x00000fd0|d5 00 00 00 00 00 00 00  42 08 00 00 12 00 10 00|........B.......|
      0x00000fe0|d0 54 00 00 00 00 00 00  65 00 00 00 00 00 00 00|.T......e.......|
      0x00000ff0|52 08 00 00 12 00 00 00  00 00 00 00 00 00 00 00|R...............|
      0x00001000|00 00 00 00 00 00 00 00  66 08 00 00 12 00 00 00|........f.......|
      0x00001010|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001020|7a 08 00 00 12 00 10 00  b9 33 00 00 00 00 00 00|z........3......|
      0x00001030|63 02 00 00 00 00 00 00  93 08 00 00 12 00 10 00|c...............|
      0x00001040|74 4d 00 00 00 00 00 00  ff 02 00 00 00 00 00 00|tM..............|
      0x00001050|a3 08 00 00 12 00 10 00  34 23 00 00 00 00 00 00|........4#......|
      0x00001060|0b 00 00 00 00 00 00 00  af 08 00 00 11 00 19 00|................|
      0x00001070|20 a0 00 00 00 00 00 00  60 02 00 00 00 00 00 00| .......`.......|
      0x00001080|ba 08 00 00 12 00 10 00  c4 50 00 00 00 00 00 00|.........P......|
      0x00001090|40 00 00 00 00 00 00 00  cf 03 00 00 10 00 1a 00|@...............|
      0x000010a0|90 a2 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000010b0|ca 08 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000010c0|00 00 00 00 00 00 00 00  45 07 00 00 12 00 10 00|........E.......|
      0x000010d0|40 22 00 00 00 00 00 00  2f 00 00 00 00 00 00 00|@"....../.......|
      0x000010e0|df 08 00 00 12 00 10 00  99 29 00 00 00 00 00 00|.........)......|
      0x000010f0|ab 01 00 00 00 00 00 00  ee 08 00 00 12 00 10 00|................|
      0x00001100|76 39 00 00 00 00 00 00  02 01 00 00 00 00 00 00|v9..............|
      0x00001110|ff 08 00 00 12 00 10 00  c4 51 00 00 00 00 00 00|.........Q......|
      0x00001120|40 00 00 00 00 00 00 00  09 09 00 00 12 00 10 00|@...............|
      0x00001130|ea 37 00 00 00 00 00 00  42 00 00 00 00 00 00 00|.7......B.......|
      0x00001140|20 09 00 00 12 00 10 00  65 42 00 00 00 00 00 00| .......eB......|
      0x00001150|64 00 00 00 00 00 00 00  2f 09 00 00 10 00 1a 00|d......./.......|
      0x00001160|80 a2 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001170|3b 09 00 00 12 00 10 00  67 53 00 00 00 00 00 00|;.......gS......|
      0x00001180|60 01 00 00 00 00 00 00  40 09 00 00 12 00 10 00|`.......@.......|
      0x00001190|2c 38 00 00 00 00 00 00  42 00 00 00 00 00 00 00|,8......B.......|
      0x000011a0|53 09 00 00 12 00 10 00  31 43 00 00 00 00 00 00|S.......1C......|
      0x000011b0|68 00 00 00 00 00 00 00  64 09 00 00 12 00 10 00|h.......d.......|
      0x000011c0|04 52 00 00 00 00 00 00  40 00 00 00 00 00 00 00|.R......@.......|
      0x000011d0|6e 09 00 00 12 00 10 00  04 51 00 00 00 00 00 00|n........Q......|
      0x000011e0|40 00 00 00 00 00 00 00  78 09 00 00 12 00 00 00|@.......x.......|
      0x000011f0|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00001200|8b 09 00 00 12 00 10 00  fd 41 00 00 00 00 00 00|.........A......|
      0x00001210|68 00 00 00 00 00 00 00  9d 09 00 00 12 00 10 00|h...............|
      0x00001220|73 50 00 00 00 00 00 00  51 00 00 00 00 00 00 00|sP......Q.......|
      0x00001230|ae 09 00 00 12 00 10 00  fb 2d 00 00 00 00 00 00|.........-......|
      0x00001240|89 02 00 00 00 00 00 00  c5 09 00 00 12 00 10 00|................|
      0x00001250|14 46 00 00 00 00 00 00  68 00 00 00 00 00 00 00|.F......h.......|
      0x00001260|d7 09 00 00 12 00 10 00  33 3f 00 00 00 00 00 00|........3?......|
      0x00001270|92 01 00 00 00 00 00 00  ea 09 00 00 12 00 10 00|................|
      0x00001280|55 23 00 00 00 00 00 00  41 00 00 00 00 00 00 00|U#......A.......|
      0x00001290|f4 09 00 00 11 02 19 00  80 a2 00 00 00 00 00 00|................|
      0x000012a0|00 00 00 00 00 00 00 00  00 0a 00 00 12 00 10 00|................|
      0x000012b0|84 30 00 00 00 00 00 00  25 00 00 00 00 00 00 00|.0......%.......|
      0x000012c0|18 0a 00 00 20 00 00 00  00 00 00 00 00 00 00 00|.... ...........|
      0x000012d0|00 00 00 00 00 00 00 00  32 0a 00 00 12 00 10 00|........2.......|
      0x000012e0|6e 4b 00 00 00 00 00 00  1f 01 00 00 00 00 00 00|nK..............|
      0x000012f0|48 0a 00 00 12 00 10 00  ac 45 00 00 00 00 00 00|H........E......|
      0x00001300|68 00 00 00 00 00 00 00  56 0a 00 00 12 00 10 00|h.......V.......|
      0x00001310|78 3a 00 00 00 00 00 00  e7 01 00 00 00 00 00 00|x:..............|
      0x00001320|67 0a 00 00 12 00 10 00  c5 40 00 00 00 00 00 00|g........@......|
      0x00001330|68 00 00 00 00 00 00 00  76 0a 00 00 12 00 10 00|h.......v.......|
      0x00001340|6b 28 00 00 00 00 00 00  2e 01 00 00 00 00 00 00|k(..............|
      0x00001350|80 0a 00 00 12 00 10 00  5e 36 00 00 00 00 00 00|........^6......|
      0x00001360|42 00 00 00 00 00 00 00  99 0a 00 00 12 00 10 00|B...............|
      0x00001370|34 39 00 00 00 00 00 00  42 00 00 00 00 00 00 00|49......B.......|
      0x00001380|ae 0a 00 00 22 00 00 00  00 00 00 00 00 00 00 00|...."...........|
      0x00001390|00 00 00 00 00 00 00 00  ca 0a 00 00 12 00 10 00|................|
      0x000013a0|44 45 00 00 00 00 00 00  68 00 00 00 00 00 00 00|DE......h.......|
      0x000013b0|dc 0a 00 00 12 00 00 00  00 00 00 00 00 00 00 00|................|
      0x000013c0|00 00 00 00 00 00 00 00  f5 0a 00 00 12 00 10 00|................|
      0x000013d0|e4 46 00 00 00 00 00 00  68 00 00 00 00 00 00 00|.F......h.......|
      =============================================================================


Symbol table '.symtab' contains 212 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx  Name  NameStr
   000:        0     0  00      00    00       0000 0000  tempstr
   001:      318     0  03      00    00       0001 0000  tempstr
   002:      338     0  03      00    00       0002 0000  tempstr
   003:      358     0  03      00    00       0003 0000  tempstr
   004:      37c     0  03      00    00       0004 0000  tempstr
   005:      3a0     0  03      00    00       0005 0000  tempstr
   006:      3c8     0  03      00    00       0006 0000  tempstr
   007:      5f0     0  03      00    00       0007 0000  tempstr
   008:      706     0  03      00    00       0008 0000  tempstr
   009:      738     0  03      00    00       0009 0000  tempstr
   010:      778     0  03      00    00       000a 0000  tempstr
   011:      fd0     0  03      00    00       000b 0000  tempstr
   012:     2000     0  03      00    00       000c 0000  tempstr
   013:     2020     0  03      00    00       000d 0000  tempstr
   014:     2130     0  03      00    00       000e 0000  tempstr
   015:     2140     0  03      00    00       000f 0000  tempstr
   016:     2240     0  03      00    00       0010 0000  tempstr
   017:     5564     0  03      00    00       0011 0000  tempstr
   018:     6000     0  03      00    00       0012 0000  tempstr
   019:     7abc     0  03      00    00       0013 0000  tempstr
   020:     7d28     0  03      00    00       0014 0000  tempstr
   021:     9d00     0  03      00    00       0015 0000  tempstr
   022:     9d28     0  03      00    00       0016 0000  tempstr
   023:     9d50     0  03      00    00       0017 0000  tempstr
   024:     9f40     0  03      00    00       0018 0000  tempstr
   025:     a000     0  03      00    00       0019 0000  tempstr
   026:     a280     0  03      00    00       001a 0000  tempstr
   027:        0     0  03      00    00       001b 0000  tempstr
   028:        0     0  03      00    00       001c 0000  tempstr
   029:        0     0  03      00    00       001d 0000  tempstr
   030:        0     0  03      00    00       001e 0000  tempstr
   031:        0     0  03      00    00       001f 0000  tempstr
   032:        0     0  03      00    00       0020 0000  tempstr
   033:        0     0  03      00    00       0021 0000  tempstr
   034:        0     0  04      00    00       fff1 0001  tempstr
   035:     2270     0  02      00    00       0010 000c  tempstr
   036:     22a0     0  02      00    00       0010 000e  tempstr
   037:     22e0     0  02      00    00       0010 0021  tempstr
   038:     a288     1  01      00    00       001a 0037  tempstr
   039:     9d28     0  01      00    00       0016 0046  tempstr
   040:     2320     0  02      00    00       0010 006d  tempstr
   041:     9d00     0  01      00    00       0015 0079  tempstr
   042:        0     0  04      00    00       fff1 0098  tempstr
   043:     7500    23  01      00    00       0012 00ab  tempstr
   044:     7520    25  01      00    00       0012 00b9  tempstr
   045:     7540    25  01      00    00       0012 00c7  tempstr
   046:     7560    25  01      00    00       0012 00e0  tempstr
   047:     7580    25  01      00    00       0012 00ee  tempstr
   048:     75a0    25  01      00    00       0012 0107  tempstr
   049:     75c0    25  01      00    00       0012 0115  tempstr
   050:     75e0    23  01      00    00       0012 0123  tempstr
   051:     7600    28  01      00    00       0012 0131  tempstr
   052:     7620    19  01      00    00       0012 013f  tempstr
   053:     7640    22  01      00    00       0012 014d  tempstr
   054:     7660    24  01      00    00       0012 015b  tempstr
   055:     7680    23  01      00    00       0012 0169  tempstr
   056:     76a0    19  01      00    00       0012 0177  tempstr
   057:     76c0    24  01      00    00       0012 0185  tempstr
   058:     76e0    21  01      00    00       0012 0193  tempstr
   059:     7700    23  01      00    00       0012 01a1  tempstr
   060:     7720    21  01      00    00       0012 01af  tempstr
   061:     7740    17  01      00    00       0012 01bd  tempstr
   062:     7760    17  01      00    00       0012 01cb  tempstr
   063:     7780    17  01      00    00       0012 01d9  tempstr
   064:     77a0    19  01      00    00       0012 01e7  tempstr
   065:     77c0    19  01      00    00       0012 01f5  tempstr
   066:     77d8    15  01      00    00       0012 0203  tempstr
   067:     77e8    14  01      00    00       0012 0211  tempstr
   068:     7800    18  01      00    00       0012 021f  tempstr
   069:     7820    18  01      00    00       0012 022d  tempstr
   070:     7838    15  01      00    00       0012 023b  tempstr
   071:     7848    15  01      00    00       0012 0249  tempstr
   072:     7860    17  01      00    00       0012 0257  tempstr
   073:     7880    21  01      00    00       0012 0265  tempstr
   074:     78a0    21  01      00    00       0012 0273  tempstr
   075:     78c0    18  01      00    00       0012 0281  tempstr
   076:     78d8    14  01      00    00       0012 028f  tempstr
   077:     78f0    18  01      00    00       0012 029d  tempstr
   078:     7908    15  01      00    00       0012 02ab  tempstr
   079:     7918    14  01      00    00       0012 02b9  tempstr
   080:     7930    18  01      00    00       0012 02c7  tempstr
   081:     7950    20  01      00    00       0012 02d5  tempstr
   082:     7970    17  01      00    00       0012 02e3  tempstr
   083:     7990    17  01      00    00       0012 02f1  tempstr
   084:     79b0    19  01      00    00       0012 02ff  tempstr
   085:     79c8    13  01      00    00       0012 030d  tempstr
   086:     79e0    22  01      00    00       0012 031b  tempstr
   087:     7a00    23  01      00    00       0012 0329  tempstr
   088:     7a20    17  01      00    00       0012 0337  tempstr
   089:     7a40    16  01      00    00       0012 0345  tempstr
   090:     7a50    10  01      00    00       0012 0353  tempstr
   091:     7a60    10  01      00    00       0012 0361  tempstr
   092:     7a70    10  01      00    00       0012 036f  tempstr
   093:     7a80    10  01      00    00       0012 037d  tempstr
   094:     7a90    10  01      00    00       0012 038b  tempstr
   095:     7aa0    10  01      00    00       0012 0399  tempstr
   096:     7ab0    11  01      00    00       0012 03a7  tempstr
   097:        0     0  04      00    00       fff1 0001  tempstr
   098:     86cc     0  01      00    00       0014 03b5  tempstr
   099:        0     0  04      00    00       fff1 0000  tempstr
   100:     5550    20  02      00    00       0010 0475  tempstr
   101:     9d28     0  00      00    00       0015 03c3  tempstr
   102:     9d50     0  01      00    00       0017 03d4  tempstr
   103:     9d00     0  00      00    00       0015 03dd  tempstr
   104:     7abc     0  00      00    00       0013 03f0  tempstr
   105:     9f40     0  01      00    00       0018 0403  tempstr
   106:     2000     0  02      00    00       000c 0822  tempstr
   107:     5540     5  02      01    00       0010 0419  tempstr
   108:     361c    66  02      01    00       0010 0429  tempstr
   109:     233f    11  02      01    00       0010 0442  tempstr
   110:     467c   104  02      01    00       0010 0452  tempstr
   111:     234a    11  02      01    00       0010 0461  tempstr
   112:     5550    20  02      01    02       0010 0473  tempstr
   113:        0     0  02      01    00       0000 047a  tempstr
   114:     412d   104  02      01    00       0010 048c  tempstr
   115:        0     0  02      01    00       0000 049a  tempstr
   116:     4399   145  02      01    00       0010 04af  tempstr
   117:     36a0    66  02      01    00       0010 04bc  tempstr
   118:        0     0  00      02    00       0000 04d3  tempstr
   119:     a280     8  01      01    00       001a 04ef  tempstr
   120:     386e    66  02      01    00       0010 0503  tempstr
   121:     a000     0  00      02    00       0019 0741  tempstr
   122:     44b7   141  02      01    00       0010 051b  tempstr
   123:     4c8d   231  02      01    00       0010 0530  tempstr
   124:        0     0  02      01    00       0000 0547  tempstr
   125:        0     0  02      01    00       0000 0559  tempstr
   126:     5144    64  02      01    00       0010 056c  tempstr
   127:     5244    64  02      01    00       0010 0576  tempstr
   128:     3398    33  02      01    00       0010 0580  tempstr
   129:     474c   104  02      01    00       0010 0598  tempstr
   130:     24b0   955  02      01    00       0010 05aa  tempstr
   131:     47b4   126  02      01    00       0010 05b7  tempstr
   132:     2396   282  02      01    00       0010 05cb  tempstr
   133:     4a6f   129  02      01    00       0010 05d7  tempstr
   134:     a280     0  00      01    00       0019 05ea  tempstr
   135:     4195   104  02      01    00       0010 05f1  tempstr
   136:     2cbd   318  02      01    00       0010 0603  tempstr
   137:        0     0  02      01    00       0000 0611  tempstr
   138:     38f2    66  02      01    00       0010 0625  tempstr
   139:     37a8    66  02      01    00       0010 063c  tempstr
   140:     5564     0  02      01    02       0011 07bc  tempstr
   141:        0     0  02      01    00       0000 0654  tempstr
   142:        0     0  02      01    00       0000 08cb  tempstr
   143:     5184    64  02      01    00       0010 0670  tempstr
   144:     3d34   126  02      01    00       0010 067a  tempstr
   145:     38b0    66  02      01    00       0010 068b  tempstr
   146:        0     0  02      01    00       0000 06a0  tempstr
   147:     36e2    66  02      01    00       0010 06bb  tempstr
   148:     49f1   126  02      01    00       0010 06d7  tempstr
   149:     5284   227  02      01    00       0010 06e8  tempstr
   150:        0     0  02      01    00       0000 06f3  tempstr
   151:        0     0  02      01    00       0000 0712  tempstr
   152:     30a9   751  02      01    00       0010 0726  tempstr
   153:     a000     0  00      01    00       0019 073f  tempstr
   154:        0     0  02      01    00       0000 074c  tempstr
   155:     3724    66  02      01    00       0010 0760  tempstr
   156:     4832   447  02      01    00       0010 0773  tempstr
   157:     4af0   126  02      01    00       0010 0784  tempstr
   158:     3db2   385  02      01    00       0010 0791  tempstr
   159:        0     0  00      02    00       0000 07a4  tempstr
   160:     42c9   104  02      01    00       0010 07b3  tempstr
   161:     a008     0  01      01    02       0019 07c2  tempstr
   162:     442a   141  02      01    00       0010 07cf  tempstr
   163:     6000     4  01      01    00       0012 07e4  tempstr
   164:     3766    66  02      01    00       0010 07f3  tempstr
   165:        0     0  02      01    00       0000 0809  tempstr
   166:     2329    11  02      01    00       0010 081e  tempstr
   167:     2b44   377  02      01    00       0010 0828  tempstr
   168:     3c5f   213  02      01    00       0010 0836  tempstr
   169:     54d0   101  02      01    00       0010 0842  tempstr
   170:        0     0  02      01    00       0000 0852  tempstr
   171:        0     0  02      01    00       0000 0866  tempstr
   172:     33b9   611  02      01    00       0010 087a  tempstr
   173:     4d74   767  02      01    00       0010 0893  tempstr
   174:     2334    11  02      01    00       0010 08a3  tempstr
   175:     a020   608  01      01    00       0019 08af  tempstr
   176:     50c4    64  02      01    00       0010 08ba  tempstr
   177:     a290     0  00      01    00       001a 03cf  tempstr
   178:        0     0  02      01    00       0000 08ca  tempstr
   179:     2240    47  02      01    00       0010 0745  tempstr
   180:     2999   427  02      01    00       0010 08df  tempstr
   181:     3976   258  02      01    00       0010 08ee  tempstr
   182:     51c4    64  02      01    00       0010 08ff  tempstr
   183:     37ea    66  02      01    00       0010 0909  tempstr
   184:     4265   100  02      01    00       0010 0920  tempstr
   185:     a280     0  00      01    00       001a 092f  tempstr
   186:     5367   352  02      01    00       0010 093b  tempstr
   187:     382c    66  02      01    00       0010 0940  tempstr
   188:     4331   104  02      01    00       0010 0953  tempstr
   189:     5204    64  02      01    00       0010 0964  tempstr
   190:     5104    64  02      01    00       0010 096e  tempstr
   191:        0     0  02      01    00       0000 0978  tempstr
   192:     41fd   104  02      01    00       0010 098b  tempstr
   193:     5073    81  02      01    00       0010 099d  tempstr
   194:     2dfb   649  02      01    00       0010 09ae  tempstr
   195:     4614   104  02      01    00       0010 09c5  tempstr
   196:     3f33   402  02      01    00       0010 09d7  tempstr
   197:     2355    65  02      01    00       0010 09ea  tempstr
   198:     a280     0  01      01    02       0019 09f4  tempstr
   199:     3084    37  02      01    00       0010 0a00  tempstr
   200:        0     0  00      02    00       0000 0a18  tempstr
   201:     4b6e   287  02      01    00       0010 0a32  tempstr
   202:     45ac   104  02      01    00       0010 0a48  tempstr
   203:     3a78   487  02      01    00       0010 0a56  tempstr
   204:     40c5   104  02      01    00       0010 0a67  tempstr
   205:     286b   302  02      01    00       0010 0a76  tempstr
   206:     365e    66  02      01    00       0010 0a80  tempstr
   207:     3934    66  02      01    00       0010 0a99  tempstr
   208:        0     0  02      02    00       0000 0aae  tempstr
   209:     4544   104  02      01    00       0010 0aca  tempstr
   210:        0     0  02      01    00       0000 0adc  tempstr
   211:     46e4   104  02      01    00       0010 0af5  tempstr

  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=35,sect_name=".strtab",pSectData=0x559e89513d00,iLen=0xb03}
    >> func{func_sect_strtab:(02193)} is call .
        No.[35]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89515230
        {
             Elf64_Word    sh_name      = 0x9;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xf470;
             Elf64_Xword   sh_size      = 0xb03;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e89513d00|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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
      0x000000a0|66 2d 30 2e 31 2e 30 38  2e 63 00 5f 5f 66 75 6e|f-0.1.08.c.__fun|
      0x000000b0|63 5f 5f 2e 32 35 30 34  00 5f 5f 66 75 6e 63 5f|c__.2504.__func_|
      0x000000c0|5f 2e 32 35 32 32 00 5f  5f 50 52 45 54 54 59 5f|_.2522.__PRETTY_|
      0x000000d0|46 55 4e 43 54 49 4f 4e  5f 5f 2e 32 35 32 36 00|FUNCTION__.2526.|
      0x000000e0|5f 5f 66 75 6e 63 5f 5f  2e 32 35 34 35 00 5f 5f|__func__.2545.__|
      0x000000f0|50 52 45 54 54 59 5f 46  55 4e 43 54 49 4f 4e 5f|PRETTY_FUNCTION_|
      0x00000100|5f 2e 32 35 34 39 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2549.__func__.|
      0x00000110|32 38 30 31 00 5f 5f 66  75 6e 63 5f 5f 2e 32 38|2801.__func__.28|
      0x00000120|30 39 00 5f 5f 66 75 6e  63 5f 5f 2e 32 38 31 37|09.__func__.2817|
      0x00000130|00 5f 5f 66 75 6e 63 5f  5f 2e 32 38 32 35 00 5f|.__func__.2825._|
      0x00000140|5f 66 75 6e 63 5f 5f 2e  32 38 33 33 00 5f 5f 66|_func__.2833.__f|
      0x00000150|75 6e 63 5f 5f 2e 32 38  34 31 00 5f 5f 66 75 6e|unc__.2841.__fun|
      0x00000160|63 5f 5f 2e 32 38 34 39  00 5f 5f 66 75 6e 63 5f|c__.2849.__func_|
      0x00000170|5f 2e 32 38 35 37 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2857.__func__.|
      0x00000180|32 38 36 35 00 5f 5f 66  75 6e 63 5f 5f 2e 32 38|2865.__func__.28|
      0x00000190|37 33 00 5f 5f 66 75 6e  63 5f 5f 2e 32 38 38 31|73.__func__.2881|
      0x000001a0|00 5f 5f 66 75 6e 63 5f  5f 2e 32 38 38 39 00 5f|.__func__.2889._|
      0x000001b0|5f 66 75 6e 63 5f 5f 2e  32 38 39 37 00 5f 5f 66|_func__.2897.__f|
      0x000001c0|75 6e 63 5f 5f 2e 32 39  30 35 00 5f 5f 66 75 6e|unc__.2905.__fun|
      0x000001d0|63 5f 5f 2e 32 39 31 37  00 5f 5f 66 75 6e 63 5f|c__.2917.__func_|
      0x000001e0|5f 2e 32 39 34 39 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2949.__func__.|
      0x000001f0|32 39 35 37 00 5f 5f 66  75 6e 63 5f 5f 2e 32 39|2957.__func__.29|
      0x00000200|37 32 00 5f 5f 66 75 6e  63 5f 5f 2e 32 39 38 37|72.__func__.2987|
      0x00000210|00 5f 5f 66 75 6e 63 5f  5f 2e 32 39 39 35 00 5f|.__func__.2995._|
      0x00000220|5f 66 75 6e 63 5f 5f 2e  33 30 30 33 00 5f 5f 66|_func__.3003.__f|
      0x00000230|75 6e 63 5f 5f 2e 33 30  31 31 00 5f 5f 66 75 6e|unc__.3011.__fun|
      0x00000240|63 5f 5f 2e 33 30 31 39  00 5f 5f 66 75 6e 63 5f|c__.3019.__func_|
      0x00000250|5f 2e 33 30 32 37 00 5f  5f 66 75 6e 63 5f 5f 2e|_.3027.__func__.|
      0x00000260|33 30 33 35 00 5f 5f 66  75 6e 63 5f 5f 2e 33 30|3035.__func__.30|
      0x00000270|35 32 00 5f 5f 66 75 6e  63 5f 5f 2e 33 30 36 30|52.__func__.3060|
      0x00000280|00 5f 5f 66 75 6e 63 5f  5f 2e 33 30 36 38 00 5f|.__func__.3068._|
      0x00000290|5f 66 75 6e 63 5f 5f 2e  33 30 37 36 00 5f 5f 66|_func__.3076.__f|
      0x000002a0|75 6e 63 5f 5f 2e 33 30  38 34 00 5f 5f 66 75 6e|unc__.3084.__fun|
      0x000002b0|63 5f 5f 2e 33 30 39 32  00 5f 5f 66 75 6e 63 5f|c__.3092.__func_|
      0x000002c0|5f 2e 33 31 30 30 00 5f  5f 66 75 6e 63 5f 5f 2e|_.3100.__func__.|
      0x000002d0|33 31 30 38 00 5f 5f 66  75 6e 63 5f 5f 2e 33 31|3108.__func__.31|
      0x000002e0|31 36 00 5f 5f 66 75 6e  63 5f 5f 2e 33 31 32 34|16.__func__.3124|
      0x000002f0|00 5f 5f 66 75 6e 63 5f  5f 2e 33 31 33 39 00 5f|.__func__.3139._|
      0x00000300|5f 66 75 6e 63 5f 5f 2e  33 31 34 37 00 5f 5f 66|_func__.3147.__f|
      0x00000310|75 6e 63 5f 5f 2e 33 31  35 35 00 5f 5f 66 75 6e|unc__.3155.__fun|
      0x00000320|63 5f 5f 2e 33 31 36 33  00 5f 5f 66 75 6e 63 5f|c__.3163.__func_|
      0x00000330|5f 2e 33 31 38 32 00 5f  5f 66 75 6e 63 5f 5f 2e|_.3182.__func__.|
      0x00000340|33 32 30 38 00 5f 5f 66  75 6e 63 5f 5f 2e 33 32|3208.__func__.32|
      0x00000350|31 32 00 5f 5f 66 75 6e  63 5f 5f 2e 33 32 32 38|12.__func__.3228|
      0x00000360|00 5f 5f 66 75 6e 63 5f  5f 2e 33 32 33 32 00 5f|.__func__.3232._|
      0x00000370|5f 66 75 6e 63 5f 5f 2e  33 32 33 36 00 5f 5f 66|_func__.3236.__f|
      0x00000380|75 6e 63 5f 5f 2e 33 32  34 30 00 5f 5f 66 75 6e|unc__.3240.__fun|
      0x00000390|63 5f 5f 2e 33 32 34 34  00 5f 5f 66 75 6e 63 5f|c__.3244.__func_|
      0x000003a0|5f 2e 33 32 34 38 00 5f  5f 66 75 6e 63 5f 5f 2e|_.3248.__func__.|
      0x000003b0|33 32 35 33 00 5f 5f 46  52 41 4d 45 5f 45 4e 44|3253.__FRAME_END|
      0x000003c0|5f 5f 00 5f 5f 69 6e 69  74 5f 61 72 72 61 79 5f|__.__init_array_|
      0x000003d0|65 6e 64 00 5f 44 59 4e  41 4d 49 43 00 5f 5f 69|end._DYNAMIC.__i|
      0x000003e0|6e 69 74 5f 61 72 72 61  79 5f 73 74 61 72 74 00|nit_array_start.|
      0x000003f0|5f 5f 47 4e 55 5f 45 48  5f 46 52 41 4d 45 5f 48|__GNU_EH_FRAME_H|
      0x00000400|44 52 00 5f 47 4c 4f 42  41 4c 5f 4f 46 46 53 45|DR._GLOBAL_OFFSE|
      0x00000410|54 5f 54 41 42 4c 45 5f  00 5f 5f 6c 69 62 63 5f|T_TABLE_.__libc_|
      0x00000420|63 73 75 5f 66 69 6e 69  00 66 75 6e 63 5f 73 65|csu_fini.func_se|
      0x00000430|63 74 5f 6e 6f 74 65 5f  67 6e 75 5f 70 72 6f 70|ct_note_gnu_prop|
      0x00000440|65 00 78 6c 6f 67 5f 6d  75 74 65 78 5f 6c 6f 63|e.xlog_mutex_loc|
      0x00000450|6b 00 66 75 6e 63 5f 73  65 63 74 5f 64 61 74 61|k.func_sect_data|
      0x00000460|00 78 6c 6f 67 5f 6d 75  74 65 78 5f 75 6e 6c 6f|.xlog_mutex_unlo|
      0x00000470|63 6b 00 5f 5f 73 74 61  74 00 66 72 65 65 40 40|ck.__stat.free@@|
      0x00000480|47 4c 49 42 43 5f 32 2e  32 2e 35 00 66 75 6e 63|GLIBC_2.2.5.func|
      0x00000490|5f 73 65 63 74 5f 70 6c  74 00 70 75 74 63 68 61|_sect_plt.putcha|
      0x000004a0|72 40 40 47 4c 49 42 43  5f 32 2e 32 2e 35 00 78|r@@GLIBC_2.2.5.x|
      0x000004b0|6c 6f 67 5f 70 74 72 64  75 6d 70 00 66 75 6e 63|log_ptrdump.func|
      0x000004c0|5f 73 65 63 74 5f 6e 6f  74 65 5f 41 42 49 5f 74|_sect_note_ABI_t|
      0x000004d0|61 67 00 5f 49 54 4d 5f  64 65 72 65 67 69 73 74|ag._ITM_deregist|
      0x000004e0|65 72 54 4d 43 6c 6f 6e  65 54 61 62 6c 65 00 73|erTMCloneTable.s|
      0x000004f0|74 64 6f 75 74 40 40 47  4c 49 42 43 5f 32 2e 32|tdout@@GLIBC_2.2|
      0x00000500|2e 35 00 66 75 6e 63 5f  73 65 63 74 5f 64 65 62|.5.func_sect_deb|
      0x00000510|75 67 5f 61 72 61 6e 67  65 73 00 66 75 6e 63 5f|ug_aranges.func_|
      0x00000520|73 65 63 74 5f 66 69 6e  69 5f 61 72 72 61 79 00|sect_fini_array.|
      0x00000530|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
      0x00000540|5f 62 6f 64 79 73 00 70  75 74 73 40 40 47 4c 49|_bodys.puts@@GLI|
      0x00000550|42 43 5f 32 2e 32 2e 35  00 66 72 65 61 64 40 40|BC_2.2.5.fread@@|
      0x00000560|47 4c 49 42 43 5f 32 2e  32 2e 35 00 6d 79 5f 66|GLIBC_2.2.5.my_f|
      0x00000570|69 6e 69 30 31 00 6d 79  5f 66 69 6e 69 30 33 00|ini01.my_fini03.|
      0x00000580|70 61 72 73 65 5f 65 6c  66 36 34 5f 70 72 6f 67|parse_elf64_prog|
      0x00000590|5f 68 65 61 64 65 72 00  66 75 6e 63 5f 73 65 63|_header.func_sec|
      0x000005a0|74 5f 63 6f 6d 6d 65 6e  74 00 78 6c 6f 67 5f 68|t_comment.xlog_h|
      0x000005b0|65 78 64 75 6d 70 00 66  75 6e 63 5f 73 65 63 74|exdump.func_sect|
      0x000005c0|5f 64 65 62 75 67 5f 73  74 72 00 78 6c 6f 67 5f|_debug_str.xlog_|
      0x000005d0|69 6e 66 6f 5f 78 00 66  75 6e 63 5f 73 65 63 74|info_x.func_sect|
      0x000005e0|5f 73 68 73 74 72 74 61  62 00 5f 65 64 61 74 61|_shstrtab._edata|
      0x000005f0|00 66 75 6e 63 5f 73 65  63 74 5f 70 6c 74 5f 67|.func_sect_plt_g|
      0x00000600|6f 74 00 50 72 74 50 72  6f 67 48 65 61 64 65 72|ot.PrtProgHeader|
      0x00000610|00 66 63 6c 6f 73 65 40  40 47 4c 49 42 43 5f 32|.fclose@@GLIBC_2|
      0x00000620|2e 32 2e 35 00 66 75 6e  63 5f 73 65 63 74 5f 64|.2.5.func_sect_d|
      0x00000630|65 62 75 67 5f 61 62 62  72 65 76 00 66 75 6e 63|ebug_abbrev.func|
      0x00000640|5f 73 65 63 74 5f 67 6e  75 5f 76 65 72 73 69 6f|_sect_gnu_versio|
      0x00000650|6e 5f 72 00 5f 5f 73 74  61 63 6b 5f 63 68 6b 5f|n_r.__stack_chk_|
      0x00000660|66 61 69 6c 40 40 47 4c  49 42 43 5f 32 2e 34 00|fail@@GLIBC_2.4.|
      0x00000670|6d 79 5f 69 6e 69 74 30  32 00 66 75 6e 63 5f 73|my_init02.func_s|
      0x00000680|65 63 74 5f 64 79 6e 73  74 72 00 66 75 6e 63 5f|ect_dynstr.func_|
      0x00000690|73 65 63 74 5f 64 65 62  75 67 5f 69 6e 66 6f 00|sect_debug_info.|
      0x000006a0|5f 5f 61 73 73 65 72 74  5f 66 61 69 6c 40 40 47|__assert_fail@@G|
      0x000006b0|4c 49 42 43 5f 32 2e 32  2e 35 00 66 75 6e 63 5f|LIBC_2.2.5.func_|
      0x000006c0|73 65 63 74 5f 6e 6f 74  65 5f 67 6e 75 5f 62 75|sect_note_gnu_bu|
      0x000006d0|69 6c 64 5f 69 64 00 66  75 6e 63 5f 73 65 63 74|ild_id.func_sect|
      0x000006e0|5f 73 74 72 74 61 62 00  70 61 72 73 65 5f 61 72|_strtab.parse_ar|
      0x000006f0|67 73 00 5f 5f 6c 69 62  63 5f 73 74 61 72 74 5f|gs.__libc_start_|
      0x00000700|6d 61 69 6e 40 40 47 4c  49 42 43 5f 32 2e 32 2e|main@@GLIBC_2.2.|
      0x00000710|35 00 63 61 6c 6c 6f 63  40 40 47 4c 49 42 43 5f|5.calloc@@GLIBC_|
      0x00000720|32 2e 32 2e 35 00 70 61  72 73 65 5f 65 6c 66 36|2.2.5.parse_elf6|
      0x00000730|34 5f 73 65 63 74 5f 68  65 61 64 65 72 73 00 5f|4_sect_headers._|
      0x00000740|5f 64 61 74 61 5f 73 74  61 72 74 00 73 74 72 63|_data_start.strc|
      0x00000750|6d 70 40 40 47 4c 49 42  43 5f 32 2e 32 2e 35 00|mp@@GLIBC_2.2.5.|
      0x00000760|66 75 6e 63 5f 73 65 63  74 5f 67 6e 75 5f 68 61|func_sect_gnu_ha|
      0x00000770|73 68 00 66 75 6e 63 5f  73 65 63 74 5f 73 79 6d|sh.func_sect_sym|
      0x00000780|74 61 62 00 66 75 6e 63  5f 70 72 6f 63 65 73 73|tab.func_process|
      0x00000790|00 66 75 6e 63 5f 73 65  63 74 5f 72 65 6c 61 5f|.func_sect_rela_|
      0x000007a0|64 79 6e 00 5f 5f 67 6d  6f 6e 5f 73 74 61 72 74|dyn.__gmon_start|
      0x000007b0|5f 5f 00 66 75 6e 63 5f  73 65 63 74 5f 66 69 6e|__.func_sect_fin|
      0x000007c0|69 00 5f 5f 64 73 6f 5f  68 61 6e 64 6c 65 00 66|i.__dso_handle.f|
      0x000007d0|75 6e 63 5f 73 65 63 74  5f 69 6e 69 74 5f 61 72|unc_sect_init_ar|
      0x000007e0|72 61 79 00 5f 49 4f 5f  73 74 64 69 6e 5f 75 73|ray._IO_stdin_us|
      0x000007f0|65 64 00 66 75 6e 63 5f  73 65 63 74 5f 67 6e 75|ed.func_sect_gnu|
      0x00000800|5f 76 65 72 73 69 6f 6e  00 5f 5f 78 73 74 61 74|_version.__xstat|
      0x00000810|40 40 47 4c 49 42 43 5f  32 2e 32 2e 35 00 78 6c|@@GLIBC_2.2.5.xl|
      0x00000820|6f 67 5f 69 6e 69 74 00  50 72 74 53 65 63 74 48|og_init.PrtSectH|
      0x00000830|65 61 64 65 72 00 44 75  6d 70 50 74 72 32 53 74|eader.DumpPtr2St|
      0x00000840|72 00 5f 5f 6c 69 62 63  5f 63 73 75 5f 69 6e 69|r.__libc_csu_ini|
      0x00000850|74 00 6d 61 6c 6c 6f 63  40 40 47 4c 49 42 43 5f|t.malloc@@GLIBC_|
      0x00000860|32 2e 32 2e 35 00 66 66  6c 75 73 68 40 40 47 4c|2.2.5.fflush@@GL|
      0x00000870|49 42 43 5f 32 2e 32 2e  35 00 70 61 72 73 65 5f|IBC_2.2.5.parse_|
      0x00000880|65 6c 66 36 34 5f 70 72  6f 67 5f 68 65 61 64 65|elf64_prog_heade|
      0x00000890|72 73 00 62 75 69 6c 64  5f 65 6c 66 36 34 5f 6f|rs.build_elf64_o|
      0x000008a0|62 6a 00 78 6c 6f 67 5f  75 6e 69 6e 69 74 00 73|bj.xlog_uninit.s|
      0x000008b0|65 63 74 5f 66 75 6e 63  73 00 61 66 74 65 72 5f|ect_funcs.after_|
      0x000008c0|6d 61 69 6e 5f 66 75 6e  63 00 76 70 72 69 6e 74|main_func.vprint|
      0x000008d0|66 40 40 47 4c 49 42 43  5f 32 2e 32 2e 35 00 67|f@@GLIBC_2.2.5.g|
      0x000008e0|65 74 5f 65 6c 66 36 34  5f 64 61 74 61 00 66 75|et_elf64_data.fu|
      0x000008f0|6e 63 5f 73 65 63 74 5f  69 6e 74 65 72 70 00 6d|nc_sect_interp.m|
      0x00000900|79 5f 66 69 6e 69 30 32  00 66 75 6e 63 5f 73 65|y_fini02.func_se|
      0x00000910|63 74 5f 65 68 5f 66 72  61 6d 65 5f 68 64 72 00|ct_eh_frame_hdr.|
      0x00000920|66 75 6e 63 5f 73 65 63  74 5f 74 65 78 74 00 5f|func_sect_text._|
      0x00000930|5f 62 73 73 5f 73 74 61  72 74 00 6d 61 69 6e 00|_bss_start.main.|
      0x00000940|66 75 6e 63 5f 73 65 63  74 5f 65 68 5f 66 72 61|func_sect_eh_fra|
      0x00000950|6d 65 00 66 75 6e 63 5f  73 65 63 74 5f 72 6f 64|me.func_sect_rod|
      0x00000960|61 74 61 00 6d 79 5f 69  6e 69 74 30 33 00 6d 79|ata.my_init03.my|
      0x00000970|5f 69 6e 69 74 30 31 00  66 6f 70 65 6e 40 40 47|_init01.fopen@@G|
      0x00000980|4c 49 42 43 5f 32 2e 32  2e 35 00 66 75 6e 63 5f|LIBC_2.2.5.func_|
      0x00000990|73 65 63 74 5f 70 6c 74  5f 73 65 63 00 62 65 66|sect_plt_sec.bef|
      0x000009a0|6f 72 65 5f 6d 61 69 6e  5f 66 75 6e 63 00 70 61|ore_main_func.pa|
      0x000009b0|72 73 65 5f 65 6c 66 36  34 5f 65 6c 66 5f 68 65|rse_elf64_elf_he|
      0x000009c0|61 64 65 72 00 66 75 6e  63 5f 73 65 63 74 5f 67|ader.func_sect_g|
      0x000009d0|6f 74 5f 70 6c 74 00 66  75 6e 63 5f 73 65 63 74|ot_plt.func_sect|
      0x000009e0|5f 72 65 6c 61 5f 70 6c  74 00 78 6c 6f 67 5f 63|_rela_plt.xlog_c|
      0x000009f0|6f 72 65 00 5f 5f 54 4d  43 5f 45 4e 44 5f 5f 00|ore.__TMC_END__.|
      0x00000a00|70 61 72 73 65 5f 65 6c  66 36 34 5f 73 65 63 74|parse_elf64_sect|
      0x00000a10|5f 68 65 61 64 65 72 00  5f 49 54 4d 5f 72 65 67|_header._ITM_reg|
      0x00000a20|69 73 74 65 72 54 4d 43  6c 6f 6e 65 54 61 62 6c|isterTMCloneTabl|
      0x00000a30|65 00 70 61 72 73 65 5f  65 6c 66 36 34 5f 73 65|e.parse_elf64_se|
      0x00000a40|63 74 5f 62 6f 64 79 00  66 75 6e 63 5f 73 65 63|ct_body.func_sec|
      0x00000a50|74 5f 67 6f 74 00 66 75  6e 63 5f 73 65 63 74 5f|t_got.func_sect_|
      0x00000a60|64 79 6e 73 79 6d 00 66  75 6e 63 5f 73 65 63 74|dynsym.func_sect|
      0x00000a70|5f 69 6e 69 74 00 78 6c  6f 67 5f 69 6e 66 6f 00|_init.xlog_info.|
      0x00000a80|66 75 6e 63 5f 73 65 63  74 5f 6e 6f 74 65 5f 67|func_sect_note_g|
      0x00000a90|6e 75 5f 62 75 69 6c 64  00 66 75 6e 63 5f 73 65|nu_build.func_se|
      0x00000aa0|63 74 5f 64 65 62 75 67  5f 6c 69 6e 65 00 5f 5f|ct_debug_line.__|
      0x00000ab0|63 78 61 5f 66 69 6e 61  6c 69 7a 65 40 40 47 4c|cxa_finalize@@GL|
      0x00000ac0|49 42 43 5f 32 2e 32 2e  35 00 66 75 6e 63 5f 73|IBC_2.2.5.func_s|
      0x00000ad0|65 63 74 5f 64 79 6e 61  6d 69 63 00 5f 5f 63 74|ect_dynamic.__ct|
      0x00000ae0|79 70 65 5f 62 5f 6c 6f  63 40 40 47 4c 49 42 43|ype_b_loc@@GLIBC|
      0x00000af0|5f 32 2e 33 00 66 75 6e  63 5f 73 65 63 74 5f 62|_2.3.func_sect_b|
      0x00000b00|73 73 00 ** ** ** ** **  ** ** ** ** ** ** ** **|ss.*************|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x00559e89513d01; str={"crtstuff.c"};
      >> ptr[001]=0x00559e89513d0c; str={"deregister_tm_clones"};
      >> ptr[002]=0x00559e89513d21; str={"__do_global_dtors_aux"};
      >> ptr[003]=0x00559e89513d37; str={"completed.8061"};
      >> ptr[004]=0x00559e89513d46; str={"__do_global_dtors_aux_fini_array_entry"};
      >> ptr[005]=0x00559e89513d6d; str={"frame_dummy"};
      >> ptr[006]=0x00559e89513d79; str={"__frame_dummy_init_array_entry"};
      >> ptr[007]=0x00559e89513d98; str={"myreadelf-0.1.08.c"};
      >> ptr[008]=0x00559e89513dab; str={"__func__.2504"};
      >> ptr[009]=0x00559e89513db9; str={"__func__.2522"};
      >> ptr[010]=0x00559e89513dc7; str={"__PRETTY_FUNCTION__.2526"};
      >> ptr[011]=0x00559e89513de0; str={"__func__.2545"};
      >> ptr[012]=0x00559e89513dee; str={"__PRETTY_FUNCTION__.2549"};
      >> ptr[013]=0x00559e89513e07; str={"__func__.2801"};
      >> ptr[014]=0x00559e89513e15; str={"__func__.2809"};
      >> ptr[015]=0x00559e89513e23; str={"__func__.2817"};
      >> ptr[016]=0x00559e89513e31; str={"__func__.2825"};
      >> ptr[017]=0x00559e89513e3f; str={"__func__.2833"};
      >> ptr[018]=0x00559e89513e4d; str={"__func__.2841"};
      >> ptr[019]=0x00559e89513e5b; str={"__func__.2849"};
      >> ptr[020]=0x00559e89513e69; str={"__func__.2857"};
      >> ptr[021]=0x00559e89513e77; str={"__func__.2865"};
      >> ptr[022]=0x00559e89513e85; str={"__func__.2873"};
      >> ptr[023]=0x00559e89513e93; str={"__func__.2881"};
      >> ptr[024]=0x00559e89513ea1; str={"__func__.2889"};
      >> ptr[025]=0x00559e89513eaf; str={"__func__.2897"};
      >> ptr[026]=0x00559e89513ebd; str={"__func__.2905"};
      >> ptr[027]=0x00559e89513ecb; str={"__func__.2917"};
      >> ptr[028]=0x00559e89513ed9; str={"__func__.2949"};
      >> ptr[029]=0x00559e89513ee7; str={"__func__.2957"};
      >> ptr[030]=0x00559e89513ef5; str={"__func__.2972"};
      >> ptr[031]=0x00559e89513f03; str={"__func__.2987"};
      >> ptr[032]=0x00559e89513f11; str={"__func__.2995"};
      >> ptr[033]=0x00559e89513f1f; str={"__func__.3003"};
      >> ptr[034]=0x00559e89513f2d; str={"__func__.3011"};
      >> ptr[035]=0x00559e89513f3b; str={"__func__.3019"};
      >> ptr[036]=0x00559e89513f49; str={"__func__.3027"};
      >> ptr[037]=0x00559e89513f57; str={"__func__.3035"};
      >> ptr[038]=0x00559e89513f65; str={"__func__.3052"};
      >> ptr[039]=0x00559e89513f73; str={"__func__.3060"};
      >> ptr[040]=0x00559e89513f81; str={"__func__.3068"};
      >> ptr[041]=0x00559e89513f8f; str={"__func__.3076"};
      >> ptr[042]=0x00559e89513f9d; str={"__func__.3084"};
      >> ptr[043]=0x00559e89513fab; str={"__func__.3092"};
      >> ptr[044]=0x00559e89513fb9; str={"__func__.3100"};
      >> ptr[045]=0x00559e89513fc7; str={"__func__.3108"};
      >> ptr[046]=0x00559e89513fd5; str={"__func__.3116"};
      >> ptr[047]=0x00559e89513fe3; str={"__func__.3124"};
      >> ptr[048]=0x00559e89513ff1; str={"__func__.3139"};
      >> ptr[049]=0x00559e89513fff; str={"__func__.3147"};
      >> ptr[050]=0x00559e8951400d; str={"__func__.3155"};
      >> ptr[051]=0x00559e8951401b; str={"__func__.3163"};
      >> ptr[052]=0x00559e89514029; str={"__func__.3182"};
      >> ptr[053]=0x00559e89514037; str={"__func__.3208"};
      >> ptr[054]=0x00559e89514045; str={"__func__.3212"};
      >> ptr[055]=0x00559e89514053; str={"__func__.3228"};
      >> ptr[056]=0x00559e89514061; str={"__func__.3232"};
      >> ptr[057]=0x00559e8951406f; str={"__func__.3236"};
      >> ptr[058]=0x00559e8951407d; str={"__func__.3240"};
      >> ptr[059]=0x00559e8951408b; str={"__func__.3244"};
      >> ptr[060]=0x00559e89514099; str={"__func__.3248"};
      >> ptr[061]=0x00559e895140a7; str={"__func__.3253"};
      >> ptr[062]=0x00559e895140b5; str={"__FRAME_END__"};
      >> ptr[063]=0x00559e895140c3; str={"__init_array_end"};
      >> ptr[064]=0x00559e895140d4; str={"_DYNAMIC"};
      >> ptr[065]=0x00559e895140dd; str={"__init_array_start"};
      >> ptr[066]=0x00559e895140f0; str={"__GNU_EH_FRAME_HDR"};
      >> ptr[067]=0x00559e89514103; str={"_GLOBAL_OFFSET_TABLE_"};
      >> ptr[068]=0x00559e89514119; str={"__libc_csu_fini"};
      >> ptr[069]=0x00559e89514129; str={"func_sect_note_gnu_prope"};
      >> ptr[070]=0x00559e89514142; str={"xlog_mutex_lock"};
      >> ptr[071]=0x00559e89514152; str={"func_sect_data"};
      >> ptr[072]=0x00559e89514161; str={"xlog_mutex_unlock"};
      >> ptr[073]=0x00559e89514173; str={"__stat"};
      >> ptr[074]=0x00559e8951417a; str={"free@@GLIBC_2.2.5"};
      >> ptr[075]=0x00559e8951418c; str={"func_sect_plt"};
      >> ptr[076]=0x00559e8951419a; str={"putchar@@GLIBC_2.2.5"};
      >> ptr[077]=0x00559e895141af; str={"xlog_ptrdump"};
      >> ptr[078]=0x00559e895141bc; str={"func_sect_note_ABI_tag"};
      >> ptr[079]=0x00559e895141d3; str={"_ITM_deregisterTMCloneTable"};
      >> ptr[080]=0x00559e895141ef; str={"stdout@@GLIBC_2.2.5"};
      >> ptr[081]=0x00559e89514203; str={"func_sect_debug_aranges"};
      >> ptr[082]=0x00559e8951421b; str={"func_sect_fini_array"};
      >> ptr[083]=0x00559e89514230; str={"parse_elf64_sect_bodys"};
      >> ptr[084]=0x00559e89514247; str={"puts@@GLIBC_2.2.5"};
      >> ptr[085]=0x00559e89514259; str={"fread@@GLIBC_2.2.5"};
      >> ptr[086]=0x00559e8951426c; str={"my_fini01"};
      >> ptr[087]=0x00559e89514276; str={"my_fini03"};
      >> ptr[088]=0x00559e89514280; str={"parse_elf64_prog_header"};
      >> ptr[089]=0x00559e89514298; str={"func_sect_comment"};
      >> ptr[090]=0x00559e895142aa; str={"xlog_hexdump"};
      >> ptr[091]=0x00559e895142b7; str={"func_sect_debug_str"};
      >> ptr[092]=0x00559e895142cb; str={"xlog_info_x"};
      >> ptr[093]=0x00559e895142d7; str={"func_sect_shstrtab"};
      >> ptr[094]=0x00559e895142ea; str={"_edata"};
      >> ptr[095]=0x00559e895142f1; str={"func_sect_plt_got"};
      >> ptr[096]=0x00559e89514303; str={"PrtProgHeader"};
      >> ptr[097]=0x00559e89514311; str={"fclose@@GLIBC_2.2.5"};
      >> ptr[098]=0x00559e89514325; str={"func_sect_debug_abbrev"};
      >> ptr[099]=0x00559e8951433c; str={"func_sect_gnu_version_r"};
      >> ptr[100]=0x00559e89514354; str={"__stack_chk_fail@@GLIBC_2.4"};
      >> ptr[101]=0x00559e89514370; str={"my_init02"};
      >> ptr[102]=0x00559e8951437a; str={"func_sect_dynstr"};
      >> ptr[103]=0x00559e8951438b; str={"func_sect_debug_info"};
      >> ptr[104]=0x00559e895143a0; str={"__assert_fail@@GLIBC_2.2.5"};
      >> ptr[105]=0x00559e895143bb; str={"func_sect_note_gnu_build_id"};
      >> ptr[106]=0x00559e895143d7; str={"func_sect_strtab"};
      >> ptr[107]=0x00559e895143e8; str={"parse_args"};
      >> ptr[108]=0x00559e895143f3; str={"__libc_start_main@@GLIBC_2.2.5"};
      >> ptr[109]=0x00559e89514412; str={"calloc@@GLIBC_2.2.5"};
      >> ptr[110]=0x00559e89514426; str={"parse_elf64_sect_headers"};
      >> ptr[111]=0x00559e8951443f; str={"__data_start"};
      >> ptr[112]=0x00559e8951444c; str={"strcmp@@GLIBC_2.2.5"};
      >> ptr[113]=0x00559e89514460; str={"func_sect_gnu_hash"};
      >> ptr[114]=0x00559e89514473; str={"func_sect_symtab"};
      >> ptr[115]=0x00559e89514484; str={"func_process"};
      >> ptr[116]=0x00559e89514491; str={"func_sect_rela_dyn"};
      >> ptr[117]=0x00559e895144a4; str={"__gmon_start__"};
      >> ptr[118]=0x00559e895144b3; str={"func_sect_fini"};
      >> ptr[119]=0x00559e895144c2; str={"__dso_handle"};
      >> ptr[120]=0x00559e895144cf; str={"func_sect_init_array"};
      >> ptr[121]=0x00559e895144e4; str={"_IO_stdin_used"};
      >> ptr[122]=0x00559e895144f3; str={"func_sect_gnu_version"};
      >> ptr[123]=0x00559e89514509; str={"__xstat@@GLIBC_2.2.5"};
      >> ptr[124]=0x00559e8951451e; str={"xlog_init"};
      >> ptr[125]=0x00559e89514528; str={"PrtSectHeader"};
      >> ptr[126]=0x00559e89514536; str={"DumpPtr2Str"};
      >> ptr[127]=0x00559e89514542; str={"__libc_csu_init"};
      >> ptr[128]=0x00559e89514552; str={"malloc@@GLIBC_2.2.5"};
      >> ptr[129]=0x00559e89514566; str={"fflush@@GLIBC_2.2.5"};
      >> ptr[130]=0x00559e8951457a; str={"parse_elf64_prog_headers"};
      >> ptr[131]=0x00559e89514593; str={"build_elf64_obj"};
      >> ptr[132]=0x00559e895145a3; str={"xlog_uninit"};
      >> ptr[133]=0x00559e895145af; str={"sect_funcs"};
      >> ptr[134]=0x00559e895145ba; str={"after_main_func"};
      >> ptr[135]=0x00559e895145ca; str={"vprintf@@GLIBC_2.2.5"};
      >> ptr[136]=0x00559e895145df; str={"get_elf64_data"};
      >> ptr[137]=0x00559e895145ee; str={"func_sect_interp"};
      >> ptr[138]=0x00559e895145ff; str={"my_fini02"};
      >> ptr[139]=0x00559e89514609; str={"func_sect_eh_frame_hdr"};
      >> ptr[140]=0x00559e89514620; str={"func_sect_text"};
      >> ptr[141]=0x00559e8951462f; str={"__bss_start"};
      >> ptr[142]=0x00559e8951463b; str={"main"};
      >> ptr[143]=0x00559e89514640; str={"func_sect_eh_frame"};
      >> ptr[144]=0x00559e89514653; str={"func_sect_rodata"};
      >> ptr[145]=0x00559e89514664; str={"my_init03"};
      >> ptr[146]=0x00559e8951466e; str={"my_init01"};
      >> ptr[147]=0x00559e89514678; str={"fopen@@GLIBC_2.2.5"};
      >> ptr[148]=0x00559e8951468b; str={"func_sect_plt_sec"};
      >> ptr[149]=0x00559e8951469d; str={"before_main_func"};
      >> ptr[150]=0x00559e895146ae; str={"parse_elf64_elf_header"};
      >> ptr[151]=0x00559e895146c5; str={"func_sect_got_plt"};
      >> ptr[152]=0x00559e895146d7; str={"func_sect_rela_plt"};
      >> ptr[153]=0x00559e895146ea; str={"xlog_core"};
      >> ptr[154]=0x00559e895146f4; str={"__TMC_END__"};
      >> ptr[155]=0x00559e89514700; str={"parse_elf64_sect_header"};
      >> ptr[156]=0x00559e89514718; str={"_ITM_registerTMCloneTable"};
      >> ptr[157]=0x00559e89514732; str={"parse_elf64_sect_body"};
      >> ptr[158]=0x00559e89514748; str={"func_sect_got"};
      >> ptr[159]=0x00559e89514756; str={"func_sect_dynsym"};
      >> ptr[160]=0x00559e89514767; str={"func_sect_init"};
      >> ptr[161]=0x00559e89514776; str={"xlog_info"};
      >> ptr[162]=0x00559e89514780; str={"func_sect_note_gnu_build"};
      >> ptr[163]=0x00559e89514799; str={"func_sect_debug_line"};
      >> ptr[164]=0x00559e895147ae; str={"__cxa_finalize@@GLIBC_2.2.5"};
      >> ptr[165]=0x00559e895147ca; str={"func_sect_dynamic"};
      >> ptr[166]=0x00559e895147dc; str={"__ctype_b_loc@@GLIBC_2.3"};
      >> ptr[167]=0x00559e895147f5; str={"func_sect_bss"};
      ===========================================================


  >> func{parse_elf64_sect_body:(02390)} is call. 
      {idx=36,sect_name=".shstrtab",pSectData=0x559e89514803,iLen=0x168}
    >> func{func_sect_shstrtab:(02281)} is call .
        No.[36]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x559e89515270
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xff73;
             Elf64_Xword   sh_size      = 0x168;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x00559e89514803|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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
      0x00000150|64 65 62 75 67 5f 73 74  72 00 2e 64 65 62 75 67|debug_str..debug|
      0x00000160|5f 72 61 6e 67 65 73 00  00 00 00 00 00 00 00 00|_ranges.........|
      0x00000170|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000180|00 00 00 00 00 00 00 00  ** ** ** ** ** ** ** **|........********|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x00559e89514804; str={".symtab"};
      >> ptr[001]=0x00559e8951480c; str={".strtab"};
      >> ptr[002]=0x00559e89514814; str={".shstrtab"};
      >> ptr[003]=0x00559e8951481e; str={".interp"};
      >> ptr[004]=0x00559e89514826; str={".note.gnu.property"};
      >> ptr[005]=0x00559e89514839; str={".note.gnu.build-id"};
      >> ptr[006]=0x00559e8951484c; str={".note.ABI-tag"};
      >> ptr[007]=0x00559e8951485a; str={".gnu.hash"};
      >> ptr[008]=0x00559e89514864; str={".dynsym"};
      >> ptr[009]=0x00559e8951486c; str={".dynstr"};
      >> ptr[010]=0x00559e89514874; str={".gnu.version"};
      >> ptr[011]=0x00559e89514881; str={".gnu.version_r"};
      >> ptr[012]=0x00559e89514890; str={".rela.dyn"};
      >> ptr[013]=0x00559e8951489a; str={".rela.plt"};
      >> ptr[014]=0x00559e895148a4; str={".init"};
      >> ptr[015]=0x00559e895148aa; str={".plt.got"};
      >> ptr[016]=0x00559e895148b3; str={".plt.sec"};
      >> ptr[017]=0x00559e895148bc; str={".text"};
      >> ptr[018]=0x00559e895148c2; str={".fini"};
      >> ptr[019]=0x00559e895148c8; str={".rodata"};
      >> ptr[020]=0x00559e895148d0; str={".eh_frame_hdr"};
      >> ptr[021]=0x00559e895148de; str={".eh_frame"};
      >> ptr[022]=0x00559e895148e8; str={".init_array"};
      >> ptr[023]=0x00559e895148f4; str={".fini_array"};
      >> ptr[024]=0x00559e89514900; str={".dynamic"};
      >> ptr[025]=0x00559e89514909; str={".data"};
      >> ptr[026]=0x00559e8951490f; str={".bss"};
      >> ptr[027]=0x00559e89514914; str={".comment"};
      >> ptr[028]=0x00559e8951491d; str={".debug_aranges"};
      >> ptr[029]=0x00559e8951492c; str={".debug_info"};
      >> ptr[030]=0x00559e89514938; str={".debug_abbrev"};
      >> ptr[031]=0x00559e89514946; str={".debug_line"};
      >> ptr[032]=0x00559e89514952; str={".debug_str"};
      >> ptr[033]=0x00559e8951495d; str={".debug_ranges"};
      ===========================================================


  >> build_elf64_obj() exit;
  >> the app exit.
  >> func{my_fini03:(02548)@(myreadelf-0.1.08.c)} is call .
  #<<<<====
  >> func{my_fini02:(02536)@(myreadelf-0.1.08.c)} is call .
  #<<<<====
  >> func{my_fini01:(02524)@(myreadelf-0.1.08.c)} is call .
  #<<<<====
  >> func{after_main_func:(02504)@(myreadelf-0.1.08.c)} is call .
  #<<<<====
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 
xadmin@hw:~/xwks.git.1/myreadelf-c11$ gcc -std=c11 -g -Wall -O0  myreadelf-0.1.08.c -o myapp
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 

#endif
