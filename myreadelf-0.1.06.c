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

//==============================================================
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
int func_sect_dynsym           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
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
//int func_sect_dynsym           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}

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

//===============================================================
struct s_elf64_obj_t
{
    uint8_t*                      pElfData      ;
    struct S_ELF64_ELFHeader_t*   pElfHeader    ;
    struct S_ELF64_ELFHeader_t    ElfHeaderObj  ;
    struct S_ELF64_SectHeader_t** ppSectHeaders ;
    struct S_ELF64_SectHeader_t   SectHeaderObjs[0x30];
    struct S_ELF64_ProgHeader_t** ppProgHeaders ;
    struct S_ELF64_ProgHeader_t   ProgHeaderObjs[0x10];
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
xadmin@hw:~/xwks.git.1/myreadelf-c11$ ./myapp
################################################{}##################################################
  #====>>>>
  >> func{before_main_func:(00977)@(myreadelf-0.1.06.c)} is call .
  #====>>>>
  >> func{my_init01:(00998)@(myreadelf-0.1.06.c)} is call .
  #====>>>>
  >> func{my_init02:(01010)@(myreadelf-0.1.06.c)} is call .
  #====>>>>
  >> func{my_init03:(01022)@(myreadelf-0.1.06.c)} is call .
  >> the app starting ... ...

0x007ffe8d7abe98|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|60 d6 7a 8d fe 7f 00 00  00 00 00 00 00 00 00 00|`.z.............|
      0x00000010|68 d6 7a 8d fe 7f 00 00  78 d6 7a 8d fe 7f 00 00|h.z.....x.z.....|
      0x00000020|90 d6 7a 8d fe 7f 00 00  a7 d6 7a 8d fe 7f 00 00|..z.......z.....|
      0x00000030|bb d6 7a 8d fe 7f 00 00  d3 d6 7a 8d fe 7f 00 00|..z.......z.....|
      0x00000040|fd d6 7a 8d fe 7f 00 00  0c d7 7a 8d fe 7f 00 00|..z.......z.....|
      0x00000050|21 d7 7a 8d fe 7f 00 00  30 d7 7a ** ** ** ** **|!.z.....0.z*****|
      =============================================================================


0x007ffe8d7ad660|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2e 2f 6d 79 61 70 70 00  53 48 45 4c 4c 3d 2f 62|./myapp.SHELL=/b|
      0x00000010|69 6e 2f 62 61 73 68 00  4c 41 4e 47 55 41 47 45|in/bash.LANGUAGE|
      0x00000020|3d 7a 68 5f 43 4e 3a 65  6e 5f 55 53 3a 65 6e 00|=zh_CN:en_US:en.|
      0x00000030|4c 43 5f 41 44 44 52 45  53 53 3d 7a 68 5f 43 4e|LC_ADDRESS=zh_CN|
      0x00000040|2e 55 54 46 2d 38 00 4c  43 5f 4e 41 4d 45 3d 7a|.UTF-8.LC_NAME=z|
      0x00000050|68 5f 43 4e 2e 55 54 46  2d 38 00 ** ** ** ** **|h_CN.UTF-8.*****|
      =============================================================================

  >> func:parse_args(1, 0x7ffe8d7abe98) is called. (@file:myreadelf-0.1.06.c,line:1036).

    >>> argv[00](addr=0x7ffe8d7ad660) = {"./myapp"}.

  >> func:parse_args() is called. @line:(1043).
  >> get_elf64_data("./myapp", len) entry;

0x0055f0f34aa890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  e0 21 00 00 00 00 00 00|..>......!......|
      0x00000020|40 00 00 00 00 00 00 00  68 e8 00 00 00 00 00 00|@.......h.......|
      0x00000030|00 00 00 00 40 00 38 00  0d 00 40 00 24 00 23 00|....@.8...@.$.#.|
      0x00000040|06 00 00 00 04 00 00 00  40 00 00 00 00 00 00 00|........@.......|
      0x00000050|40 00 00 00 00 ** ** **  ** ** ** ** ** ** ** **|@....***********|
      =============================================================================

  >> build_elf64_obj(0x55f0f34aa890, 61800) entry;
  >> func{parse_elf64_elf_header:(00356)} is call.{pElfData=0x55f0f34aa890}.
        struct S_ELF64_ELFHeader_t pElfHeader = {0x55f0f34aa890} 
        {
                 unsigned char e_ident[16] = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00};
                 Elf64_Half    e_type      = 0x0003;
                 Elf64_Half    e_machine   = 0x003e;
                 Elf64_Word    e_version   = 0x1  ;
                 Elf64_Addr    e_entry     = 0x21e0;
                 Elf64_Off     e_phoff     = 0x40;
                 Elf64_Off     e_shoff     = 0xe868;
                 Elf64_Word    e_flags     = 0x0  ;
                 Elf64_Half    e_ehsize    = 0x0040;
                 Elf64_Half    e_phentsize = 0x0038;
                 Elf64_Half    e_phnum     = 0x000d;
                 Elf64_Half    e_shentsize = 0x0040;
                 Elf64_Half    e_shnum     = 0x0024;
                 Elf64_Half    e_shstrndx  = 0x0023;
        };
        No.[35]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55f0f34b99b8
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xe70b;
             Elf64_Xword   sh_size      = 0x15a;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x0055f0f34b8f9b|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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

  >> func{parse_elf64_sect_headers:(00437)} is call .
  >> func{parse_elf64_sect_headers:(00454)} is call .


----------------------------------------------------------------
Section Headers:  
  [Nr] Name            Type      Address     Offset  Size    EntSize Flags  Link   Info   Align
  [00]                 00000000  0000000000  000000  000000  000000  0x0000 0x0000 0x0000 0x0000
  [01] .interp         00000001  0000000318  000792  000028  000000  0x0002 0x0000 0x0000 0x0001
  [02] .note.gnu.prope 00000007  0000000338  000824  000032  000000  0x0002 0x0000 0x0000 0x0008
  [03] .note.gnu.build 00000007  0000000358  000856  000036  000000  0x0002 0x0000 0x0000 0x0004
  [04] .note.ABI-tag   00000007  000000037c  000892  000032  000000  0x0002 0x0000 0x0000 0x0004
  [05] .gnu.hash       6ffffff6  00000003a0  000928  000040  000000  0x0002 0x0006 0x0000 0x0008
  [06] .dynsym         0000000b  00000003c8  000968  000480  000024  0x0002 0x0007 0x0001 0x0008
  [07] .dynstr         00000003  00000005a8  001448  000258  000000  0x0002 0x0000 0x0000 0x0001
  [08] .gnu.version    6fffffff  00000006aa  001706  000040  000002  0x0002 0x0006 0x0000 0x0002
  [09] .gnu.version_r  6ffffffe  00000006d8  001752  000064  000000  0x0002 0x0007 0x0001 0x0008
  [10] .rela.dyn       00000004  0000000718  001816  002088  000024  0x0002 0x0006 0x0000 0x0008
  [11] .rela.plt       00000004  0000000f40  003904  000312  000024  0x0042 0x0006 0x0018 0x0008
  [12] .init           00000001  0000002000  008192  000027  000000  0x0006 0x0000 0x0000 0x0004
  [13] .plt            00000001  0000002020  008224  000224  000016  0x0006 0x0000 0x0000 0x0010
  [14] .plt.got        00000001  0000002100  008448  000016  000016  0x0006 0x0000 0x0000 0x0010
  [15] .plt.sec        00000001  0000002110  008464  000208  000016  0x0006 0x0000 0x0000 0x0010
  [16] .text           00000001  00000021e0  008672  010756  000000  0x0006 0x0000 0x0000 0x0010
  [17] .fini           00000001  0000004be4  019428  000013  000000  0x0006 0x0000 0x0000 0x0004
  [18] .rodata         00000001  0000005000  020480  005819  000000  0x0002 0x0000 0x0000 0x0010
  [19] .eh_frame_hdr   00000001  00000066bc  026300  000604  000000  0x0002 0x0000 0x0000 0x0004
  [20] .eh_frame       00000001  0000006918  026904  002408  000000  0x0002 0x0000 0x0000 0x0008
  [21] .init_array     0000000e  0000008d18  032024  000040  000008  0x0003 0x0000 0x0000 0x0008
  [22] .fini_array     0000000f  0000008d40  032064  000040  000008  0x0003 0x0000 0x0000 0x0008
  [23] .dynamic        00000006  0000008d68  032104  000496  000016  0x0003 0x0007 0x0000 0x0008
  [24] .got            00000001  0000008f58  032600  000168  000008  0x0003 0x0000 0x0000 0x0008
  [25] .data           00000001  0000009000  032768  000624  000000  0x0003 0x0000 0x0000 0x0020
  [26] .bss            00000008  0000009270  033392  000016  000000  0x0003 0x0000 0x0000 0x0008
  [27] .comment        00000001  0000000000  033392  000043  000001  0x0030 0x0000 0x0000 0x0001
  [28] .debug_aranges  00000001  0000000000  033435  000048  000000  0x0000 0x0000 0x0000 0x0001
  [29] .debug_info     00000001  0000000000  033483  010822  000000  0x0000 0x0000 0x0000 0x0001
  [30] .debug_abbrev   00000001  0000000000  044305  000670  000000  0x0000 0x0000 0x0000 0x0001
  [31] .debug_line     00000001  0000000000  044975  003285  000000  0x0000 0x0000 0x0000 0x0001
  [32] .debug_str      00000001  0000000000  048260  003246  000001  0x0030 0x0000 0x0000 0x0001
  [33] .symtab         00000002  0000000000  051512  004920  000024  0x0000 0x0022 0x0069 0x0008
  [34] .strtab         00000003  0000000000  056432  002715  000000  0x0000 0x0000 0x0000 0x0001
  [35] .shstrtab       00000003  0000000000  059147  000346  000000  0x0000 0x0000 0x0000 0x0001
----------------------------------------------------------------
  >> func{parse_elf64_sect_headers:(00477)} is call .
  >> func{parse_elf64_prog_headers:(00512)} is call .

    ----------------------------------------------------------------
    Program Headers:
    [No] Type     Offset   VirtAddr   PhysAddr   FileSiz  MemSiz   Flags    Align
    [00] 00000006 00000040 0000000040 0000000040 0x0002d8 0x0002d8 0x000004 0x000008
    [01] 00000003 00000318 0000000318 0000000318 0x00001c 0x00001c 0x000004 0x000001
    [02] 00000001 00000000 0000000000 0000000000 0x001078 0x001078 0x000004 0x001000
    [03] 00000001 00002000 0000002000 0000002000 0x002bf1 0x002bf1 0x000005 0x001000
    [04] 00000001 00005000 0000005000 0000005000 0x002280 0x002280 0x000004 0x001000
    [05] 00000001 00007d18 0000008d18 0000008d18 0x000558 0x000568 0x000006 0x001000
    [06] 00000002 00007d68 0000008d68 0000008d68 0x0001f0 0x0001f0 0x000006 0x000008
    [07] 00000004 00000338 0000000338 0000000338 0x000020 0x000020 0x000004 0x000008
    [08] 00000004 00000358 0000000358 0000000358 0x000044 0x000044 0x000004 0x000004
    [09] 6474e553 00000338 0000000338 0000000338 0x000020 0x000020 0x000004 0x000008
    [10] 6474e550 000066bc 00000066bc 00000066bc 0x00025c 0x00025c 0x000004 0x000004
    [11] 6474e551 00000000 0000000000 0000000000 0x000000 0x000000 0x000006 0x000010
    [12] 6474e552 00007d18 0000008d18 0000008d18 0x0002e8 0x0002e8 0x000004 0x000001
    ----------------------------------------------------------------
  >> func{parse_elf64_sect_bodys:(00871)} is call .
  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=00,sect_name="",pSectData=0x55f0f34aa890,iLen=0x0}
    >> func{func_process:(00828)} is call .
      >>> {idx=0, name="", pData=0x55f0f34aa890, iLen=0, pSectHeader=0x55f0f34b90f8}.

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=01,sect_name=".interp",pSectData=0x55f0f34aaba8,iLen=0x1c}
    >> func{func_sect_interp:(00638)} is call .
        No.[01]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55f0f34b9138
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

0x0055f0f34aaba8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2f 6c 69 62 36 34 2f 6c  64 2d 6c 69 6e 75 78 2d|/lib64/ld-linux-|
      0x00000010|78 38 36 2d 36 34 2e 73  6f 2e 32 00 ** ** ** **|x86-64.so.2.****|
      =============================================================================

      ------------------------------------------------------------
      /lib64/ld-linux-x86-64.so.2
      ------------------------------------------------------------

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=02,sect_name=".note.gnu.property",pSectData=0x55f0f34aabc8,iLen=0x20}
    >> func{func_process:(00828)} is call .
      >>> {idx=2, name=".note.gnu.property", pData=0x55f0f34aabc8, iLen=32, pSectHeader=0x55f0f34b9178}.

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=03,sect_name=".note.gnu.build-id",pSectData=0x55f0f34aabe8,iLen=0x24}
    >> func{func_sect_note_gnu_build_id:(00600)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=04,sect_name=".note.ABI-tag",pSectData=0x55f0f34aac0c,iLen=0x20}
    >> func{func_sect_note_ABI_tag:(00599)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=05,sect_name=".gnu.hash",pSectData=0x55f0f34aac30,iLen=0x28}
    >> func{func_sect_gnu_hash:(00601)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=06,sect_name=".dynsym",pSectData=0x55f0f34aac58,iLen=0x1e0}
    >> func{func_sect_dynsym:(00602)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=07,sect_name=".dynstr",pSectData=0x55f0f34aae38,iLen=0x102}
    >> func{func_sect_dynstr:(00698)} is call .
        No.[07]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55f0f34b92b8
        {
             Elf64_Word    sh_name      = 0x69;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x2;
             Elf64_Addr    sh_addr      = 0x5a8;
             Elf64_Off     sh_offset    = 0x5a8;
             Elf64_Xword   sh_size      = 0x102;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x0055f0f34aae38|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|00 6c 69 62 63 2e 73 6f  2e 36 00 66 66 6c 75 73|.libc.so.6.fflus|
      0x00000010|68 00 66 6f 70 65 6e 00  5f 5f 73 74 61 63 6b 5f|h.fopen.__stack_|
      0x00000020|63 68 6b 5f 66 61 69 6c  00 5f 5f 61 73 73 65 72|chk_fail.__asser|
      0x00000030|74 5f 66 61 69 6c 00 63  61 6c 6c 6f 63 00 73 74|t_fail.calloc.st|
      0x00000040|64 6f 75 74 00 66 63 6c  6f 73 65 00 76 70 72 69|dout.fclose.vpri|
      0x00000050|6e 74 66 00 5f 5f 63 74  79 70 65 5f 62 5f 6c 6f|ntf.__ctype_b_lo|
      0x00000060|63 00 66 72 65 61 64 00  5f 5f 63 78 61 5f 66 69|c.fread.__cxa_fi|
      0x00000070|6e 61 6c 69 7a 65 00 73  74 72 63 6d 70 00 5f 5f|nalize.strcmp.__|
      0x00000080|6c 69 62 63 5f 73 74 61  72 74 5f 6d 61 69 6e 00|libc_start_main.|
      0x00000090|66 72 65 65 00 5f 5f 78  73 74 61 74 00 47 4c 49|free.__xstat.GLI|
      0x000000a0|42 43 5f 32 2e 33 00 47  4c 49 42 43 5f 32 2e 34|BC_2.3.GLIBC_2.4|
      0x000000b0|00 47 4c 49 42 43 5f 32  2e 32 2e 35 00 5f 49 54|.GLIBC_2.2.5._IT|
      0x000000c0|4d 5f 64 65 72 65 67 69  73 74 65 72 54 4d 43 6c|M_deregisterTMCl|
      0x000000d0|6f 6e 65 54 61 62 6c 65  00 5f 5f 67 6d 6f 6e 5f|oneTable.__gmon_|
      0x000000e0|73 74 61 72 74 5f 5f 00  5f 49 54 4d 5f 72 65 67|start__._ITM_reg|
      0x000000f0|69 73 74 65 72 54 4d 43  6c 6f 6e 65 54 61 62 6c|isterTMCloneTabl|
      0x00000100|65 00 ** ** ** ** ** **  ** ** ** ** ** ** ** **|e.**************|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x0055f0f34aae39; str={"libc.so.6"};
      >> ptr[001]=0x0055f0f34aae43; str={"fflush"};
      >> ptr[002]=0x0055f0f34aae4a; str={"fopen"};
      >> ptr[003]=0x0055f0f34aae50; str={"__stack_chk_fail"};
      >> ptr[004]=0x0055f0f34aae61; str={"__assert_fail"};
      >> ptr[005]=0x0055f0f34aae6f; str={"calloc"};
      >> ptr[006]=0x0055f0f34aae76; str={"stdout"};
      >> ptr[007]=0x0055f0f34aae7d; str={"fclose"};
      >> ptr[008]=0x0055f0f34aae84; str={"vprintf"};
      >> ptr[009]=0x0055f0f34aae8c; str={"__ctype_b_loc"};
      >> ptr[010]=0x0055f0f34aae9a; str={"fread"};
      >> ptr[011]=0x0055f0f34aaea0; str={"__cxa_finalize"};
      >> ptr[012]=0x0055f0f34aaeaf; str={"strcmp"};
      >> ptr[013]=0x0055f0f34aaeb6; str={"__libc_start_main"};
      >> ptr[014]=0x0055f0f34aaec8; str={"free"};
      >> ptr[015]=0x0055f0f34aaecd; str={"__xstat"};
      >> ptr[016]=0x0055f0f34aaed5; str={"GLIBC_2.3"};
      >> ptr[017]=0x0055f0f34aaedf; str={"GLIBC_2.4"};
      >> ptr[018]=0x0055f0f34aaee9; str={"GLIBC_2.2.5"};
      >> ptr[019]=0x0055f0f34aaef5; str={"_ITM_deregisterTMCloneTable"};
      >> ptr[020]=0x0055f0f34aaf11; str={"__gmon_start__"};
      >> ptr[021]=0x0055f0f34aaf20; str={"_ITM_registerTMCloneTable"};
      >> ptr[022]=0x0055f0f34aaf3c; str={""};
      ===========================================================


  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=08,sect_name=".gnu.version",pSectData=0x55f0f34aaf3a,iLen=0x28}
    >> func{func_sect_gnu_version:(00604)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=09,sect_name=".gnu.version_r",pSectData=0x55f0f34aaf68,iLen=0x40}
    >> func{func_sect_gnu_version_r:(00605)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=10,sect_name=".rela.dyn",pSectData=0x55f0f34aafa8,iLen=0x828}
    >> func{func_sect_rela_dyn:(00606)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=11,sect_name=".rela.plt",pSectData=0x55f0f34ab7d0,iLen=0x138}
    >> func{func_sect_rela_plt:(00607)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=12,sect_name=".init",pSectData=0x55f0f34ac890,iLen=0x1b}
    >> func{func_sect_init:(00608)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=13,sect_name=".plt",pSectData=0x55f0f34ac8b0,iLen=0xe0}
    >> func{func_sect_plt:(00609)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=14,sect_name=".plt.got",pSectData=0x55f0f34ac990,iLen=0x10}
    >> func{func_sect_plt_got:(00610)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=15,sect_name=".plt.sec",pSectData=0x55f0f34ac9a0,iLen=0xd0}
    >> func{func_process:(00828)} is call .
      >>> {idx=15, name=".plt.sec", pData=0x55f0f34ac9a0, iLen=208, pSectHeader=0x55f0f34b94b8}.

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=16,sect_name=".text",pSectData=0x55f0f34aca70,iLen=0x2a04}
    >> func{func_sect_text:(00611)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=17,sect_name=".fini",pSectData=0x55f0f34af474,iLen=0xd}
    >> func{func_sect_fini:(00612)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=18,sect_name=".rodata",pSectData=0x55f0f34af890,iLen=0x16bb}
    >> func{func_sect_rodata:(00613)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=19,sect_name=".eh_frame_hdr",pSectData=0x55f0f34b0f4c,iLen=0x25c}
    >> func{func_sect_eh_frame_hdr:(00614)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=20,sect_name=".eh_frame",pSectData=0x55f0f34b11a8,iLen=0x968}
    >> func{func_sect_eh_frame:(00615)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=21,sect_name=".init_array",pSectData=0x55f0f34b25a8,iLen=0x28}
    >> func{func_sect_init_array:(00616)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=22,sect_name=".fini_array",pSectData=0x55f0f34b25d0,iLen=0x28}
    >> func{func_sect_fini_array:(00617)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=23,sect_name=".dynamic",pSectData=0x55f0f34b25f8,iLen=0x1f0}
    >> func{func_sect_dynamic:(00618)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=24,sect_name=".got",pSectData=0x55f0f34b27e8,iLen=0xa8}
    >> func{func_sect_got:(00619)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=25,sect_name=".data",pSectData=0x55f0f34b2890,iLen=0x270}
    >> func{func_sect_data:(00621)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=26,sect_name=".bss",pSectData=0x55f0f34b2b00,iLen=0x10}
    >> func{func_sect_bss:(00622)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=27,sect_name=".comment",pSectData=0x55f0f34b2b00,iLen=0x2b}
    >> func{func_sect_comment:(00623)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=28,sect_name=".debug_aranges",pSectData=0x55f0f34b2b2b,iLen=0x30}
    >> func{func_sect_debug_aranges:(00624)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=29,sect_name=".debug_info",pSectData=0x55f0f34b2b5b,iLen=0x2a46}
    >> func{func_sect_debug_info:(00625)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=30,sect_name=".debug_abbrev",pSectData=0x55f0f34b55a1,iLen=0x29e}
    >> func{func_sect_debug_abbrev:(00626)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=31,sect_name=".debug_line",pSectData=0x55f0f34b583f,iLen=0xcd5}
    >> func{func_sect_debug_line:(00627)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=32,sect_name=".debug_str",pSectData=0x55f0f34b6514,iLen=0xcae}
    >> func{func_sect_debug_str:(00736)} is call .
        No.[32]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55f0f34b98f8
        {
             Elf64_Word    sh_name      = 0x14f;
             Elf64_Word    sh_type      = 0x1;
             Elf64_Xword   sh_flags     = 0x30;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xbc84;
             Elf64_Xword   sh_size      = 0xcae;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x1;
        }

0x0055f0f34b6514|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|5f 5f 6f 66 66 5f 74 00  5f 5f 67 69 64 5f 74 00|__off_t.__gid_t.|
      0x00000010|73 68 5f 61 64 64 72 61  6c 69 67 6e 00 5f 49 4f|sh_addralign._IO|
      0x00000020|5f 72 65 61 64 5f 70 74  72 00 5f 63 68 61 69 6e|_read_ptr._chain|
      0x00000030|00 67 65 74 5f 65 6c 66  36 34 5f 64 61 74 61 00|.get_elf64_data.|
      0x00000040|70 5f 76 61 64 64 72 00  78 6c 6f 67 5f 69 6e 66|p_vaddr.xlog_inf|
      0x00000050|6f 5f 78 00 69 50 74 72  4d 61 78 43 6e 74 00 66|o_x.iPtrMaxCnt.f|
      0x00000060|75 6e 63 5f 73 65 63 74  5f 72 6f 64 61 74 61 00|unc_sect_rodata.|
      0x00000070|5f 73 68 6f 72 74 62 75  66 00 45 6c 66 36 34 5f|_shortbuf.Elf64_|
      0x00000080|4f 66 66 00 5f 49 53 67  72 61 70 68 00 73 68 5f|Off._ISgraph.sh_|
      0x00000090|65 6e 74 73 69 7a 65 00  78 6c 6f 67 5f 68 65 78|entsize.xlog_hex|
      0x000000a0|64 75 6d 70 00 67 70 5f  6f 66 66 73 65 74 00 5f|dump.gp_offset._|
      0x000000b0|49 53 73 70 61 63 65 00  61 66 74 65 72 5f 6d 61|ISspace.after_ma|
      0x000000c0|69 6e 5f 66 75 6e 63 00  5f 49 4f 5f 62 75 66 5f|in_func._IO_buf_|
      0x000000d0|62 61 73 65 00 65 5f 74  79 70 65 00 65 5f 65 6e|base.e_type.e_en|
      0x000000e0|74 72 79 00 6c 6f 6e 67  20 6c 6f 6e 67 20 75 6e|try.long long un|
      0x000000f0|73 69 67 6e 65 64 20 69  6e 74 00 73 74 5f 62 6c|signed int.st_bl|
      0x00000100|6f 63 6b 73 00 73 68 5f  73 69 7a 65 00 6d 79 5f|ocks.sh_size.my_|
      0x00000110|69 6e 69 74 30 33 00 73  74 61 74 62 75 66 00 73|init03.statbuf.s|
      0x00000120|68 5f 61 64 64 72 00 66  75 6e 63 5f 73 65 63 74|h_addr.func_sect|
      0x00000130|5f 70 6c 74 00 53 5f 45  4c 46 36 34 5f 50 72 6f|_plt.S_ELF64_Pro|
      0x00000140|67 48 65 61 64 65 72 5f  74 00 5f 5f 66 75 6e 63|gHeader_t.__func|
      0x00000150|5f 5f 00 78 6c 6f 67 5f  63 6f 72 65 00 5f 49 53|__.xlog_core._IS|
      0x00000160|61 6c 70 68 61 00 5f 49  53 64 69 67 69 74 00 45|alpha._ISdigit.E|
      0x00000170|6c 66 48 65 61 64 65 72  4f 62 6a 00 65 5f 73 68|lfHeaderObj.e_sh|
      0x00000180|6e 75 6d 00 73 74 61 74  00 6c 6f 6e 67 20 6c 6f|num.stat.long lo|
      0x00000190|6e 67 20 69 6e 74 00 66  75 6e 63 5f 73 65 63 74|ng int.func_sect|
      0x000001a0|5f 64 65 62 75 67 5f 73  74 72 00 70 5f 66 69 6c|_debug_str.p_fil|
      0x000001b0|65 73 7a 00 73 74 5f 69  6e 6f 00 5f 5f 6d 6f 64|esz.st_ino.__mod|
      0x000001c0|65 5f 74 00 75 69 5f 6c  65 76 65 6c 00 70 50 72|e_t.ui_level.pPr|
      0x000001d0|6f 67 48 65 61 64 65 72  44 61 74 61 00 5f 66 69|ogHeaderData._fi|
      0x000001e0|6c 65 6e 6f 00 5f 49 4f  5f 72 65 61 64 5f 65 6e|leno._IO_read_en|
      0x000001f0|64 00 66 75 6e 63 5f 73  65 63 74 5f 6e 6f 74 65|d.func_sect_note|
      0x00000200|5f 67 6e 75 5f 62 75 69  6c 64 5f 69 64 00 5f 5f|_gnu_build_id.__|
      0x00000210|62 6c 6b 63 6e 74 5f 74  00 66 75 6e 63 5f 73 65|blkcnt_t.func_se|
      0x00000220|63 74 5f 63 6f 6d 6d 65  6e 74 00 68 46 69 6c 65|ct_comment.hFile|
      0x00000230|00 66 75 6e 63 5f 73 65  63 74 5f 73 68 73 74 72|.func_sect_shstr|
      0x00000240|74 61 62 00 5f 5f 62 75  69 6c 74 69 6e 5f 76 61|tab.__builtin_va|
      0x00000250|5f 6c 69 73 74 00 5f 49  4f 5f 62 75 66 5f 65 6e|_list._IO_buf_en|
      0x00000260|64 00 5f 63 75 72 5f 63  6f 6c 75 6d 6e 00 69 72|d._cur_column.ir|
      0x00000270|65 74 00 70 53 48 4e 61  6d 65 00 5f 49 4f 5f 63|et.pSHName._IO_c|
      0x00000280|6f 64 65 63 76 74 00 78  6c 6f 67 5f 69 6e 66 6f|odecvt.xlog_info|
      0x00000290|00 78 6c 6f 67 5f 6d 75  74 65 78 5f 75 6e 6c 6f|.xlog_mutex_unlo|
      0x000002a0|63 6b 00 6d 79 5f 66 69  6e 69 30 31 00 6d 79 5f|ck.my_fini01.my_|
      0x000002b0|66 69 6e 69 30 32 00 6d  79 5f 66 69 6e 69 30 33|fini02.my_fini03|
      0x000002c0|00 66 75 6e 63 5f 73 65  63 74 5f 73 74 72 74 61|.func_sect_strta|
      0x000002d0|62 00 66 75 6e 63 5f 73  65 63 74 5f 6e 6f 74 65|b.func_sect_note|
      0x000002e0|5f 67 6e 75 5f 62 75 69  6c 64 00 5f 6f 6c 64 5f|_gnu_build._old_|
      0x000002f0|6f 66 66 73 65 74 00 70  5f 70 61 64 64 72 00 66|offset.p_paddr.f|
      0x00000300|75 6e 63 5f 73 65 63 74  5f 66 69 6e 69 00 70 4e|unc_sect_fini.pN|
      0x00000310|61 6d 65 00 66 75 6e 63  5f 73 65 63 74 5f 69 6e|ame.func_sect_in|
      0x00000320|69 74 5f 61 72 72 61 79  00 45 6c 66 36 34 5f 57|it_array.Elf64_W|
      0x00000330|6f 72 64 00 5f 49 53 62  6c 61 6e 6b 00 70 44 61|ord._ISblank.pDa|
      0x00000340|74 61 00 5f 5f 70 61 64  30 00 70 5f 6d 65 6d 73|ta.__pad0.p_mems|
      0x00000350|7a 00 70 53 65 63 74 4e  61 6d 65 73 00 70 61 72|z.pSectNames.par|
      0x00000360|73 65 5f 65 6c 66 36 34  5f 73 65 63 74 5f 68 65|se_elf64_sect_he|
      0x00000370|61 64 65 72 00 50 72 6f  67 48 65 61 64 65 72 4f|ader.ProgHeaderO|
      0x00000380|62 6a 73 00 73 68 5f 6c  69 6e 6b 00 5f 49 53 70|bjs.sh_link._ISp|
      0x00000390|75 6e 63 74 00 5f 5f 64  65 76 5f 74 00 73 74 5f|unct.__dev_t.st_|
      0x000003a0|75 69 64 00 5f 49 4f 5f  6d 61 72 6b 65 72 00 73|uid._IO_marker.s|
      0x000003b0|74 64 69 6e 00 70 61 72  73 65 5f 65 6c 66 36 34|tdin.parse_elf64|
      0x000003c0|5f 73 65 63 74 5f 68 65  61 64 65 72 73 00 70 5f|_sect_headers.p_|
      0x000003d0|74 79 70 65 00 66 75 6e  63 5f 73 65 63 74 5f 66|type.func_sect_f|
      0x000003e0|69 6e 69 5f 61 72 72 61  79 00 5f 66 72 65 65 72|ini_array._freer|
      0x000003f0|65 73 5f 62 75 66 00 65  5f 70 68 65 6e 74 73 69|es_buf.e_phentsi|
      0x00000400|7a 65 00 6f 76 65 72 66  6c 6f 77 5f 61 72 67 5f|ze.overflow_arg_|
      0x00000410|61 72 65 61 00 50 72 74  50 72 6f 67 48 65 61 64|area.PrtProgHead|
      0x00000420|65 72 00 53 65 63 74 48  65 61 64 65 72 4f 62 6a|er.SectHeaderObj|
      0x00000430|73 00 5f 49 4f 5f 77 72  69 74 65 5f 70 74 72 00|s._IO_write_ptr.|
      0x00000440|70 61 72 73 65 5f 65 6c  66 36 34 5f 70 72 6f 67|parse_elf64_prog|
      0x00000450|5f 68 65 61 64 65 72 73  00 65 5f 73 68 73 74 72|_headers.e_shstr|
      0x00000460|6e 64 78 00 66 75 6e 63  5f 73 65 63 74 5f 72 65|ndx.func_sect_re|
      0x00000470|6c 61 5f 64 79 6e 00 53  5f 45 4c 46 36 34 5f 53|la_dyn.S_ELF64_S|
      0x00000480|65 63 74 48 65 61 64 65  72 5f 74 00 73 68 5f 6e|ectHeader_t.sh_n|
      0x00000490|61 6d 65 00 66 75 6e 63  5f 73 65 63 74 5f 69 6e|ame.func_sect_in|
      0x000004a0|69 74 00 66 75 6e 63 5f  73 65 63 74 5f 67 6e 75|it.func_sect_gnu|
      0x000004b0|5f 68 61 73 68 00 73 68  6f 72 74 20 75 6e 73 69|_hash.short unsi|
      0x000004c0|67 6e 65 64 20 69 6e 74  00 5f 49 4f 5f 77 69 64|gned int._IO_wid|
      0x000004d0|65 5f 64 61 74 61 00 66  75 6e 63 5f 73 65 63 74|e_data.func_sect|
      0x000004e0|5f 65 68 5f 66 72 61 6d  65 5f 68 64 72 00 70 53|_eh_frame_hdr.pS|
      0x000004f0|65 63 74 4e 61 6d 65 00  66 75 6e 63 5f 73 65 63|ectName.func_sec|
      0x00000500|74 5f 64 61 74 61 00 45  6c 66 36 34 5f 58 77 6f|t_data.Elf64_Xwo|
      0x00000510|72 64 00 5f 49 4f 5f 73  61 76 65 5f 62 61 73 65|rd._IO_save_base|
      0x00000520|00 70 53 65 63 74 44 61  74 61 00 5f 5f 6e 6c 69|.pSectData.__nli|
      0x00000530|6e 6b 5f 74 00 66 75 6e  63 5f 73 65 63 74 5f 70|nk_t.func_sect_p|
      0x00000540|6c 74 5f 67 6f 74 00 66  75 6e 63 5f 73 65 63 74|lt_got.func_sect|
      0x00000550|5f 64 65 62 75 67 5f 61  62 62 72 65 76 00 62 75|_debug_abbrev.bu|
      0x00000560|69 6c 64 5f 65 6c 66 36  34 5f 6f 62 6a 00 78 6c|ild_elf64_obj.xl|
      0x00000570|6f 67 5f 6d 75 74 65 78  5f 6c 6f 63 6b 00 70 44|og_mutex_lock.pD|
      0x00000580|61 74 61 53 74 61 72 74  00 69 5f 72 6f 77 00 65|ataStart.i_row.e|
      0x00000590|5f 6d 61 63 68 69 6e 65  00 5f 66 6c 61 67 73 32|_machine._flags2|
      0x000005a0|00 73 74 5f 63 74 69 6d  65 6e 73 65 63 00 73 74|.st_ctimensec.st|
      0x000005b0|64 6f 75 74 00 66 75 6e  63 5f 73 65 63 74 5f 67|dout.func_sect_g|
      0x000005c0|6f 74 00 70 61 72 73 65  5f 65 6c 66 36 34 5f 73|ot.parse_elf64_s|
      0x000005d0|65 63 74 5f 62 6f 64 79  73 00 73 74 5f 73 69 7a|ect_bodys.st_siz|
      0x000005e0|65 00 66 75 6e 63 5f 73  65 63 74 5f 65 68 5f 66|e.func_sect_eh_f|
      0x000005f0|72 61 6d 65 00 70 70 53  65 63 74 48 65 61 64 65|rame.ppSectHeade|
      0x00000600|72 73 00 73 74 5f 6d 6f  64 65 00 44 75 6d 70 50|rs.st_mode.DumpP|
      0x00000610|74 72 32 53 74 72 00 70  53 65 63 74 48 65 61 64|tr2Str.pSectHead|
      0x00000620|65 72 00 2f 68 6f 6d 65  2f 78 61 64 6d 69 6e 2f|er./home/xadmin/|
      0x00000630|78 77 6b 73 2e 67 69 74  2e 31 2f 6d 79 72 65 61|xwks.git.1/myrea|
      0x00000640|64 65 6c 66 2d 63 31 31  00 66 75 6e 63 5f 73 65|delf-c11.func_se|
      0x00000650|63 74 5f 64 79 6e 61 6d  69 63 00 70 66 75 6e 63|ct_dynamic.pfunc|
      0x00000660|5f 70 72 6f 63 65 73 73  00 69 43 6e 74 00 69 5f|_process.iCnt.i_|
      0x00000670|65 6c 66 36 34 5f 6c 65  6e 00 65 5f 65 68 73 69|elf64_len.e_ehsi|
      0x00000680|7a 65 00 65 5f 69 64 65  6e 74 00 66 69 6c 65 6e|ze.e_ident.filen|
      0x00000690|61 6d 65 00 5f 5f 73 79  73 63 61 6c 6c 5f 73 6c|ame.__syscall_sl|
      0x000006a0|6f 6e 67 5f 74 00 5f 5f  67 6e 75 63 5f 76 61 5f|ong_t.__gnuc_va_|
      0x000006b0|6c 69 73 74 00 70 53 65  63 74 48 65 61 64 65 72|list.pSectHeader|
      0x000006c0|44 61 74 61 00 5f 49 4f  5f 77 72 69 74 65 5f 65|Data._IO_write_e|
      0x000006d0|6e 64 00 65 5f 76 65 72  73 69 6f 6e 00 69 4c 65|nd.e_version.iLe|
      0x000006e0|6e 00 70 5f 61 6c 69 67  6e 00 70 53 65 63 74 48|n.p_align.pSectH|
      0x000006f0|65 61 64 65 72 73 44 61  74 61 00 5f 5f 73 79 73|eadersData.__sys|
      0x00000700|63 61 6c 6c 5f 75 6c 6f  6e 67 5f 74 00 70 5f 65|call_ulong_t.p_e|
      0x00000710|6c 66 36 34 5f 64 61 74  61 00 5f 49 4f 5f 6c 6f|lf64_data._IO_lo|
      0x00000720|63 6b 5f 74 00 5f 49 4f  5f 46 49 4c 45 00 5f 5f|ck_t._IO_FILE.__|
      0x00000730|62 6c 6b 73 69 7a 65 5f  74 00 6d 79 72 65 61 64|blksize_t.myread|
      0x00000740|65 6c 66 2d 30 2e 31 2e  30 36 2e 63 00 66 75 6e|elf-0.1.06.c.fun|
      0x00000750|63 5f 73 65 63 74 5f 72  65 6c 61 5f 70 6c 74 00|c_sect_rela_plt.|
      0x00000760|73 5f 65 6c 66 36 34 5f  6f 62 6a 5f 74 00 70 5f|s_elf64_obj_t.p_|
      0x00000770|64 61 74 61 00 66 75 6e  63 5f 73 65 63 74 5f 69|data.func_sect_i|
      0x00000780|6e 74 65 72 70 00 6d 79  5f 69 6e 69 74 30 31 00|nterp.my_init01.|
      0x00000790|6d 79 5f 69 6e 69 74 30  32 00 70 5f 65 6c 66 36|my_init02.p_elf6|
      0x000007a0|34 5f 6f 62 6a 00 5f 6d  61 72 6b 65 72 73 00 70|4_obj._markers.p|
      0x000007b0|61 72 73 65 5f 61 72 67  73 00 70 61 72 73 65 5f|arse_args.parse_|
      0x000007c0|65 6c 66 36 34 5f 73 65  63 74 5f 62 6f 64 79 00|elf64_sect_body.|
      0x000007d0|53 5f 45 4c 46 36 34 5f  45 4c 46 48 65 61 64 65|S_ELF64_ELFHeade|
      0x000007e0|72 5f 74 00 5f 5f 67 6c  69 62 63 5f 72 65 73 65|r_t.__glibc_rese|
      0x000007f0|72 76 65 64 00 73 74 5f  6e 6c 69 6e 6b 00 66 75|rved.st_nlink.fu|
      0x00000800|6e 63 5f 73 65 63 74 5f  67 6e 75 5f 76 65 72 73|nc_sect_gnu_vers|
      0x00000810|69 6f 6e 00 66 75 6e 63  5f 73 65 63 74 5f 64 65|ion.func_sect_de|
      0x00000820|62 75 67 5f 69 6e 66 6f  00 75 6e 73 69 67 6e 65|bug_info.unsigne|
      0x00000830|64 20 63 68 61 72 00 65  5f 73 68 6f 66 66 00 66|d char.e_shoff.f|
      0x00000840|75 6e 63 5f 73 65 63 74  5f 6e 6f 74 65 5f 67 6e|unc_sect_note_gn|
      0x00000850|75 5f 70 72 6f 70 65 00  45 6c 66 36 34 5f 48 61|u_prope.Elf64_Ha|
      0x00000860|6c 66 00 73 68 6f 72 74  20 69 6e 74 00 47 4e 55|lf.short int.GNU|
      0x00000870|20 43 31 31 20 39 2e 34  2e 30 20 2d 6d 74 75 6e| C11 9.4.0 -mtun|
      0x00000880|65 3d 67 65 6e 65 72 69  63 20 2d 6d 61 72 63 68|e=generic -march|
      0x00000890|3d 78 38 36 2d 36 34 20  2d 67 20 2d 4f 30 20 2d|=x86-64 -g -O0 -|
      0x000008a0|73 74 64 3d 63 31 31 20  2d 66 61 73 79 6e 63 68|std=c11 -fasynch|
      0x000008b0|72 6f 6e 6f 75 73 2d 75  6e 77 69 6e 64 2d 74 61|ronous-unwind-ta|
      0x000008c0|62 6c 65 73 20 2d 66 73  74 61 63 6b 2d 70 72 6f|bles -fstack-pro|
      0x000008d0|74 65 63 74 6f 72 2d 73  74 72 6f 6e 67 20 2d 66|tector-strong -f|
      0x000008e0|73 74 61 63 6b 2d 63 6c  61 73 68 2d 70 72 6f 74|stack-clash-prot|
      0x000008f0|65 63 74 69 6f 6e 20 2d  66 63 66 2d 70 72 6f 74|ection -fcf-prot|
      0x00000900|65 63 74 69 6f 6e 00 73  74 5f 62 6c 6b 73 69 7a|ection.st_blksiz|
      0x00000910|65 00 73 68 5f 69 6e 66  6f 00 70 5f 66 6c 61 67|e.sh_info.p_flag|
      0x00000920|73 00 5f 76 74 61 62 6c  65 5f 6f 66 66 73 65 74|s._vtable_offset|
      0x00000930|00 73 74 5f 63 74 69 6d  65 00 70 70 50 72 6f 67|.st_ctime.ppProg|
      0x00000940|48 65 61 64 65 72 73 00  72 65 67 5f 73 61 76 65|Headers.reg_save|
      0x00000950|5f 61 72 65 61 00 70 50  72 6f 67 48 65 61 64 65|_area.pProgHeade|
      0x00000960|72 00 73 74 5f 6d 74 69  6d 65 6e 73 65 63 00 5f|r.st_mtimensec._|
      0x00000970|5f 69 6e 6f 5f 74 00 65  5f 66 6c 61 67 73 00 73|_ino_t.e_flags.s|
      0x00000980|65 63 74 5f 66 75 6e 63  73 00 70 45 6c 66 48 65|ect_funcs.pElfHe|
      0x00000990|61 64 65 72 00 75 69 6e  74 33 32 5f 74 00 70 53|ader.uint32_t.pS|
      0x000009a0|65 63 74 5f 53 68 53 74  72 54 61 62 5f 48 65 61|ect_ShStrTab_Hea|
      0x000009b0|64 65 72 00 78 6c 6f 67  5f 69 6e 69 74 00 73 74|der.xlog_init.st|
      0x000009c0|5f 72 64 65 76 00 73 74  5f 61 74 69 6d 65 00 66|_rdev.st_atime.f|
      0x000009d0|75 6e 63 5f 73 65 63 74  5f 67 6e 75 5f 76 65 72|unc_sect_gnu_ver|
      0x000009e0|73 69 6f 6e 5f 72 00 65  5f 70 68 6f 66 66 00 70|sion_r.e_phoff.p|
      0x000009f0|61 72 73 65 5f 65 6c 66  36 34 5f 65 6c 66 5f 68|arse_elf64_elf_h|
      0x00000a00|65 61 64 65 72 00 5f 49  53 63 6e 74 72 6c 00 73|eader._IScntrl.s|
      0x00000a10|68 5f 66 6c 61 67 73 00  66 75 6e 63 5f 73 65 63|h_flags.func_sec|
      0x00000a20|74 5f 74 65 78 74 00 73  68 5f 74 79 70 65 00 5f|t_text.sh_type._|
      0x00000a30|49 53 78 64 69 67 69 74  00 5f 49 53 6c 6f 77 65|ISxdigit._ISlowe|
      0x00000a40|72 00 65 5f 73 68 65 6e  74 73 69 7a 65 00 65 6c|r.e_shentsize.el|
      0x00000a50|66 36 34 5f 6f 62 6a 5f  73 69 7a 65 00 5f 5f 75|f64_obj_size.__u|
      0x00000a60|69 64 5f 74 00 5f 5f 6f  66 66 36 34 5f 74 00 66|id_t.__off64_t.f|
      0x00000a70|75 6e 63 5f 73 65 63 74  5f 64 65 62 75 67 5f 6c|unc_sect_debug_l|
      0x00000a80|69 6e 65 00 5f 49 4f 5f  72 65 61 64 5f 62 61 73|ine._IO_read_bas|
      0x00000a90|65 00 5f 49 4f 5f 73 61  76 65 5f 65 6e 64 00 70|e._IO_save_end.p|
      0x00000aa0|45 6c 66 44 61 74 61 00  66 75 6e 63 5f 73 65 63|ElfData.func_sec|
      0x00000ab0|74 5f 67 6f 74 5f 70 6c  74 00 70 61 72 73 65 5f|t_got_plt.parse_|
      0x00000ac0|65 6c 66 36 34 5f 70 72  6f 67 5f 68 65 61 64 65|elf64_prog_heade|
      0x00000ad0|72 00 45 6c 66 36 34 5f  41 64 64 72 00 73 74 5f|r.Elf64_Addr.st_|
      0x00000ae0|67 69 64 00 62 65 66 6f  72 65 5f 6d 61 69 6e 5f|gid.before_main_|
      0x00000af0|66 75 6e 63 00 66 75 6e  63 5f 73 65 63 74 5f 64|func.func_sect_d|
      0x00000b00|79 6e 73 79 6d 00 5f 5f  70 61 64 35 00 5f 5f 74|ynsym.__pad5.__t|
      0x00000b10|69 6d 65 5f 74 00 78 6c  6f 67 5f 75 6e 69 6e 69|ime_t.xlog_unini|
      0x00000b20|74 00 66 75 6e 63 5f 73  65 63 74 5f 6e 6f 74 65|t.func_sect_note|
      0x00000b30|5f 41 42 49 5f 74 61 67  00 5f 75 6e 75 73 65 64|_ABI_tag._unused|
      0x00000b40|32 00 73 74 64 65 72 72  00 61 72 67 76 00 5f 49|2.stderr.argv._I|
      0x00000b50|53 61 6c 6e 75 6d 00 66  75 6e 63 5f 73 65 63 74|Salnum.func_sect|
      0x00000b60|5f 64 65 62 75 67 5f 61  72 61 6e 67 65 73 00 73|_debug_aranges.s|
      0x00000b70|74 5f 64 65 76 00 5f 49  53 75 70 70 65 72 00 75|t_dev._ISupper.u|
      0x00000b80|69 6e 74 38 5f 74 00 73  74 5f 6d 74 69 6d 65 00|int8_t.st_mtime.|
      0x00000b90|5f 49 4f 5f 62 61 63 6b  75 70 5f 62 61 73 65 00|_IO_backup_base.|
      0x00000ba0|66 70 5f 6f 66 66 73 65  74 00 70 50 72 6f 67 48|fp_offset.pProgH|
      0x00000bb0|65 61 64 65 72 73 44 61  74 61 00 74 65 73 74 5f|eadersData.test_|
      0x00000bc0|63 68 61 72 00 73 74 5f  61 74 69 6d 65 6e 73 65|char.st_atimense|
      0x00000bd0|63 00 66 75 6e 63 5f 73  65 63 74 5f 64 79 6e 73|c.func_sect_dyns|
      0x00000be0|74 72 00 70 73 74 72 5f  6e 61 6d 65 00 66 75 6e|tr.pstr_name.fun|
      0x00000bf0|63 5f 73 65 63 74 5f 73  79 6d 74 61 62 00 61 72|c_sect_symtab.ar|
      0x00000c00|67 63 00 65 5f 70 68 6e  75 6d 00 5f 66 72 65 65|gc.e_phnum._free|
      0x00000c10|72 65 73 5f 6c 69 73 74  00 50 72 74 53 65 63 74|res_list.PrtSect|
      0x00000c20|48 65 61 64 65 72 00 53  5f 45 6c 66 36 34 5f 53|Header.S_Elf64_S|
      0x00000c30|65 63 74 46 75 6e 63 5f  74 00 6c 6f 67 5f 73 77|ectFunc_t.log_sw|
      0x00000c40|69 74 63 68 00 73 69 7a  65 5f 72 65 61 64 6f 6b|itch.size_readok|
      0x00000c50|00 5f 5f 50 52 45 54 54  59 5f 46 55 4e 43 54 49|.__PRETTY_FUNCTI|
      0x00000c60|4f 4e 5f 5f 00 73 68 5f  6f 66 66 73 65 74 00 69|ON__.sh_offset.i|
      0x00000c70|5f 6c 65 6e 00 6d 61 69  6e 00 5f 49 4f 5f 77 72|_len.main._IO_wr|
      0x00000c80|69 74 65 5f 62 61 73 65  00 5f 49 53 70 72 69 6e|ite_base._ISprin|
      0x00000c90|74 00 66 75 6e 63 5f 73  65 63 74 5f 62 73 73 00|t.func_sect_bss.|
      0x00000ca0|5f 5f 76 61 5f 6c 69 73  74 5f 74 61 67 00 ** **|__va_list_tag.**|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x0055f0f34b6514; str={"__off_t"};
      >> ptr[001]=0x0055f0f34b651c; str={"__gid_t"};
      >> ptr[002]=0x0055f0f34b6524; str={"sh_addralign"};
      >> ptr[003]=0x0055f0f34b6531; str={"_IO_read_ptr"};
      >> ptr[004]=0x0055f0f34b653e; str={"_chain"};
      >> ptr[005]=0x0055f0f34b6545; str={"get_elf64_data"};
      >> ptr[006]=0x0055f0f34b6554; str={"p_vaddr"};
      >> ptr[007]=0x0055f0f34b655c; str={"xlog_info_x"};
      >> ptr[008]=0x0055f0f34b6568; str={"iPtrMaxCnt"};
      >> ptr[009]=0x0055f0f34b6573; str={"func_sect_rodata"};
      >> ptr[010]=0x0055f0f34b6584; str={"_shortbuf"};
      >> ptr[011]=0x0055f0f34b658e; str={"Elf64_Off"};
      >> ptr[012]=0x0055f0f34b6598; str={"_ISgraph"};
      >> ptr[013]=0x0055f0f34b65a1; str={"sh_entsize"};
      >> ptr[014]=0x0055f0f34b65ac; str={"xlog_hexdump"};
      >> ptr[015]=0x0055f0f34b65b9; str={"gp_offset"};
      >> ptr[016]=0x0055f0f34b65c3; str={"_ISspace"};
      >> ptr[017]=0x0055f0f34b65cc; str={"after_main_func"};
      >> ptr[018]=0x0055f0f34b65dc; str={"_IO_buf_base"};
      >> ptr[019]=0x0055f0f34b65e9; str={"e_type"};
      >> ptr[020]=0x0055f0f34b65f0; str={"e_entry"};
      >> ptr[021]=0x0055f0f34b65f8; str={"long long unsigned int"};
      >> ptr[022]=0x0055f0f34b660f; str={"st_blocks"};
      >> ptr[023]=0x0055f0f34b6619; str={"sh_size"};
      >> ptr[024]=0x0055f0f34b6621; str={"my_init03"};
      >> ptr[025]=0x0055f0f34b662b; str={"statbuf"};
      >> ptr[026]=0x0055f0f34b6633; str={"sh_addr"};
      >> ptr[027]=0x0055f0f34b663b; str={"func_sect_plt"};
      >> ptr[028]=0x0055f0f34b6649; str={"S_ELF64_ProgHeader_t"};
      >> ptr[029]=0x0055f0f34b665e; str={"__func__"};
      >> ptr[030]=0x0055f0f34b6667; str={"xlog_core"};
      >> ptr[031]=0x0055f0f34b6671; str={"_ISalpha"};
      >> ptr[032]=0x0055f0f34b667a; str={"_ISdigit"};
      >> ptr[033]=0x0055f0f34b6683; str={"ElfHeaderObj"};
      >> ptr[034]=0x0055f0f34b6690; str={"e_shnum"};
      >> ptr[035]=0x0055f0f34b6698; str={"stat"};
      >> ptr[036]=0x0055f0f34b669d; str={"long long int"};
      >> ptr[037]=0x0055f0f34b66ab; str={"func_sect_debug_str"};
      >> ptr[038]=0x0055f0f34b66bf; str={"p_filesz"};
      >> ptr[039]=0x0055f0f34b66c8; str={"st_ino"};
      >> ptr[040]=0x0055f0f34b66cf; str={"__mode_t"};
      >> ptr[041]=0x0055f0f34b66d8; str={"ui_level"};
      >> ptr[042]=0x0055f0f34b66e1; str={"pProgHeaderData"};
      >> ptr[043]=0x0055f0f34b66f1; str={"_fileno"};
      >> ptr[044]=0x0055f0f34b66f9; str={"_IO_read_end"};
      >> ptr[045]=0x0055f0f34b6706; str={"func_sect_note_gnu_build_id"};
      >> ptr[046]=0x0055f0f34b6722; str={"__blkcnt_t"};
      >> ptr[047]=0x0055f0f34b672d; str={"func_sect_comment"};
      >> ptr[048]=0x0055f0f34b673f; str={"hFile"};
      >> ptr[049]=0x0055f0f34b6745; str={"func_sect_shstrtab"};
      >> ptr[050]=0x0055f0f34b6758; str={"__builtin_va_list"};
      >> ptr[051]=0x0055f0f34b676a; str={"_IO_buf_end"};
      >> ptr[052]=0x0055f0f34b6776; str={"_cur_column"};
      >> ptr[053]=0x0055f0f34b6782; str={"iret"};
      >> ptr[054]=0x0055f0f34b6787; str={"pSHName"};
      >> ptr[055]=0x0055f0f34b678f; str={"_IO_codecvt"};
      >> ptr[056]=0x0055f0f34b679b; str={"xlog_info"};
      >> ptr[057]=0x0055f0f34b67a5; str={"xlog_mutex_unlock"};
      >> ptr[058]=0x0055f0f34b67b7; str={"my_fini01"};
      >> ptr[059]=0x0055f0f34b67c1; str={"my_fini02"};
      >> ptr[060]=0x0055f0f34b67cb; str={"my_fini03"};
      >> ptr[061]=0x0055f0f34b67d5; str={"func_sect_strtab"};
      >> ptr[062]=0x0055f0f34b67e6; str={"func_sect_note_gnu_build"};
      >> ptr[063]=0x0055f0f34b67ff; str={"_old_offset"};
      >> ptr[064]=0x0055f0f34b680b; str={"p_paddr"};
      >> ptr[065]=0x0055f0f34b6813; str={"func_sect_fini"};
      >> ptr[066]=0x0055f0f34b6822; str={"pName"};
      >> ptr[067]=0x0055f0f34b6828; str={"func_sect_init_array"};
      >> ptr[068]=0x0055f0f34b683d; str={"Elf64_Word"};
      >> ptr[069]=0x0055f0f34b6848; str={"_ISblank"};
      >> ptr[070]=0x0055f0f34b6851; str={"pData"};
      >> ptr[071]=0x0055f0f34b6857; str={"__pad0"};
      >> ptr[072]=0x0055f0f34b685e; str={"p_memsz"};
      >> ptr[073]=0x0055f0f34b6866; str={"pSectNames"};
      >> ptr[074]=0x0055f0f34b6871; str={"parse_elf64_sect_header"};
      >> ptr[075]=0x0055f0f34b6889; str={"ProgHeaderObjs"};
      >> ptr[076]=0x0055f0f34b6898; str={"sh_link"};
      >> ptr[077]=0x0055f0f34b68a0; str={"_ISpunct"};
      >> ptr[078]=0x0055f0f34b68a9; str={"__dev_t"};
      >> ptr[079]=0x0055f0f34b68b1; str={"st_uid"};
      >> ptr[080]=0x0055f0f34b68b8; str={"_IO_marker"};
      >> ptr[081]=0x0055f0f34b68c3; str={"stdin"};
      >> ptr[082]=0x0055f0f34b68c9; str={"parse_elf64_sect_headers"};
      >> ptr[083]=0x0055f0f34b68e2; str={"p_type"};
      >> ptr[084]=0x0055f0f34b68e9; str={"func_sect_fini_array"};
      >> ptr[085]=0x0055f0f34b68fe; str={"_freeres_buf"};
      >> ptr[086]=0x0055f0f34b690b; str={"e_phentsize"};
      >> ptr[087]=0x0055f0f34b6917; str={"overflow_arg_area"};
      >> ptr[088]=0x0055f0f34b6929; str={"PrtProgHeader"};
      >> ptr[089]=0x0055f0f34b6937; str={"SectHeaderObjs"};
      >> ptr[090]=0x0055f0f34b6946; str={"_IO_write_ptr"};
      >> ptr[091]=0x0055f0f34b6954; str={"parse_elf64_prog_headers"};
      >> ptr[092]=0x0055f0f34b696d; str={"e_shstrndx"};
      >> ptr[093]=0x0055f0f34b6978; str={"func_sect_rela_dyn"};
      >> ptr[094]=0x0055f0f34b698b; str={"S_ELF64_SectHeader_t"};
      >> ptr[095]=0x0055f0f34b69a0; str={"sh_name"};
      >> ptr[096]=0x0055f0f34b69a8; str={"func_sect_init"};
      >> ptr[097]=0x0055f0f34b69b7; str={"func_sect_gnu_hash"};
      >> ptr[098]=0x0055f0f34b69ca; str={"short unsigned int"};
      >> ptr[099]=0x0055f0f34b69dd; str={"_IO_wide_data"};
      >> ptr[100]=0x0055f0f34b69eb; str={"func_sect_eh_frame_hdr"};
      >> ptr[101]=0x0055f0f34b6a02; str={"pSectName"};
      >> ptr[102]=0x0055f0f34b6a0c; str={"func_sect_data"};
      >> ptr[103]=0x0055f0f34b6a1b; str={"Elf64_Xword"};
      >> ptr[104]=0x0055f0f34b6a27; str={"_IO_save_base"};
      >> ptr[105]=0x0055f0f34b6a35; str={"pSectData"};
      >> ptr[106]=0x0055f0f34b6a3f; str={"__nlink_t"};
      >> ptr[107]=0x0055f0f34b6a49; str={"func_sect_plt_got"};
      >> ptr[108]=0x0055f0f34b6a5b; str={"func_sect_debug_abbrev"};
      >> ptr[109]=0x0055f0f34b6a72; str={"build_elf64_obj"};
      >> ptr[110]=0x0055f0f34b6a82; str={"xlog_mutex_lock"};
      >> ptr[111]=0x0055f0f34b6a92; str={"pDataStart"};
      >> ptr[112]=0x0055f0f34b6a9d; str={"i_row"};
      >> ptr[113]=0x0055f0f34b6aa3; str={"e_machine"};
      >> ptr[114]=0x0055f0f34b6aad; str={"_flags2"};
      >> ptr[115]=0x0055f0f34b6ab5; str={"st_ctimensec"};
      >> ptr[116]=0x0055f0f34b6ac2; str={"stdout"};
      >> ptr[117]=0x0055f0f34b6ac9; str={"func_sect_got"};
      >> ptr[118]=0x0055f0f34b6ad7; str={"parse_elf64_sect_bodys"};
      >> ptr[119]=0x0055f0f34b6aee; str={"st_size"};
      >> ptr[120]=0x0055f0f34b6af6; str={"func_sect_eh_frame"};
      >> ptr[121]=0x0055f0f34b6b09; str={"ppSectHeaders"};
      >> ptr[122]=0x0055f0f34b6b17; str={"st_mode"};
      >> ptr[123]=0x0055f0f34b6b1f; str={"DumpPtr2Str"};
      >> ptr[124]=0x0055f0f34b6b2b; str={"pSectHeader"};
      >> ptr[125]=0x0055f0f34b6b37; str={"/home/xadmin/xwks.git.1/myreadelf-c11"};
      >> ptr[126]=0x0055f0f34b6b5d; str={"func_sect_dynamic"};
      >> ptr[127]=0x0055f0f34b6b6f; str={"pfunc_process"};
      >> ptr[128]=0x0055f0f34b6b7d; str={"iCnt"};
      >> ptr[129]=0x0055f0f34b6b82; str={"i_elf64_len"};
      >> ptr[130]=0x0055f0f34b6b8e; str={"e_ehsize"};
      >> ptr[131]=0x0055f0f34b6b97; str={"e_ident"};
      >> ptr[132]=0x0055f0f34b6b9f; str={"filename"};
      >> ptr[133]=0x0055f0f34b6ba8; str={"__syscall_slong_t"};
      >> ptr[134]=0x0055f0f34b6bba; str={"__gnuc_va_list"};
      >> ptr[135]=0x0055f0f34b6bc9; str={"pSectHeaderData"};
      >> ptr[136]=0x0055f0f34b6bd9; str={"_IO_write_end"};
      >> ptr[137]=0x0055f0f34b6be7; str={"e_version"};
      >> ptr[138]=0x0055f0f34b6bf1; str={"iLen"};
      >> ptr[139]=0x0055f0f34b6bf6; str={"p_align"};
      >> ptr[140]=0x0055f0f34b6bfe; str={"pSectHeadersData"};
      >> ptr[141]=0x0055f0f34b6c0f; str={"__syscall_ulong_t"};
      >> ptr[142]=0x0055f0f34b6c21; str={"p_elf64_data"};
      >> ptr[143]=0x0055f0f34b6c2e; str={"_IO_lock_t"};
      >> ptr[144]=0x0055f0f34b6c39; str={"_IO_FILE"};
      >> ptr[145]=0x0055f0f34b6c42; str={"__blksize_t"};
      >> ptr[146]=0x0055f0f34b6c4e; str={"myreadelf-0.1.06.c"};
      >> ptr[147]=0x0055f0f34b6c61; str={"func_sect_rela_plt"};
      >> ptr[148]=0x0055f0f34b6c74; str={"s_elf64_obj_t"};
      >> ptr[149]=0x0055f0f34b6c82; str={"p_data"};
      >> ptr[150]=0x0055f0f34b6c89; str={"func_sect_interp"};
      >> ptr[151]=0x0055f0f34b6c9a; str={"my_init01"};
      >> ptr[152]=0x0055f0f34b6ca4; str={"my_init02"};
      >> ptr[153]=0x0055f0f34b6cae; str={"p_elf64_obj"};
      >> ptr[154]=0x0055f0f34b6cba; str={"_markers"};
      >> ptr[155]=0x0055f0f34b6cc3; str={"parse_args"};
      >> ptr[156]=0x0055f0f34b6cce; str={"parse_elf64_sect_body"};
      >> ptr[157]=0x0055f0f34b6ce4; str={"S_ELF64_ELFHeader_t"};
      >> ptr[158]=0x0055f0f34b6cf8; str={"__glibc_reserved"};
      >> ptr[159]=0x0055f0f34b6d09; str={"st_nlink"};
      >> ptr[160]=0x0055f0f34b6d12; str={"func_sect_gnu_version"};
      >> ptr[161]=0x0055f0f34b6d28; str={"func_sect_debug_info"};
      >> ptr[162]=0x0055f0f34b6d3d; str={"unsigned char"};
      >> ptr[163]=0x0055f0f34b6d4b; str={"e_shoff"};
      >> ptr[164]=0x0055f0f34b6d53; str={"func_sect_note_gnu_prope"};
      >> ptr[165]=0x0055f0f34b6d6c; str={"Elf64_Half"};
      >> ptr[166]=0x0055f0f34b6d77; str={"short int"};
      >> ptr[167]=0x0055f0f34b6d81; str={"GNU C11 9.4.0 -mtune=generic -march=x86-64 -g -O0 -std=c11 -fasynchronous-unwind-tables -fstack-protector-strong -fstack-clash-protection -fcf-protection"};
      >> ptr[168]=0x0055f0f34b6e1b; str={"st_blksize"};
      >> ptr[169]=0x0055f0f34b6e26; str={"sh_info"};
      >> ptr[170]=0x0055f0f34b6e2e; str={"p_flags"};
      >> ptr[171]=0x0055f0f34b6e36; str={"_vtable_offset"};
      >> ptr[172]=0x0055f0f34b6e45; str={"st_ctime"};
      >> ptr[173]=0x0055f0f34b6e4e; str={"ppProgHeaders"};
      >> ptr[174]=0x0055f0f34b6e5c; str={"reg_save_area"};
      >> ptr[175]=0x0055f0f34b6e6a; str={"pProgHeader"};
      >> ptr[176]=0x0055f0f34b6e76; str={"st_mtimensec"};
      >> ptr[177]=0x0055f0f34b6e83; str={"__ino_t"};
      >> ptr[178]=0x0055f0f34b6e8b; str={"e_flags"};
      >> ptr[179]=0x0055f0f34b6e93; str={"sect_funcs"};
      >> ptr[180]=0x0055f0f34b6e9e; str={"pElfHeader"};
      >> ptr[181]=0x0055f0f34b6ea9; str={"uint32_t"};
      >> ptr[182]=0x0055f0f34b6eb2; str={"pSect_ShStrTab_Header"};
      >> ptr[183]=0x0055f0f34b6ec8; str={"xlog_init"};
      >> ptr[184]=0x0055f0f34b6ed2; str={"st_rdev"};
      >> ptr[185]=0x0055f0f34b6eda; str={"st_atime"};
      >> ptr[186]=0x0055f0f34b6ee3; str={"func_sect_gnu_version_r"};
      >> ptr[187]=0x0055f0f34b6efb; str={"e_phoff"};
      >> ptr[188]=0x0055f0f34b6f03; str={"parse_elf64_elf_header"};
      >> ptr[189]=0x0055f0f34b6f1a; str={"_IScntrl"};
      >> ptr[190]=0x0055f0f34b6f23; str={"sh_flags"};
      >> ptr[191]=0x0055f0f34b6f2c; str={"func_sect_text"};
      >> ptr[192]=0x0055f0f34b6f3b; str={"sh_type"};
      >> ptr[193]=0x0055f0f34b6f43; str={"_ISxdigit"};
      >> ptr[194]=0x0055f0f34b6f4d; str={"_ISlower"};
      >> ptr[195]=0x0055f0f34b6f56; str={"e_shentsize"};
      >> ptr[196]=0x0055f0f34b6f62; str={"elf64_obj_size"};
      >> ptr[197]=0x0055f0f34b6f71; str={"__uid_t"};
      >> ptr[198]=0x0055f0f34b6f79; str={"__off64_t"};
      >> ptr[199]=0x0055f0f34b6f83; str={"func_sect_debug_line"};
      >> ptr[200]=0x0055f0f34b6f98; str={"_IO_read_base"};
      >> ptr[201]=0x0055f0f34b6fa6; str={"_IO_save_end"};
      >> ptr[202]=0x0055f0f34b6fb3; str={"pElfData"};
      >> ptr[203]=0x0055f0f34b6fbc; str={"func_sect_got_plt"};
      >> ptr[204]=0x0055f0f34b6fce; str={"parse_elf64_prog_header"};
      >> ptr[205]=0x0055f0f34b6fe6; str={"Elf64_Addr"};
      >> ptr[206]=0x0055f0f34b6ff1; str={"st_gid"};
      >> ptr[207]=0x0055f0f34b6ff8; str={"before_main_func"};
      >> ptr[208]=0x0055f0f34b7009; str={"func_sect_dynsym"};
      >> ptr[209]=0x0055f0f34b701a; str={"__pad5"};
      >> ptr[210]=0x0055f0f34b7021; str={"__time_t"};
      >> ptr[211]=0x0055f0f34b702a; str={"xlog_uninit"};
      >> ptr[212]=0x0055f0f34b7036; str={"func_sect_note_ABI_tag"};
      >> ptr[213]=0x0055f0f34b704d; str={"_unused2"};
      >> ptr[214]=0x0055f0f34b7056; str={"stderr"};
      >> ptr[215]=0x0055f0f34b705d; str={"argv"};
      >> ptr[216]=0x0055f0f34b7062; str={"_ISalnum"};
      >> ptr[217]=0x0055f0f34b706b; str={"func_sect_debug_aranges"};
      >> ptr[218]=0x0055f0f34b7083; str={"st_dev"};
      >> ptr[219]=0x0055f0f34b708a; str={"_ISupper"};
      >> ptr[220]=0x0055f0f34b7093; str={"uint8_t"};
      >> ptr[221]=0x0055f0f34b709b; str={"st_mtime"};
      >> ptr[222]=0x0055f0f34b70a4; str={"_IO_backup_base"};
      >> ptr[223]=0x0055f0f34b70b4; str={"fp_offset"};
      >> ptr[224]=0x0055f0f34b70be; str={"pProgHeadersData"};
      >> ptr[225]=0x0055f0f34b70cf; str={"test_char"};
      >> ptr[226]=0x0055f0f34b70d9; str={"st_atimensec"};
      >> ptr[227]=0x0055f0f34b70e6; str={"func_sect_dynstr"};
      >> ptr[228]=0x0055f0f34b70f7; str={"pstr_name"};
      >> ptr[229]=0x0055f0f34b7101; str={"func_sect_symtab"};
      >> ptr[230]=0x0055f0f34b7112; str={"argc"};
      >> ptr[231]=0x0055f0f34b7117; str={"e_phnum"};
      >> ptr[232]=0x0055f0f34b711f; str={"_freeres_list"};
      >> ptr[233]=0x0055f0f34b712d; str={"PrtSectHeader"};
      >> ptr[234]=0x0055f0f34b713b; str={"S_Elf64_SectFunc_t"};
      >> ptr[235]=0x0055f0f34b714e; str={"log_switch"};
      >> ptr[236]=0x0055f0f34b7159; str={"size_readok"};
      >> ptr[237]=0x0055f0f34b7165; str={"__PRETTY_FUNCTION__"};
      >> ptr[238]=0x0055f0f34b7179; str={"sh_offset"};
      >> ptr[239]=0x0055f0f34b7183; str={"i_len"};
      >> ptr[240]=0x0055f0f34b7189; str={"main"};
      >> ptr[241]=0x0055f0f34b718e; str={"_IO_write_base"};
      >> ptr[242]=0x0055f0f34b719d; str={"_ISprint"};
      >> ptr[243]=0x0055f0f34b71a6; str={"func_sect_bss"};
      >> ptr[244]=0x0055f0f34b71b4; str={"__va_list_tag"};
      >> ptr[245]=0x0055f0f34b71e4; str={""};
      ===========================================================


  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=33,sect_name=".symtab",pSectData=0x55f0f34b71c8,iLen=0x1338}
    >> func{func_sect_symtab:(00629)} is call .

  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=34,sect_name=".strtab",pSectData=0x55f0f34b8500,iLen=0xa9b}
    >> func{func_sect_strtab:(00751)} is call .
        No.[34]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55f0f34b9978
        {
             Elf64_Word    sh_name      = 0x9;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xdc70;
             Elf64_Xword   sh_size      = 0xa9b;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x0055f0f34b8500|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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
      0x000000a0|66 2d 30 2e 31 2e 30 36  2e 63 00 5f 5f 66 75 6e|f-0.1.06.c.__fun|
      0x000000b0|63 5f 5f 2e 32 34 38 31  00 5f 5f 66 75 6e 63 5f|c__.2481.__func_|
      0x000000c0|5f 2e 32 34 39 39 00 5f  5f 50 52 45 54 54 59 5f|_.2499.__PRETTY_|
      0x000000d0|46 55 4e 43 54 49 4f 4e  5f 5f 2e 32 35 30 33 00|FUNCTION__.2503.|
      0x000000e0|5f 5f 66 75 6e 63 5f 5f  2e 32 35 32 32 00 5f 5f|__func__.2522.__|
      0x000000f0|50 52 45 54 54 59 5f 46  55 4e 43 54 49 4f 4e 5f|PRETTY_FUNCTION_|
      0x00000100|5f 2e 32 35 32 36 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2526.__func__.|
      0x00000110|32 37 36 33 00 5f 5f 66  75 6e 63 5f 5f 2e 32 37|2763.__func__.27|
      0x00000120|37 31 00 5f 5f 66 75 6e  63 5f 5f 2e 32 37 37 39|71.__func__.2779|
      0x00000130|00 5f 5f 66 75 6e 63 5f  5f 2e 32 37 38 37 00 5f|.__func__.2787._|
      0x00000140|5f 66 75 6e 63 5f 5f 2e  32 37 39 35 00 5f 5f 66|_func__.2795.__f|
      0x00000150|75 6e 63 5f 5f 2e 32 38  30 33 00 5f 5f 66 75 6e|unc__.2803.__fun|
      0x00000160|63 5f 5f 2e 32 38 31 31  00 5f 5f 66 75 6e 63 5f|c__.2811.__func_|
      0x00000170|5f 2e 32 38 31 39 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2819.__func__.|
      0x00000180|32 38 32 37 00 5f 5f 66  75 6e 63 5f 5f 2e 32 38|2827.__func__.28|
      0x00000190|33 35 00 5f 5f 66 75 6e  63 5f 5f 2e 32 38 34 33|35.__func__.2843|
      0x000001a0|00 5f 5f 66 75 6e 63 5f  5f 2e 32 38 35 31 00 5f|.__func__.2851._|
      0x000001b0|5f 66 75 6e 63 5f 5f 2e  32 38 35 39 00 5f 5f 66|_func__.2859.__f|
      0x000001c0|75 6e 63 5f 5f 2e 32 38  36 37 00 5f 5f 66 75 6e|unc__.2867.__fun|
      0x000001d0|63 5f 5f 2e 32 38 37 35  00 5f 5f 66 75 6e 63 5f|c__.2875.__func_|
      0x000001e0|5f 2e 32 38 38 33 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2883.__func__.|
      0x000001f0|32 38 39 31 00 5f 5f 66  75 6e 63 5f 5f 2e 32 38|2891.__func__.28|
      0x00000200|39 39 00 5f 5f 66 75 6e  63 5f 5f 2e 32 39 30 37|99.__func__.2907|
      0x00000210|00 5f 5f 66 75 6e 63 5f  5f 2e 32 39 31 35 00 5f|.__func__.2915._|
      0x00000220|5f 66 75 6e 63 5f 5f 2e  32 39 32 33 00 5f 5f 66|_func__.2923.__f|
      0x00000230|75 6e 63 5f 5f 2e 32 39  33 31 00 5f 5f 66 75 6e|unc__.2931.__fun|
      0x00000240|63 5f 5f 2e 32 39 33 39  00 5f 5f 66 75 6e 63 5f|c__.2939.__func_|
      0x00000250|5f 2e 32 39 34 37 00 5f  5f 66 75 6e 63 5f 5f 2e|_.2947.__func__.|
      0x00000260|32 39 35 35 00 5f 5f 66  75 6e 63 5f 5f 2e 32 39|2955.__func__.29|
      0x00000270|36 33 00 5f 5f 66 75 6e  63 5f 5f 2e 32 39 37 31|63.__func__.2971|
      0x00000280|00 5f 5f 66 75 6e 63 5f  5f 2e 32 39 37 39 00 5f|.__func__.2979._|
      0x00000290|5f 66 75 6e 63 5f 5f 2e  32 39 38 37 00 5f 5f 66|_func__.2987.__f|
      0x000002a0|75 6e 63 5f 5f 2e 32 39  39 35 00 5f 5f 66 75 6e|unc__.2995.__fun|
      0x000002b0|63 5f 5f 2e 33 30 30 33  00 5f 5f 66 75 6e 63 5f|c__.3003.__func_|
      0x000002c0|5f 2e 33 30 31 31 00 5f  5f 66 75 6e 63 5f 5f 2e|_.3011.__func__.|
      0x000002d0|33 30 33 39 00 5f 5f 66  75 6e 63 5f 5f 2e 33 30|3039.__func__.30|
      0x000002e0|34 37 00 5f 5f 66 75 6e  63 5f 5f 2e 33 30 35 35|47.__func__.3055|
      0x000002f0|00 5f 5f 66 75 6e 63 5f  5f 2e 33 30 36 33 00 5f|.__func__.3063._|
      0x00000300|5f 66 75 6e 63 5f 5f 2e  33 30 38 30 00 5f 5f 66|_func__.3080.__f|
      0x00000310|75 6e 63 5f 5f 2e 33 30  38 38 00 5f 5f 66 75 6e|unc__.3088.__fun|
      0x00000320|63 5f 5f 2e 33 31 30 37  00 5f 5f 66 75 6e 63 5f|c__.3107.__func_|
      0x00000330|5f 2e 33 31 34 31 00 5f  5f 66 75 6e 63 5f 5f 2e|_.3141.__func__.|
      0x00000340|33 31 34 35 00 5f 5f 66  75 6e 63 5f 5f 2e 33 31|3145.__func__.31|
      0x00000350|36 31 00 5f 5f 66 75 6e  63 5f 5f 2e 33 31 36 35|61.__func__.3165|
      0x00000360|00 5f 5f 66 75 6e 63 5f  5f 2e 33 31 36 39 00 5f|.__func__.3169._|
      0x00000370|5f 66 75 6e 63 5f 5f 2e  33 31 37 33 00 5f 5f 66|_func__.3173.__f|
      0x00000380|75 6e 63 5f 5f 2e 33 31  37 37 00 5f 5f 66 75 6e|unc__.3177.__fun|
      0x00000390|63 5f 5f 2e 33 31 38 31  00 5f 5f 66 75 6e 63 5f|c__.3181.__func_|
      0x000003a0|5f 2e 33 31 38 36 00 5f  5f 46 52 41 4d 45 5f 45|_.3186.__FRAME_E|
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
      0x00000810|66 66 6c 75 73 68 40 40  47 4c 49 42 43 5f 32 2e|fflush@@GLIBC_2.|
      0x00000820|32 2e 35 00 70 61 72 73  65 5f 65 6c 66 36 34 5f|2.5.parse_elf64_|
      0x00000830|70 72 6f 67 5f 68 65 61  64 65 72 73 00 62 75 69|prog_headers.bui|
      0x00000840|6c 64 5f 65 6c 66 36 34  5f 6f 62 6a 00 78 6c 6f|ld_elf64_obj.xlo|
      0x00000850|67 5f 75 6e 69 6e 69 74  00 73 65 63 74 5f 66 75|g_uninit.sect_fu|
      0x00000860|6e 63 73 00 61 66 74 65  72 5f 6d 61 69 6e 5f 66|ncs.after_main_f|
      0x00000870|75 6e 63 00 76 70 72 69  6e 74 66 40 40 47 4c 49|unc.vprintf@@GLI|
      0x00000880|42 43 5f 32 2e 32 2e 35  00 67 65 74 5f 65 6c 66|BC_2.2.5.get_elf|
      0x00000890|36 34 5f 64 61 74 61 00  66 75 6e 63 5f 73 65 63|64_data.func_sec|
      0x000008a0|74 5f 69 6e 74 65 72 70  00 6d 79 5f 66 69 6e 69|t_interp.my_fini|
      0x000008b0|30 32 00 66 75 6e 63 5f  73 65 63 74 5f 65 68 5f|02.func_sect_eh_|
      0x000008c0|66 72 61 6d 65 5f 68 64  72 00 66 75 6e 63 5f 73|frame_hdr.func_s|
      0x000008d0|65 63 74 5f 74 65 78 74  00 5f 5f 62 73 73 5f 73|ect_text.__bss_s|
      0x000008e0|74 61 72 74 00 6d 61 69  6e 00 66 75 6e 63 5f 73|tart.main.func_s|
      0x000008f0|65 63 74 5f 65 68 5f 66  72 61 6d 65 00 66 75 6e|ect_eh_frame.fun|
      0x00000900|63 5f 73 65 63 74 5f 72  6f 64 61 74 61 00 6d 79|c_sect_rodata.my|
      0x00000910|5f 69 6e 69 74 30 33 00  6d 79 5f 69 6e 69 74 30|_init03.my_init0|
      0x00000920|31 00 66 6f 70 65 6e 40  40 47 4c 49 42 43 5f 32|1.fopen@@GLIBC_2|
      0x00000930|2e 32 2e 35 00 62 65 66  6f 72 65 5f 6d 61 69 6e|.2.5.before_main|
      0x00000940|5f 66 75 6e 63 00 70 61  72 73 65 5f 65 6c 66 36|_func.parse_elf6|
      0x00000950|34 5f 65 6c 66 5f 68 65  61 64 65 72 00 66 75 6e|4_elf_header.fun|
      0x00000960|63 5f 73 65 63 74 5f 67  6f 74 5f 70 6c 74 00 66|c_sect_got_plt.f|
      0x00000970|75 6e 63 5f 73 65 63 74  5f 72 65 6c 61 5f 70 6c|unc_sect_rela_pl|
      0x00000980|74 00 78 6c 6f 67 5f 63  6f 72 65 00 5f 5f 54 4d|t.xlog_core.__TM|
      0x00000990|43 5f 45 4e 44 5f 5f 00  70 61 72 73 65 5f 65 6c|C_END__.parse_el|
      0x000009a0|66 36 34 5f 73 65 63 74  5f 68 65 61 64 65 72 00|f64_sect_header.|
      0x000009b0|5f 49 54 4d 5f 72 65 67  69 73 74 65 72 54 4d 43|_ITM_registerTMC|
      0x000009c0|6c 6f 6e 65 54 61 62 6c  65 00 70 61 72 73 65 5f|loneTable.parse_|
      0x000009d0|65 6c 66 36 34 5f 73 65  63 74 5f 62 6f 64 79 00|elf64_sect_body.|
      0x000009e0|66 75 6e 63 5f 73 65 63  74 5f 67 6f 74 00 66 75|func_sect_got.fu|
      0x000009f0|6e 63 5f 73 65 63 74 5f  64 79 6e 73 79 6d 00 66|nc_sect_dynsym.f|
      0x00000a00|75 6e 63 5f 73 65 63 74  5f 69 6e 69 74 00 78 6c|unc_sect_init.xl|
      0x00000a10|6f 67 5f 69 6e 66 6f 00  66 75 6e 63 5f 73 65 63|og_info.func_sec|
      0x00000a20|74 5f 6e 6f 74 65 5f 67  6e 75 5f 62 75 69 6c 64|t_note_gnu_build|
      0x00000a30|00 66 75 6e 63 5f 73 65  63 74 5f 64 65 62 75 67|.func_sect_debug|
      0x00000a40|5f 6c 69 6e 65 00 5f 5f  63 78 61 5f 66 69 6e 61|_line.__cxa_fina|
      0x00000a50|6c 69 7a 65 40 40 47 4c  49 42 43 5f 32 2e 32 2e|lize@@GLIBC_2.2.|
      0x00000a60|35 00 66 75 6e 63 5f 73  65 63 74 5f 64 79 6e 61|5.func_sect_dyna|
      0x00000a70|6d 69 63 00 5f 5f 63 74  79 70 65 5f 62 5f 6c 6f|mic.__ctype_b_lo|
      0x00000a80|63 40 40 47 4c 49 42 43  5f 32 2e 33 00 66 75 6e|c@@GLIBC_2.3.fun|
      0x00000a90|63 5f 73 65 63 74 5f 62  73 73 00 ** ** ** ** **|c_sect_bss.*****|
      =============================================================================

      ===========================================================
      >> ptr[000]=0x0055f0f34b8501; str={"crtstuff.c"};
      >> ptr[001]=0x0055f0f34b850c; str={"deregister_tm_clones"};
      >> ptr[002]=0x0055f0f34b8521; str={"__do_global_dtors_aux"};
      >> ptr[003]=0x0055f0f34b8537; str={"completed.8061"};
      >> ptr[004]=0x0055f0f34b8546; str={"__do_global_dtors_aux_fini_array_entry"};
      >> ptr[005]=0x0055f0f34b856d; str={"frame_dummy"};
      >> ptr[006]=0x0055f0f34b8579; str={"__frame_dummy_init_array_entry"};
      >> ptr[007]=0x0055f0f34b8598; str={"myreadelf-0.1.06.c"};
      >> ptr[008]=0x0055f0f34b85ab; str={"__func__.2481"};
      >> ptr[009]=0x0055f0f34b85b9; str={"__func__.2499"};
      >> ptr[010]=0x0055f0f34b85c7; str={"__PRETTY_FUNCTION__.2503"};
      >> ptr[011]=0x0055f0f34b85e0; str={"__func__.2522"};
      >> ptr[012]=0x0055f0f34b85ee; str={"__PRETTY_FUNCTION__.2526"};
      >> ptr[013]=0x0055f0f34b8607; str={"__func__.2763"};
      >> ptr[014]=0x0055f0f34b8615; str={"__func__.2771"};
      >> ptr[015]=0x0055f0f34b8623; str={"__func__.2779"};
      >> ptr[016]=0x0055f0f34b8631; str={"__func__.2787"};
      >> ptr[017]=0x0055f0f34b863f; str={"__func__.2795"};
      >> ptr[018]=0x0055f0f34b864d; str={"__func__.2803"};
      >> ptr[019]=0x0055f0f34b865b; str={"__func__.2811"};
      >> ptr[020]=0x0055f0f34b8669; str={"__func__.2819"};
      >> ptr[021]=0x0055f0f34b8677; str={"__func__.2827"};
      >> ptr[022]=0x0055f0f34b8685; str={"__func__.2835"};
      >> ptr[023]=0x0055f0f34b8693; str={"__func__.2843"};
      >> ptr[024]=0x0055f0f34b86a1; str={"__func__.2851"};
      >> ptr[025]=0x0055f0f34b86af; str={"__func__.2859"};
      >> ptr[026]=0x0055f0f34b86bd; str={"__func__.2867"};
      >> ptr[027]=0x0055f0f34b86cb; str={"__func__.2875"};
      >> ptr[028]=0x0055f0f34b86d9; str={"__func__.2883"};
      >> ptr[029]=0x0055f0f34b86e7; str={"__func__.2891"};
      >> ptr[030]=0x0055f0f34b86f5; str={"__func__.2899"};
      >> ptr[031]=0x0055f0f34b8703; str={"__func__.2907"};
      >> ptr[032]=0x0055f0f34b8711; str={"__func__.2915"};
      >> ptr[033]=0x0055f0f34b871f; str={"__func__.2923"};
      >> ptr[034]=0x0055f0f34b872d; str={"__func__.2931"};
      >> ptr[035]=0x0055f0f34b873b; str={"__func__.2939"};
      >> ptr[036]=0x0055f0f34b8749; str={"__func__.2947"};
      >> ptr[037]=0x0055f0f34b8757; str={"__func__.2955"};
      >> ptr[038]=0x0055f0f34b8765; str={"__func__.2963"};
      >> ptr[039]=0x0055f0f34b8773; str={"__func__.2971"};
      >> ptr[040]=0x0055f0f34b8781; str={"__func__.2979"};
      >> ptr[041]=0x0055f0f34b878f; str={"__func__.2987"};
      >> ptr[042]=0x0055f0f34b879d; str={"__func__.2995"};
      >> ptr[043]=0x0055f0f34b87ab; str={"__func__.3003"};
      >> ptr[044]=0x0055f0f34b87b9; str={"__func__.3011"};
      >> ptr[045]=0x0055f0f34b87c7; str={"__func__.3039"};
      >> ptr[046]=0x0055f0f34b87d5; str={"__func__.3047"};
      >> ptr[047]=0x0055f0f34b87e3; str={"__func__.3055"};
      >> ptr[048]=0x0055f0f34b87f1; str={"__func__.3063"};
      >> ptr[049]=0x0055f0f34b87ff; str={"__func__.3080"};
      >> ptr[050]=0x0055f0f34b880d; str={"__func__.3088"};
      >> ptr[051]=0x0055f0f34b881b; str={"__func__.3107"};
      >> ptr[052]=0x0055f0f34b8829; str={"__func__.3141"};
      >> ptr[053]=0x0055f0f34b8837; str={"__func__.3145"};
      >> ptr[054]=0x0055f0f34b8845; str={"__func__.3161"};
      >> ptr[055]=0x0055f0f34b8853; str={"__func__.3165"};
      >> ptr[056]=0x0055f0f34b8861; str={"__func__.3169"};
      >> ptr[057]=0x0055f0f34b886f; str={"__func__.3173"};
      >> ptr[058]=0x0055f0f34b887d; str={"__func__.3177"};
      >> ptr[059]=0x0055f0f34b888b; str={"__func__.3181"};
      >> ptr[060]=0x0055f0f34b8899; str={"__func__.3186"};
      >> ptr[061]=0x0055f0f34b88a7; str={"__FRAME_END__"};
      >> ptr[062]=0x0055f0f34b88b5; str={"__init_array_end"};
      >> ptr[063]=0x0055f0f34b88c6; str={"_DYNAMIC"};
      >> ptr[064]=0x0055f0f34b88cf; str={"__init_array_start"};
      >> ptr[065]=0x0055f0f34b88e2; str={"__GNU_EH_FRAME_HDR"};
      >> ptr[066]=0x0055f0f34b88f5; str={"_GLOBAL_OFFSET_TABLE_"};
      >> ptr[067]=0x0055f0f34b890b; str={"__libc_csu_fini"};
      >> ptr[068]=0x0055f0f34b891b; str={"func_sect_note_gnu_prope"};
      >> ptr[069]=0x0055f0f34b8934; str={"xlog_mutex_lock"};
      >> ptr[070]=0x0055f0f34b8944; str={"func_sect_data"};
      >> ptr[071]=0x0055f0f34b8953; str={"xlog_mutex_unlock"};
      >> ptr[072]=0x0055f0f34b8965; str={"__stat"};
      >> ptr[073]=0x0055f0f34b896c; str={"free@@GLIBC_2.2.5"};
      >> ptr[074]=0x0055f0f34b897e; str={"func_sect_plt"};
      >> ptr[075]=0x0055f0f34b898c; str={"func_sect_note_ABI_tag"};
      >> ptr[076]=0x0055f0f34b89a3; str={"_ITM_deregisterTMCloneTable"};
      >> ptr[077]=0x0055f0f34b89bf; str={"stdout@@GLIBC_2.2.5"};
      >> ptr[078]=0x0055f0f34b89d3; str={"func_sect_debug_aranges"};
      >> ptr[079]=0x0055f0f34b89eb; str={"func_sect_fini_array"};
      >> ptr[080]=0x0055f0f34b8a00; str={"parse_elf64_sect_bodys"};
      >> ptr[081]=0x0055f0f34b8a17; str={"fread@@GLIBC_2.2.5"};
      >> ptr[082]=0x0055f0f34b8a2a; str={"my_fini01"};
      >> ptr[083]=0x0055f0f34b8a34; str={"my_fini03"};
      >> ptr[084]=0x0055f0f34b8a3e; str={"parse_elf64_prog_header"};
      >> ptr[085]=0x0055f0f34b8a56; str={"func_sect_comment"};
      >> ptr[086]=0x0055f0f34b8a68; str={"xlog_hexdump"};
      >> ptr[087]=0x0055f0f34b8a75; str={"func_sect_debug_str"};
      >> ptr[088]=0x0055f0f34b8a89; str={"xlog_info_x"};
      >> ptr[089]=0x0055f0f34b8a95; str={"func_sect_shstrtab"};
      >> ptr[090]=0x0055f0f34b8aa8; str={"_edata"};
      >> ptr[091]=0x0055f0f34b8aaf; str={"func_sect_plt_got"};
      >> ptr[092]=0x0055f0f34b8ac1; str={"PrtProgHeader"};
      >> ptr[093]=0x0055f0f34b8acf; str={"fclose@@GLIBC_2.2.5"};
      >> ptr[094]=0x0055f0f34b8ae3; str={"func_sect_debug_abbrev"};
      >> ptr[095]=0x0055f0f34b8afa; str={"func_sect_gnu_version_r"};
      >> ptr[096]=0x0055f0f34b8b12; str={"__stack_chk_fail@@GLIBC_2.4"};
      >> ptr[097]=0x0055f0f34b8b2e; str={"my_init02"};
      >> ptr[098]=0x0055f0f34b8b38; str={"func_sect_dynstr"};
      >> ptr[099]=0x0055f0f34b8b49; str={"func_sect_debug_info"};
      >> ptr[100]=0x0055f0f34b8b5e; str={"__assert_fail@@GLIBC_2.2.5"};
      >> ptr[101]=0x0055f0f34b8b79; str={"func_sect_note_gnu_build_id"};
      >> ptr[102]=0x0055f0f34b8b95; str={"func_sect_strtab"};
      >> ptr[103]=0x0055f0f34b8ba6; str={"parse_args"};
      >> ptr[104]=0x0055f0f34b8bb1; str={"__libc_start_main@@GLIBC_2.2.5"};
      >> ptr[105]=0x0055f0f34b8bd0; str={"calloc@@GLIBC_2.2.5"};
      >> ptr[106]=0x0055f0f34b8be4; str={"parse_elf64_sect_headers"};
      >> ptr[107]=0x0055f0f34b8bfd; str={"__data_start"};
      >> ptr[108]=0x0055f0f34b8c0a; str={"strcmp@@GLIBC_2.2.5"};
      >> ptr[109]=0x0055f0f34b8c1e; str={"func_sect_gnu_hash"};
      >> ptr[110]=0x0055f0f34b8c31; str={"func_sect_symtab"};
      >> ptr[111]=0x0055f0f34b8c42; str={"func_process"};
      >> ptr[112]=0x0055f0f34b8c4f; str={"func_sect_rela_dyn"};
      >> ptr[113]=0x0055f0f34b8c62; str={"__gmon_start__"};
      >> ptr[114]=0x0055f0f34b8c71; str={"func_sect_fini"};
      >> ptr[115]=0x0055f0f34b8c80; str={"__dso_handle"};
      >> ptr[116]=0x0055f0f34b8c8d; str={"func_sect_init_array"};
      >> ptr[117]=0x0055f0f34b8ca2; str={"_IO_stdin_used"};
      >> ptr[118]=0x0055f0f34b8cb1; str={"func_sect_gnu_version"};
      >> ptr[119]=0x0055f0f34b8cc7; str={"__xstat@@GLIBC_2.2.5"};
      >> ptr[120]=0x0055f0f34b8cdc; str={"xlog_init"};
      >> ptr[121]=0x0055f0f34b8ce6; str={"PrtSectHeader"};
      >> ptr[122]=0x0055f0f34b8cf4; str={"DumpPtr2Str"};
      >> ptr[123]=0x0055f0f34b8d00; str={"__libc_csu_init"};
      >> ptr[124]=0x0055f0f34b8d10; str={"fflush@@GLIBC_2.2.5"};
      >> ptr[125]=0x0055f0f34b8d24; str={"parse_elf64_prog_headers"};
      >> ptr[126]=0x0055f0f34b8d3d; str={"build_elf64_obj"};
      >> ptr[127]=0x0055f0f34b8d4d; str={"xlog_uninit"};
      >> ptr[128]=0x0055f0f34b8d59; str={"sect_funcs"};
      >> ptr[129]=0x0055f0f34b8d64; str={"after_main_func"};
      >> ptr[130]=0x0055f0f34b8d74; str={"vprintf@@GLIBC_2.2.5"};
      >> ptr[131]=0x0055f0f34b8d89; str={"get_elf64_data"};
      >> ptr[132]=0x0055f0f34b8d98; str={"func_sect_interp"};
      >> ptr[133]=0x0055f0f34b8da9; str={"my_fini02"};
      >> ptr[134]=0x0055f0f34b8db3; str={"func_sect_eh_frame_hdr"};
      >> ptr[135]=0x0055f0f34b8dca; str={"func_sect_text"};
      >> ptr[136]=0x0055f0f34b8dd9; str={"__bss_start"};
      >> ptr[137]=0x0055f0f34b8de5; str={"main"};
      >> ptr[138]=0x0055f0f34b8dea; str={"func_sect_eh_frame"};
      >> ptr[139]=0x0055f0f34b8dfd; str={"func_sect_rodata"};
      >> ptr[140]=0x0055f0f34b8e0e; str={"my_init03"};
      >> ptr[141]=0x0055f0f34b8e18; str={"my_init01"};
      >> ptr[142]=0x0055f0f34b8e22; str={"fopen@@GLIBC_2.2.5"};
      >> ptr[143]=0x0055f0f34b8e35; str={"before_main_func"};
      >> ptr[144]=0x0055f0f34b8e46; str={"parse_elf64_elf_header"};
      >> ptr[145]=0x0055f0f34b8e5d; str={"func_sect_got_plt"};
      >> ptr[146]=0x0055f0f34b8e6f; str={"func_sect_rela_plt"};
      >> ptr[147]=0x0055f0f34b8e82; str={"xlog_core"};
      >> ptr[148]=0x0055f0f34b8e8c; str={"__TMC_END__"};
      >> ptr[149]=0x0055f0f34b8e98; str={"parse_elf64_sect_header"};
      >> ptr[150]=0x0055f0f34b8eb0; str={"_ITM_registerTMCloneTable"};
      >> ptr[151]=0x0055f0f34b8eca; str={"parse_elf64_sect_body"};
      >> ptr[152]=0x0055f0f34b8ee0; str={"func_sect_got"};
      >> ptr[153]=0x0055f0f34b8eee; str={"func_sect_dynsym"};
      >> ptr[154]=0x0055f0f34b8eff; str={"func_sect_init"};
      >> ptr[155]=0x0055f0f34b8f0e; str={"xlog_info"};
      >> ptr[156]=0x0055f0f34b8f18; str={"func_sect_note_gnu_build"};
      >> ptr[157]=0x0055f0f34b8f31; str={"func_sect_debug_line"};
      >> ptr[158]=0x0055f0f34b8f46; str={"__cxa_finalize@@GLIBC_2.2.5"};
      >> ptr[159]=0x0055f0f34b8f62; str={"func_sect_dynamic"};
      >> ptr[160]=0x0055f0f34b8f74; str={"__ctype_b_loc@@GLIBC_2.3"};
      >> ptr[161]=0x0055f0f34b8f8d; str={"func_sect_bss"};
      >> ptr[162]=0x0055f0f34b8f9c; str={".symtab"};
      ===========================================================


  >> func{parse_elf64_sect_body:(00838)} is call. 
      {idx=35,sect_name=".shstrtab",pSectData=0x55f0f34b8f9b,iLen=0x15a}
    >> func{func_sect_shstrtab:(00764)} is call .
        No.[35]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55f0f34b99b8
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xe70b;
             Elf64_Xword   sh_size      = 0x15a;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }

0x0055f0f34b8f9b|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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
      >> ptr[000]=0x0055f0f34b8f9c; str={".symtab"};
      >> ptr[001]=0x0055f0f34b8fa4; str={".strtab"};
      >> ptr[002]=0x0055f0f34b8fac; str={".shstrtab"};
      >> ptr[003]=0x0055f0f34b8fb6; str={".interp"};
      >> ptr[004]=0x0055f0f34b8fbe; str={".note.gnu.property"};
      >> ptr[005]=0x0055f0f34b8fd1; str={".note.gnu.build-id"};
      >> ptr[006]=0x0055f0f34b8fe4; str={".note.ABI-tag"};
      >> ptr[007]=0x0055f0f34b8ff2; str={".gnu.hash"};
      >> ptr[008]=0x0055f0f34b8ffc; str={".dynsym"};
      >> ptr[009]=0x0055f0f34b9004; str={".dynstr"};
      >> ptr[010]=0x0055f0f34b900c; str={".gnu.version"};
      >> ptr[011]=0x0055f0f34b9019; str={".gnu.version_r"};
      >> ptr[012]=0x0055f0f34b9028; str={".rela.dyn"};
      >> ptr[013]=0x0055f0f34b9032; str={".rela.plt"};
      >> ptr[014]=0x0055f0f34b903c; str={".init"};
      >> ptr[015]=0x0055f0f34b9042; str={".plt.got"};
      >> ptr[016]=0x0055f0f34b904b; str={".plt.sec"};
      >> ptr[017]=0x0055f0f34b9054; str={".text"};
      >> ptr[018]=0x0055f0f34b905a; str={".fini"};
      >> ptr[019]=0x0055f0f34b9060; str={".rodata"};
      >> ptr[020]=0x0055f0f34b9068; str={".eh_frame_hdr"};
      >> ptr[021]=0x0055f0f34b9076; str={".eh_frame"};
      >> ptr[022]=0x0055f0f34b9080; str={".init_array"};
      >> ptr[023]=0x0055f0f34b908c; str={".fini_array"};
      >> ptr[024]=0x0055f0f34b9098; str={".dynamic"};
      >> ptr[025]=0x0055f0f34b90a1; str={".data"};
      >> ptr[026]=0x0055f0f34b90a7; str={".bss"};
      >> ptr[027]=0x0055f0f34b90ac; str={".comment"};
      >> ptr[028]=0x0055f0f34b90b5; str={".debug_aranges"};
      >> ptr[029]=0x0055f0f34b90c4; str={".debug_info"};
      >> ptr[030]=0x0055f0f34b90d0; str={".debug_abbrev"};
      >> ptr[031]=0x0055f0f34b90de; str={".debug_line"};
      >> ptr[032]=0x0055f0f34b90ea; str={".debug_str"};
      >> ptr[033]=0x0055f0f34b9138; str={"};
      ===========================================================


  >> build_elf64_obj() exit;
  >> the app exit.
  >> func{my_fini03:(01027)@(myreadelf-0.1.06.c)} is call .
  #<<<<====
  >> func{my_fini02:(01015)@(myreadelf-0.1.06.c)} is call .
  #<<<<====
  >> func{my_fini01:(01003)@(myreadelf-0.1.06.c)} is call .
  #<<<<====
  >> func{after_main_func:(00983)@(myreadelf-0.1.06.c)} is call .
  #<<<<====
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 

#endif

