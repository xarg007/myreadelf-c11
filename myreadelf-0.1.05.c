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
    xlog_info("        }\n\n");
    
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
    
    if(1)
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

struct S_ELF64_ProgHeader_t* 
parse_elf64_prog_header(struct S_ELF64_ELFHeader_t* pElfHeader, unsigned char* pProgHeaderData, int idx)
{
    xlog_info("  >> func\e[1m{%s:(%05d)}\e[0m is call .\n", __func__, __LINE__);
    
    struct S_ELF64_ProgHeader_t* pProgHeader = (struct S_ELF64_ProgHeader_t*)pProgHeaderData;
    if(1)
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
    }
    
    xlog_info("\n");
    
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
    
    xlog_info("\n\n");
    
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
int func_sect_interp           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_note_gnu_prope   (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_note_gnu_build   (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_note_ABI_tag     (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_note_gnu_build_id(int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_gnu_hash         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_dynsym           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_dynstr           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
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
int func_sect_debug_str        (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_symtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_strtab           (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
int func_sect_shstrtab         (int idx, char* name, unsigned char* pData, int iLen, struct S_ELF64_SectHeader_t* pSectHeader){xlog_info("    >> func{%s:(%05d)} is call .\n", __func__, __LINE__);return 0;}
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
            xlog_hexdump((uint8_t*)p_elf64_data, 16*20+5);
        }
        
        //基于从文件中读取的ELF数据，构建ELF对象；
        struct s_elf64_obj_t* p_elf64_obj = build_elf64_obj(p_elf64_data, i_elf64_len);
        
        xlog_hexdump((uint8_t*)p_elf64_obj, 16*40+5);
        
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
  >> func{before_main_func:(00815)@(myreadelf-0.1.05.c)} is call .
  #====>>>>
  >> func{my_init01:(00836)@(myreadelf-0.1.05.c)} is call .
  #====>>>>
  >> func{my_init02:(00848)@(myreadelf-0.1.05.c)} is call .
  #====>>>>
  >> func{my_init03:(00860)@(myreadelf-0.1.05.c)} is call .
  >> the app starting ... ...

0x007fff727afed8|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|60 16 7b 72 ff 7f 00 00  00 00 00 00 00 00 00 00|`.{r............|
      0x00000010|68 16 7b 72 ff 7f 00 00  78 16 7b 72 ff 7f 00 00|h.{r....x.{r....|
      0x00000020|90 16 7b 72 ff 7f 00 00  a7 16 7b 72 ff 7f 00 00|..{r......{r....|
      0x00000030|bb 16 7b 72 ff 7f 00 00  d3 16 7b 72 ff 7f 00 00|..{r......{r....|
      0x00000040|fd 16 7b 72 ff 7f 00 00  0c 17 7b 72 ff 7f 00 00|..{r......{r....|
      0x00000050|21 17 7b 72 ff 7f 00 00  30 17 7b ** ** ** ** **|!.{r....0.{*****|
      =============================================================================


0x007fff727b1660|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2e 2f 6d 79 61 70 70 00  53 48 45 4c 4c 3d 2f 62|./myapp.SHELL=/b|
      0x00000010|69 6e 2f 62 61 73 68 00  4c 41 4e 47 55 41 47 45|in/bash.LANGUAGE|
      0x00000020|3d 7a 68 5f 43 4e 3a 65  6e 5f 55 53 3a 65 6e 00|=zh_CN:en_US:en.|
      0x00000030|4c 43 5f 41 44 44 52 45  53 53 3d 7a 68 5f 43 4e|LC_ADDRESS=zh_CN|
      0x00000040|2e 55 54 46 2d 38 00 4c  43 5f 4e 41 4d 45 3d 7a|.UTF-8.LC_NAME=z|
      0x00000050|68 5f 43 4e 2e 55 54 46  2d 38 00 ** ** ** ** **|h_CN.UTF-8.*****|
      =============================================================================

  >> func:parse_args(1, 0x7fff727afed8) is called. (@file:myreadelf-0.1.05.c,line:0874).

    >>> argv[00](addr=0x7fff727b1660) = {"./myapp"}.

  >> func:parse_args() is called. @line:(0881).
  >> get_elf64_data("./myapp", len) entry;

0x0055b3fc038890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  e0 21 00 00 00 00 00 00|..>......!......|
      0x00000020|40 00 00 00 00 00 00 00  78 e7 00 00 00 00 00 00|@.......x.......|
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
      0x000000d0|78 10 00 00 00 00 00 00  78 10 00 00 00 00 00 00|x.......x.......|
      0x000000e0|00 10 00 00 00 00 00 00  01 00 00 00 05 00 00 00|................|
      0x000000f0|00 20 00 00 00 00 00 00  00 20 00 00 00 00 00 00|. ....... ......|
      0x00000100|00 20 00 00 00 00 00 00  a1 2c 00 00 00 00 00 00|. .......,......|
      0x00000110|a1 2c 00 00 00 00 00 00  00 10 00 00 00 00 00 00|.,..............|
      0x00000120|01 00 00 00 04 00 00 00  00 50 00 00 00 00 00 00|.........P......|
      0x00000130|00 50 00 00 00 00 00 00  00 50 00 00 00 00 00 00|.P.......P......|
      0x00000140|c8 24 00 00 00 ** ** **  ** ** ** ** ** ** ** **|.$...***********|
      =============================================================================

  >> build_elf64_obj(0x55b3fc038890, 61560) entry;
  >> func{parse_elf64_elf_header:(00335)} is call.{pElfData=0x55b3fc038890}.
        struct S_ELF64_ELFHeader_t pElfHeader = {0x55b3fc038890} 
        {
                 unsigned char e_ident[16] = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00};
                 Elf64_Half    e_type      = 0x0003;
                 Elf64_Half    e_machine   = 0x003e;
                 Elf64_Word    e_version   = 0x1  ;
                 Elf64_Addr    e_entry     = 0x21e0;
                 Elf64_Off     e_phoff     = 0x40;
                 Elf64_Off     e_shoff     = 0xe778;
                 Elf64_Word    e_flags     = 0x0  ;
                 Elf64_Half    e_ehsize    = 0x0040;
                 Elf64_Half    e_phentsize = 0x0038;
                 Elf64_Half    e_phnum     = 0x000d;
                 Elf64_Half    e_shentsize = 0x0040;
                 Elf64_Half    e_shnum     = 0x0024;
                 Elf64_Half    e_shstrndx  = 0x0023;
        };
        No.[35]--------------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0478c8
        {
             Elf64_Word    sh_name      = 0x11;
             Elf64_Word    sh_type      = 0x3;
             Elf64_Xword   sh_flags     = 0x0;
             Elf64_Addr    sh_addr      = 0x0;
             Elf64_Off     sh_offset    = 0xe61b;
             Elf64_Xword   sh_size      = 0x15a;
             Elf64_Word    sh_link      = 0x0;
             Elf64_Word    sh_info      = 0x0;
             Elf64_Xword   sh_addralign = 0x1;
             Elf64_Xword   sh_entsize   = 0x0;
        }


0x0055b3fc046eab|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
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

  >> func{parse_elf64_sect_headers:(00416)} is call .
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[00] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047008
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
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[01] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047048
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
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[02] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047088
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
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[03] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0470c8
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
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[04] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047108
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
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[05] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047148
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
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[06] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047188
        {
                 Elf64_Word    sh_name     = {0x61|".dynsym"};
                 Elf64_Word    sh_type     = 0xb;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x3c8;       
                 Elf64_Off     sh_offset   = 0x3c8;       
                 Elf64_Xword   sh_size     = 0x1e0;       
                 Elf64_Word    sh_link     = 0x7;         
                 Elf64_Word    sh_info     = 0x1;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x18;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[07] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0471c8
        {
                 Elf64_Word    sh_name     = {0x69|".dynstr"};
                 Elf64_Word    sh_type     = 0x3;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x5a8;       
                 Elf64_Off     sh_offset   = 0x5a8;       
                 Elf64_Xword   sh_size     = 0x102;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[08] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047208
        {
                 Elf64_Word    sh_name     = {0x71|".gnu.version"};
                 Elf64_Word    sh_type     = 0x6fffffff;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x6aa;       
                 Elf64_Off     sh_offset   = 0x6aa;       
                 Elf64_Xword   sh_size     = 0x28;       
                 Elf64_Word    sh_link     = 0x6;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x2;       
                 Elf64_Xword   sh_entsize  = 0x2;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[09] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047248
        {
                 Elf64_Word    sh_name     = {0x7e|".gnu.version_r"};
                 Elf64_Word    sh_type     = 0x6ffffffe;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x6d8;       
                 Elf64_Off     sh_offset   = 0x6d8;       
                 Elf64_Xword   sh_size     = 0x40;       
                 Elf64_Word    sh_link     = 0x7;         
                 Elf64_Word    sh_info     = 0x1;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[10] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047288
        {
                 Elf64_Word    sh_name     = {0x8d|".rela.dyn"};
                 Elf64_Word    sh_type     = 0x4;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x718;       
                 Elf64_Off     sh_offset   = 0x718;       
                 Elf64_Xword   sh_size     = 0x828;       
                 Elf64_Word    sh_link     = 0x6;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x18;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[11] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0472c8
        {
                 Elf64_Word    sh_name     = {0x97|".rela.plt"};
                 Elf64_Word    sh_type     = 0x4;         
                 Elf64_Xword   sh_flags    = 0x42;       
                 Elf64_Addr    sh_addr     = 0xf40;       
                 Elf64_Off     sh_offset   = 0xf40;       
                 Elf64_Xword   sh_size     = 0x138;       
                 Elf64_Word    sh_link     = 0x6;         
                 Elf64_Word    sh_info     = 0x18;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x18;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[12] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047308
        {
                 Elf64_Word    sh_name     = {0xa1|".init"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x2000;       
                 Elf64_Off     sh_offset   = 0x2000;       
                 Elf64_Xword   sh_size     = 0x1b;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x4;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[13] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047348
        {
                 Elf64_Word    sh_name     = {0x9c|".plt"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x2020;       
                 Elf64_Off     sh_offset   = 0x2020;       
                 Elf64_Xword   sh_size     = 0xe0;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x10;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[14] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047388
        {
                 Elf64_Word    sh_name     = {0xa7|".plt.got"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x2100;       
                 Elf64_Off     sh_offset   = 0x2100;       
                 Elf64_Xword   sh_size     = 0x10;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x10;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[15] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0473c8
        {
                 Elf64_Word    sh_name     = {0xb0|".plt.sec"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x2110;       
                 Elf64_Off     sh_offset   = 0x2110;       
                 Elf64_Xword   sh_size     = 0xd0;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x10;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[16] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047408
        {
                 Elf64_Word    sh_name     = {0xb9|".text"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x21e0;       
                 Elf64_Off     sh_offset   = 0x21e0;       
                 Elf64_Xword   sh_size     = 0x2ab4;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[17] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047448
        {
                 Elf64_Word    sh_name     = {0xbf|".fini"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x6;       
                 Elf64_Addr    sh_addr     = 0x4c94;       
                 Elf64_Off     sh_offset   = 0x4c94;       
                 Elf64_Xword   sh_size     = 0xd;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x4;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[18] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047488
        {
                 Elf64_Word    sh_name     = {0xc5|".rodata"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x5000;       
                 Elf64_Off     sh_offset   = 0x5000;       
                 Elf64_Xword   sh_size     = 0x192b;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x10;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[19] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0474c8
        {
                 Elf64_Word    sh_name     = {0xcd|".eh_frame_hdr"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x692c;       
                 Elf64_Off     sh_offset   = 0x692c;       
                 Elf64_Xword   sh_size     = 0x254;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x4;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[20] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047508
        {
                 Elf64_Word    sh_name     = {0xdb|".eh_frame"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x2;       
                 Elf64_Addr    sh_addr     = 0x6b80;       
                 Elf64_Off     sh_offset   = 0x6b80;       
                 Elf64_Xword   sh_size     = 0x948;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[21] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047548
        {
                 Elf64_Word    sh_name     = {0xe5|".init_array"};
                 Elf64_Word    sh_type     = 0xe;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x8d18;       
                 Elf64_Off     sh_offset   = 0x7d18;       
                 Elf64_Xword   sh_size     = 0x28;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x8;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[22] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047588
        {
                 Elf64_Word    sh_name     = {0xf1|".fini_array"};
                 Elf64_Word    sh_type     = 0xf;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x8d40;       
                 Elf64_Off     sh_offset   = 0x7d40;       
                 Elf64_Xword   sh_size     = 0x28;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x8;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[23] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0475c8
        {
                 Elf64_Word    sh_name     = {0xfd|".dynamic"};
                 Elf64_Word    sh_type     = 0x6;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x8d68;       
                 Elf64_Off     sh_offset   = 0x7d68;       
                 Elf64_Xword   sh_size     = 0x1f0;       
                 Elf64_Word    sh_link     = 0x7;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x10;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[24] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047608
        {
                 Elf64_Word    sh_name     = {0xab|".got"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x8f58;       
                 Elf64_Off     sh_offset   = 0x7f58;       
                 Elf64_Xword   sh_size     = 0xa8;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x8;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[25] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047648
        {
                 Elf64_Word    sh_name     = {0x106|".data"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x9000;       
                 Elf64_Off     sh_offset   = 0x8000;       
                 Elf64_Xword   sh_size     = 0x270;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x20;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[26] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047688
        {
                 Elf64_Word    sh_name     = {0x10c|".bss"};
                 Elf64_Word    sh_type     = 0x8;         
                 Elf64_Xword   sh_flags    = 0x3;       
                 Elf64_Addr    sh_addr     = 0x9270;       
                 Elf64_Off     sh_offset   = 0x8270;       
                 Elf64_Xword   sh_size     = 0x10;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[27] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0476c8
        {
                 Elf64_Word    sh_name     = {0x111|".comment"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x30;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x8270;       
                 Elf64_Xword   sh_size     = 0x2b;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x1;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[28] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047708
        {
                 Elf64_Word    sh_name     = {0x11a|".debug_aranges"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x829b;       
                 Elf64_Xword   sh_size     = 0x30;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[29] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047748
        {
                 Elf64_Word    sh_name     = {0x129|".debug_info"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0x82cb;       
                 Elf64_Xword   sh_size     = 0x29c9;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[30] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047788
        {
                 Elf64_Word    sh_name     = {0x135|".debug_abbrev"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0xac94;       
                 Elf64_Xword   sh_size     = 0x280;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[31] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0477c8
        {
                 Elf64_Word    sh_name     = {0x143|".debug_line"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0xaf14;       
                 Elf64_Xword   sh_size     = 0xc85;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[32] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047808
        {
                 Elf64_Word    sh_name     = {0x14f|".debug_str"};
                 Elf64_Word    sh_type     = 0x1;         
                 Elf64_Xword   sh_flags    = 0x30;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0xbb99;       
                 Elf64_Xword   sh_size     = 0xc87;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x1;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[33] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047848
        {
                 Elf64_Word    sh_name     = {0x1|".symtab"};
                 Elf64_Word    sh_type     = 0x2;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0xc820;       
                 Elf64_Xword   sh_size     = 0x1350;       
                 Elf64_Word    sh_link     = 0x22;         
                 Elf64_Word    sh_info     = 0x6b;         
                 Elf64_Xword   sh_addralign= 0x8;       
                 Elf64_Xword   sh_entsize  = 0x18;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[34] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc047888
        {
                 Elf64_Word    sh_name     = {0x9|".strtab"};
                 Elf64_Word    sh_type     = 0x3;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0xdb70;       
                 Elf64_Xword   sh_size     = 0xaab;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
    >> func{parse_elf64_sect_header:(00384)} is call .
        SectionHeader[35] ----------------------------------------
        struct S_ELF64_SectHeader_t * pSectHeader = 0x55b3fc0478c8
        {
                 Elf64_Word    sh_name     = {0x11|".shstrtab"};
                 Elf64_Word    sh_type     = 0x3;         
                 Elf64_Xword   sh_flags    = 0x0;       
                 Elf64_Addr    sh_addr     = 0x0;       
                 Elf64_Off     sh_offset   = 0xe61b;       
                 Elf64_Xword   sh_size     = 0x15a;       
                 Elf64_Word    sh_link     = 0x0;         
                 Elf64_Word    sh_info     = 0x0;         
                 Elf64_Xword   sh_addralign= 0x1;       
                 Elf64_Xword   sh_entsize  = 0x0;       
        };
  >> func{parse_elf64_sect_headers:(00433)} is call .


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
  [16] .text           00000001  00000021e0  008672  010932  000000  0x0006 0x0000 0x0000 0x0010
  [17] .fini           00000001  0000004c94  019604  000013  000000  0x0006 0x0000 0x0000 0x0004
  [18] .rodata         00000001  0000005000  020480  006443  000000  0x0002 0x0000 0x0000 0x0010
  [19] .eh_frame_hdr   00000001  000000692c  026924  000596  000000  0x0002 0x0000 0x0000 0x0004
  [20] .eh_frame       00000001  0000006b80  027520  002376  000000  0x0002 0x0000 0x0000 0x0008
  [21] .init_array     0000000e  0000008d18  032024  000040  000008  0x0003 0x0000 0x0000 0x0008
  [22] .fini_array     0000000f  0000008d40  032064  000040  000008  0x0003 0x0000 0x0000 0x0008
  [23] .dynamic        00000006  0000008d68  032104  000496  000016  0x0003 0x0007 0x0000 0x0008
  [24] .got            00000001  0000008f58  032600  000168  000008  0x0003 0x0000 0x0000 0x0008
  [25] .data           00000001  0000009000  032768  000624  000000  0x0003 0x0000 0x0000 0x0020
  [26] .bss            00000008  0000009270  033392  000016  000000  0x0003 0x0000 0x0000 0x0008
  [27] .comment        00000001  0000000000  033392  000043  000001  0x0030 0x0000 0x0000 0x0001
  [28] .debug_aranges  00000001  0000000000  033435  000048  000000  0x0000 0x0000 0x0000 0x0001
  [29] .debug_info     00000001  0000000000  033483  010697  000000  0x0000 0x0000 0x0000 0x0001
  [30] .debug_abbrev   00000001  0000000000  044180  000640  000000  0x0000 0x0000 0x0000 0x0001
  [31] .debug_line     00000001  0000000000  044820  003205  000000  0x0000 0x0000 0x0000 0x0001
  [32] .debug_str      00000001  0000000000  048025  003207  000001  0x0030 0x0000 0x0000 0x0001
  [33] .symtab         00000002  0000000000  051232  004944  000024  0x0000 0x0022 0x006b 0x0008
  [34] .strtab         00000003  0000000000  056176  002731  000000  0x0000 0x0000 0x0000 0x0001
  [35] .shstrtab       00000003  0000000000  058907  000346  000000  0x0000 0x0000 0x0000 0x0001
----------------------------------------------------------------
  >> func{parse_elf64_sect_headers:(00456)} is call .


  >> func{parse_elf64_prog_headers:(00492)} is call .
  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[00] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x6;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x40;
             Elf64_Addr    p_vaddr   = 0x40;
             Elf64_Addr    p_paddr   = 0x40;
             Elf64_Xword   p_filesz  = 0x2d8;
             Elf64_Xword   p_memsz   = 0x2d8;
             Elf64_Xword   p_align   = 0x8;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[01] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x3;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x318;
             Elf64_Addr    p_vaddr   = 0x318;
             Elf64_Addr    p_paddr   = 0x318;
             Elf64_Xword   p_filesz  = 0x1c;
             Elf64_Xword   p_memsz   = 0x1c;
             Elf64_Xword   p_align   = 0x1;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[02] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x1;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x0;
             Elf64_Addr    p_vaddr   = 0x0;
             Elf64_Addr    p_paddr   = 0x0;
             Elf64_Xword   p_filesz  = 0x1078;
             Elf64_Xword   p_memsz   = 0x1078;
             Elf64_Xword   p_align   = 0x1000;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[03] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x1;  
             Elf64_Word    p_flags   = 0x5;  
             Elf64_Off     p_offset  = 0x2000;
             Elf64_Addr    p_vaddr   = 0x2000;
             Elf64_Addr    p_paddr   = 0x2000;
             Elf64_Xword   p_filesz  = 0x2ca1;
             Elf64_Xword   p_memsz   = 0x2ca1;
             Elf64_Xword   p_align   = 0x1000;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[04] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x1;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x5000;
             Elf64_Addr    p_vaddr   = 0x5000;
             Elf64_Addr    p_paddr   = 0x5000;
             Elf64_Xword   p_filesz  = 0x24c8;
             Elf64_Xword   p_memsz   = 0x24c8;
             Elf64_Xword   p_align   = 0x1000;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[05] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x1;  
             Elf64_Word    p_flags   = 0x6;  
             Elf64_Off     p_offset  = 0x7d18;
             Elf64_Addr    p_vaddr   = 0x8d18;
             Elf64_Addr    p_paddr   = 0x8d18;
             Elf64_Xword   p_filesz  = 0x558;
             Elf64_Xword   p_memsz   = 0x568;
             Elf64_Xword   p_align   = 0x1000;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[06] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x2;  
             Elf64_Word    p_flags   = 0x6;  
             Elf64_Off     p_offset  = 0x7d68;
             Elf64_Addr    p_vaddr   = 0x8d68;
             Elf64_Addr    p_paddr   = 0x8d68;
             Elf64_Xword   p_filesz  = 0x1f0;
             Elf64_Xword   p_memsz   = 0x1f0;
             Elf64_Xword   p_align   = 0x8;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[07] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x4;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x338;
             Elf64_Addr    p_vaddr   = 0x338;
             Elf64_Addr    p_paddr   = 0x338;
             Elf64_Xword   p_filesz  = 0x20;
             Elf64_Xword   p_memsz   = 0x20;
             Elf64_Xword   p_align   = 0x8;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[08] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x4;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x358;
             Elf64_Addr    p_vaddr   = 0x358;
             Elf64_Addr    p_paddr   = 0x358;
             Elf64_Xword   p_filesz  = 0x44;
             Elf64_Xword   p_memsz   = 0x44;
             Elf64_Xword   p_align   = 0x4;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[09] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x6474e553;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x338;
             Elf64_Addr    p_vaddr   = 0x338;
             Elf64_Addr    p_paddr   = 0x338;
             Elf64_Xword   p_filesz  = 0x20;
             Elf64_Xword   p_memsz   = 0x20;
             Elf64_Xword   p_align   = 0x8;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[10] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x6474e550;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x692c;
             Elf64_Addr    p_vaddr   = 0x692c;
             Elf64_Addr    p_paddr   = 0x692c;
             Elf64_Xword   p_filesz  = 0x254;
             Elf64_Xword   p_memsz   = 0x254;
             Elf64_Xword   p_align   = 0x4;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[11] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x6474e551;  
             Elf64_Word    p_flags   = 0x6;  
             Elf64_Off     p_offset  = 0x0;
             Elf64_Addr    p_vaddr   = 0x0;
             Elf64_Addr    p_paddr   = 0x0;
             Elf64_Xword   p_filesz  = 0x0;
             Elf64_Xword   p_memsz   = 0x0;
             Elf64_Xword   p_align   = 0x10;
        }

  >> func{parse_elf64_prog_header:(00465)} is call .
        ProgramHeader[12] ----------------------------------------
        struct S_ELF64_ProgHeader_t 
        {
             Elf64_Word    p_type    = 0x6474e552;  
             Elf64_Word    p_flags   = 0x4;  
             Elf64_Off     p_offset  = 0x7d18;
             Elf64_Addr    p_vaddr   = 0x8d18;
             Elf64_Addr    p_paddr   = 0x8d18;
             Elf64_Xword   p_filesz  = 0x2e8;
             Elf64_Xword   p_memsz   = 0x2e8;
             Elf64_Xword   p_align   = 0x1;
        }


    ----------------------------------------------------------------
    Program Headers:
    [No] Type     Offset   VirtAddr   PhysAddr   FileSiz  MemSiz   Flags    Align
    [00] 00000006 00000040 0000000040 0000000040 0x0002d8 0x0002d8 0x000004 0x000008
    [01] 00000003 00000318 0000000318 0000000318 0x00001c 0x00001c 0x000004 0x000001
    [02] 00000001 00000000 0000000000 0000000000 0x001078 0x001078 0x000004 0x001000
    [03] 00000001 00002000 0000002000 0000002000 0x002ca1 0x002ca1 0x000005 0x001000
    [04] 00000001 00005000 0000005000 0000005000 0x0024c8 0x0024c8 0x000004 0x001000
    [05] 00000001 00007d18 0000008d18 0000008d18 0x000558 0x000568 0x000006 0x001000
    [06] 00000002 00007d68 0000008d68 0000008d68 0x0001f0 0x0001f0 0x000006 0x000008
    [07] 00000004 00000338 0000000338 0000000338 0x000020 0x000020 0x000004 0x000008
    [08] 00000004 00000358 0000000358 0000000358 0x000044 0x000044 0x000004 0x000004
    [09] 6474e553 00000338 0000000338 0000000338 0x000020 0x000020 0x000004 0x000008
    [10] 6474e550 0000692c 000000692c 000000692c 0x000254 0x000254 0x000004 0x000004
    [11] 6474e551 00000000 0000000000 0000000000 0x000000 0x000000 0x000006 0x000010
    [12] 6474e552 00007d18 0000008d18 0000008d18 0x0002e8 0x0002e8 0x000004 0x000001
    ----------------------------------------------------------------


  >> func{parse_elf64_sect_bodys:(00709)} is call .
  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=00,sect_name="",pSectData=0x55b3fc038890,iLen=0x0}
    >> func{func_process:(00666)} is call .
      >>> {idx=0, name="", pData=0x55b3fc038890, iLen=0, pSectHeader=0x55b3fc047008}.

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=01,sect_name=".interp",pSectData=0x55b3fc038ba8,iLen=0x1c}
    >> func{func_sect_interp:(00577)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=02,sect_name=".note.gnu.property",pSectData=0x55b3fc038bc8,iLen=0x20}
    >> func{func_process:(00666)} is call .
      >>> {idx=2, name=".note.gnu.property", pData=0x55b3fc038bc8, iLen=32, pSectHeader=0x55b3fc047088}.

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=03,sect_name=".note.gnu.build-id",pSectData=0x55b3fc038be8,iLen=0x24}
    >> func{func_sect_note_gnu_build_id:(00581)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=04,sect_name=".note.ABI-tag",pSectData=0x55b3fc038c0c,iLen=0x20}
    >> func{func_sect_note_ABI_tag:(00580)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=05,sect_name=".gnu.hash",pSectData=0x55b3fc038c30,iLen=0x28}
    >> func{func_sect_gnu_hash:(00582)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=06,sect_name=".dynsym",pSectData=0x55b3fc038c58,iLen=0x1e0}
    >> func{func_sect_dynsym:(00583)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=07,sect_name=".dynstr",pSectData=0x55b3fc038e38,iLen=0x102}
    >> func{func_sect_dynstr:(00584)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=08,sect_name=".gnu.version",pSectData=0x55b3fc038f3a,iLen=0x28}
    >> func{func_sect_gnu_version:(00585)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=09,sect_name=".gnu.version_r",pSectData=0x55b3fc038f68,iLen=0x40}
    >> func{func_sect_gnu_version_r:(00586)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=10,sect_name=".rela.dyn",pSectData=0x55b3fc038fa8,iLen=0x828}
    >> func{func_sect_rela_dyn:(00587)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=11,sect_name=".rela.plt",pSectData=0x55b3fc0397d0,iLen=0x138}
    >> func{func_sect_rela_plt:(00588)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=12,sect_name=".init",pSectData=0x55b3fc03a890,iLen=0x1b}
    >> func{func_sect_init:(00589)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=13,sect_name=".plt",pSectData=0x55b3fc03a8b0,iLen=0xe0}
    >> func{func_sect_plt:(00590)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=14,sect_name=".plt.got",pSectData=0x55b3fc03a990,iLen=0x10}
    >> func{func_sect_plt_got:(00591)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=15,sect_name=".plt.sec",pSectData=0x55b3fc03a9a0,iLen=0xd0}
    >> func{func_process:(00666)} is call .
      >>> {idx=15, name=".plt.sec", pData=0x55b3fc03a9a0, iLen=208, pSectHeader=0x55b3fc0473c8}.

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=16,sect_name=".text",pSectData=0x55b3fc03aa70,iLen=0x2ab4}
    >> func{func_sect_text:(00592)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=17,sect_name=".fini",pSectData=0x55b3fc03d524,iLen=0xd}
    >> func{func_sect_fini:(00593)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=18,sect_name=".rodata",pSectData=0x55b3fc03d890,iLen=0x192b}
    >> func{func_sect_rodata:(00594)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=19,sect_name=".eh_frame_hdr",pSectData=0x55b3fc03f1bc,iLen=0x254}
    >> func{func_sect_eh_frame_hdr:(00595)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=20,sect_name=".eh_frame",pSectData=0x55b3fc03f410,iLen=0x948}
    >> func{func_sect_eh_frame:(00596)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=21,sect_name=".init_array",pSectData=0x55b3fc0405a8,iLen=0x28}
    >> func{func_sect_init_array:(00597)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=22,sect_name=".fini_array",pSectData=0x55b3fc0405d0,iLen=0x28}
    >> func{func_sect_fini_array:(00598)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=23,sect_name=".dynamic",pSectData=0x55b3fc0405f8,iLen=0x1f0}
    >> func{func_sect_dynamic:(00599)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=24,sect_name=".got",pSectData=0x55b3fc0407e8,iLen=0xa8}
    >> func{func_sect_got:(00600)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=25,sect_name=".data",pSectData=0x55b3fc040890,iLen=0x270}
    >> func{func_sect_data:(00602)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=26,sect_name=".bss",pSectData=0x55b3fc040b00,iLen=0x10}
    >> func{func_sect_bss:(00603)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=27,sect_name=".comment",pSectData=0x55b3fc040b00,iLen=0x2b}
    >> func{func_sect_comment:(00604)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=28,sect_name=".debug_aranges",pSectData=0x55b3fc040b2b,iLen=0x30}
    >> func{func_sect_debug_aranges:(00605)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=29,sect_name=".debug_info",pSectData=0x55b3fc040b5b,iLen=0x29c9}
    >> func{func_sect_debug_info:(00606)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=30,sect_name=".debug_abbrev",pSectData=0x55b3fc043524,iLen=0x280}
    >> func{func_sect_debug_abbrev:(00607)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=31,sect_name=".debug_line",pSectData=0x55b3fc0437a4,iLen=0xc85}
    >> func{func_sect_debug_line:(00608)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=32,sect_name=".debug_str",pSectData=0x55b3fc044429,iLen=0xc87}
    >> func{func_sect_debug_str:(00609)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=33,sect_name=".symtab",pSectData=0x55b3fc0450b0,iLen=0x1350}
    >> func{func_sect_symtab:(00610)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=34,sect_name=".strtab",pSectData=0x55b3fc046400,iLen=0xaab}
    >> func{func_sect_strtab:(00611)} is call .

  >> func{parse_elf64_sect_body:(00676)} is call. 
      {idx=35,sect_name=".shstrtab",pSectData=0x55b3fc046eab,iLen=0x15a}
    >> func{func_sect_shstrtab:(00612)} is call .

  >> build_elf64_obj() exit;

0x0055b3fc047920|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|90 88 03 fc b3 55 00 00  90 88 03 fc b3 55 00 00|.....U.......U..|
      0x00000010|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000020|03 00 3e 00 01 00 00 00  e0 21 00 00 00 00 00 00|..>......!......|
      0x00000030|40 00 00 00 00 00 00 00  78 e7 00 00 00 00 00 00|@.......x.......|
      0x00000040|00 00 00 00 40 00 38 00  0d 00 40 00 24 00 23 00|....@.8...@.$.#.|
      0x00000050|20 89 04 fc b3 55 00 00  00 00 00 00 00 00 00 00| ....U..........|
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
      0x00000140|00 00 00 00 00 00 00 00  04 00 00 00 00 00 00 00|................|
      0x00000150|00 00 00 00 00 00 00 00  49 00 00 00 07 00 00 00|........I.......|
      0x00000160|02 00 00 00 00 00 00 00  7c 03 00 00 00 00 00 00|........|.......|
      0x00000170|7c 03 00 00 00 00 00 00  20 00 00 00 00 00 00 00||....... .......|
      0x00000180|00 00 00 00 00 00 00 00  04 00 00 00 00 00 00 00|................|
      0x00000190|00 00 00 00 00 00 00 00  57 00 00 00 f6 ff ff 6f|........W......o|
      0x000001a0|02 00 00 00 00 00 00 00  a0 03 00 00 00 00 00 00|................|
      0x000001b0|a0 03 00 00 00 00 00 00  28 00 00 00 00 00 00 00|........(.......|
      0x000001c0|06 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00|................|
      0x000001d0|00 00 00 00 00 00 00 00  61 00 00 00 0b 00 00 00|........a.......|
      0x000001e0|02 00 00 00 00 00 00 00  c8 03 00 00 00 00 00 00|................|
      0x000001f0|c8 03 00 00 00 00 00 00  e0 01 00 00 00 00 00 00|................|
      0x00000200|07 00 00 00 01 00 00 00  08 00 00 00 00 00 00 00|................|
      0x00000210|18 00 00 00 00 00 00 00  69 00 00 00 03 00 00 00|........i.......|
      0x00000220|02 00 00 00 00 00 00 00  a8 05 00 00 00 00 00 00|................|
      0x00000230|a8 05 00 00 00 00 00 00  02 01 00 00 00 00 00 00|................|
      0x00000240|00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00|................|
      0x00000250|00 00 00 00 00 00 00 00  71 00 00 00 ff ff ff 6f|........q......o|
      0x00000260|02 00 00 00 00 00 00 00  aa 06 00 00 00 00 00 00|................|
      0x00000270|aa 06 00 00 00 00 00 00  28 00 00 00 00 00 00 00|........(.......|
      0x00000280|06 00 00 00 00 ** ** **  ** ** ** ** ** ** ** **|.....***********|
      =============================================================================

  >> the app exit.
  >> func{my_fini03:(00865)@(myreadelf-0.1.05.c)} is call .
  #<<<<====
  >> func{my_fini02:(00853)@(myreadelf-0.1.05.c)} is call .
  #<<<<====
  >> func{my_fini01:(00841)@(myreadelf-0.1.05.c)} is call .
  #<<<<====
  >> func{after_main_func:(00821)@(myreadelf-0.1.05.c)} is call .
  #<<<<====
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 

#endif
