#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
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

//===============================================================

struct s_elf64_obj_t
{
    uint8_t*                    pElfData   ;
    struct S_ELF64_ELFHeader_t* pElfHeader ;
};

struct s_elf64_obj_t* build_elf64_obj(uint8_t* p_elf64_data, uint32_t len)
{
    xlog_info("  >> build_elf64_obj(%p, %d) entry;\n", p_elf64_data, len);
    
    unsigned int elf64_obj_size = sizeof(struct s_elf64_obj_t);
    
    struct s_elf64_obj_t* p_elf64_obj = (struct s_elf64_obj_t*)calloc(elf64_obj_size/4+6, 4);
    
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
xadmin@hw:~/xwks.git.1/myreadelf-c11$ gcc -std=c11 -g -Wall -O0  myreadelf-0.1.02.c -o myapp
xadmin@hw:~/xwks.git.1/myreadelf-c11$ ./myapp
################################################{}##################################################
  #====>>>>
  >> func{before_main_func:(00364)@(myreadelf-0.1.02.c)} is call .
  #====>>>>
  >> func{my_init01:(00385)@(myreadelf-0.1.02.c)} is call .
  #====>>>>
  >> func{my_init02:(00397)@(myreadelf-0.1.02.c)} is call .
  #====>>>>
  >> func{my_init03:(00409)@(myreadelf-0.1.02.c)} is call .
  >> the app starting ... ...

0x007fffd6433e58|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|60 46 43 d6 ff 7f 00 00  00 00 00 00 00 00 00 00|`FC.............|
      0x00000010|68 46 43 d6 ff 7f 00 00  78 46 43 d6 ff 7f 00 00|hFC.....xFC.....|
      0x00000020|90 46 43 d6 ff 7f 00 00  a7 46 43 d6 ff 7f 00 00|.FC......FC.....|
      0x00000030|bb 46 43 d6 ff 7f 00 00  d3 46 43 d6 ff 7f 00 00|.FC......FC.....|
      0x00000040|fd 46 43 d6 ff 7f 00 00  0c 47 43 d6 ff 7f 00 00|.FC......GC.....|
      0x00000050|21 47 43 d6 ff 7f 00 00  30 47 43 ** ** ** ** **|!GC.....0GC*****|
      =============================================================================


0x007fffd6434660|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|2e 2f 6d 79 61 70 70 00  53 48 45 4c 4c 3d 2f 62|./myapp.SHELL=/b|
      0x00000010|69 6e 2f 62 61 73 68 00  4c 41 4e 47 55 41 47 45|in/bash.LANGUAGE|
      0x00000020|3d 7a 68 5f 43 4e 3a 65  6e 5f 55 53 3a 65 6e 00|=zh_CN:en_US:en.|
      0x00000030|4c 43 5f 41 44 44 52 45  53 53 3d 7a 68 5f 43 4e|LC_ADDRESS=zh_CN|
      0x00000040|2e 55 54 46 2d 38 00 4c  43 5f 4e 41 4d 45 3d 7a|.UTF-8.LC_NAME=z|
      0x00000050|68 5f 43 4e 2e 55 54 46  2d 38 00 ** ** ** ** **|h_CN.UTF-8.*****|
      =============================================================================

  >> func:parse_args(1, 0x7fffd6433e58) is called. (@file:myreadelf-0.1.02.c,line:0423).

    >>> argv[00](addr=0x7fffd6434660) = {"./myapp"}.

  >> func:parse_args() is called. @line:(0430).
  >> get_elf64_data("./myapp", len) entry;

0x00563a69597890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  80 11 00 00 00 00 00 00|..>.............|
      0x00000020|40 00 00 00 00 00 00 00  38 6d 00 00 00 00 00 00|@.......8m......|
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
      0x000000d0|38 09 00 00 00 00 00 00  38 09 00 00 00 00 00 00|8.......8.......|
      0x000000e0|00 10 00 00 00 00 00 00  01 00 00 00 05 00 00 00|................|
      0x000000f0|00 10 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000100|00 10 00 00 00 00 00 00  81 12 00 00 00 00 00 00|................|
      0x00000110|81 12 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000120|01 00 00 00 04 00 00 00  00 30 00 00 00 00 00 00|.........0......|
      0x00000130|00 30 00 00 00 00 00 00  00 30 00 00 00 00 00 00|.0.......0......|
      0x00000140|48 0c 00 00 00 ** ** **  ** ** ** ** ** ** ** **|H....***********|
      =============================================================================

  >> build_elf64_obj(0x563a69597890, 30264) entry;
  >> func{parse_elf64_elf_header:(00272)} is call.{pElfData=0x563a69597890}.
        struct S_ELF64_ELFHeader_t pElfHeader = {0x563a69597890} 
        {
                 unsigned char e_ident[16] = {7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00};
                 Elf64_Half    e_type      = 0x0003;
                 Elf64_Half    e_machine   = 0x003e;
                 Elf64_Word    e_version   = 0x1  ;
                 Elf64_Addr    e_entry     = 0x1180;
                 Elf64_Off     e_phoff     = 0x40;
                 Elf64_Off     e_shoff     = 0x6d38;
                 Elf64_Word    e_flags     = 0x0  ;
                 Elf64_Half    e_ehsize    = 0x0040;
                 Elf64_Half    e_phentsize = 0x0038;
                 Elf64_Half    e_phnum     = 0x000d;
                 Elf64_Half    e_shentsize = 0x0040;
                 Elf64_Half    e_shnum     = 0x0024;
                 Elf64_Half    e_shstrndx  = 0x0023;
        };
  >> build_elf64_obj() exit;

0x00563a6959eee0|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|90 78 59 69 3a 56 00 00  90 78 59 69 3a 56 00 00|.xYi:V...xYi:V..|
      0x00000010|00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00|................|
      0x00000020|00 00 00 00 00 00 00 00  01 91 01 00 00 00 00 00|................|
      0x00000030|18 00 00 00 00 00 00 00  a1 00 00 00 01 00 00 00|................|
      0x00000040|06 00 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000050|00 10 00 00 00 00 00 00  1b 00 00 00 00 00 00 00|................|
      0x00000060|00 00 00 00 00 00 00 00  04 00 00 00 00 00 00 00|................|
      0x00000070|00 00 00 00 00 00 00 00  9c 00 00 00 01 00 00 00|................|
      0x00000080|06 00 00 00 00 00 00 00  20 10 00 00 00 00 00 00|........ .......|
      0x00000090|20 10 00 00 00 00 00 00  b0 00 00 00 00 00 00 00| ...............|
      0x000000a0|00 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00|................|
      0x000000b0|10 00 00 00 00 00 00 00  a7 00 00 00 01 00 00 00|................|
      0x000000c0|06 00 00 00 00 00 00 00  d0 10 00 00 00 00 00 00|................|
      0x000000d0|d0 10 00 00 00 00 00 00  10 00 00 00 00 00 00 00|................|
      0x000000e0|00 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00|................|
      0x000000f0|10 00 00 00 00 00 00 00  b0 00 00 00 01 00 00 00|................|
      0x00000100|06 00 00 00 00 00 00 00  e0 10 00 00 00 00 00 00|................|
      0x00000110|e0 10 00 00 00 00 00 00  a0 00 00 00 00 00 00 00|................|
      0x00000120|00 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00|................|
      0x00000130|10 00 00 00 00 00 00 00  b9 00 00 00 01 00 00 00|................|
      0x00000140|06 00 00 00 00 ** ** **  ** ** ** ** ** ** ** **|.....***********|
      =============================================================================

  >> the app exit.
  >> func{my_fini03:(00414)@(myreadelf-0.1.02.c)} is call .
  #<<<<====
  >> func{my_fini02:(00402)@(myreadelf-0.1.02.c)} is call .
  #<<<<====
  >> func{my_fini01:(00390)@(myreadelf-0.1.02.c)} is call .
  #<<<<====
  >> func{after_main_func:(00370)@(myreadelf-0.1.02.c)} is call .
  #<<<<====
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 


#endif
