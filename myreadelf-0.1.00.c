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
    if (p_data == NULL || i_len == 0) { return 0; }
    int iret = 0;
    xlog_mutex_lock();
    
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
                xlog_info_x("%02x ", p_data[i * 16 + j]);
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
                if (j < 15) xlog_info_x("%02x ", p_data[i * 16 + j]);
                else        xlog_info_x("%02x" , p_data[i * 16 + j]);
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
                unsigned char test_char = p_data[i * 16 + j];
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
    xlog_info("  >> get_elf64_data(%s, len) entry;\n", filename);
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
        p_data = (unsigned char*)calloc(iLen, sizeof(uint8_t));
        
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

// 准备基础程序
// gcc -std=c11 -g -Wall -O0 -DXLOG_PTHREAD_T=1 myreadelf-0.1.00.c -o myapp -pthread

int main(int argc, char* argv[])
{
    xlog_init();
    xlog_info("  >> the app starting ... ...\n");
    xlog_hexdump((uint8_t*)argv, 16*10+11);
    do
    {
        char* filename = argv[0];
        uint32_t i_elf64_len  = 0;
        uint8_t* p_elf64_data = get_elf64_data(filename, &i_elf64_len);
        if(p_elf64_data==NULL || i_elf64_len==0)
        {
            xlog_info("   >>> \e[31mget_elf64_data(%s) ret(NULL).\e[0m\n", filename);
            break;
        }
        xlog_hexdump((uint8_t*)p_elf64_data, 16*20+5);
        
        free(p_elf64_data);
    }while(0);
    
    xlog_info("  >> the app exit.\n");
    xlog_uninit();
    return 0;
}

#if 0
xadmin@hw:~/xwks.git.1/myreadelf-c11$ gcc -std=c11 -g -Wall -O0 -DXLOG_PTHREAD_T=1 myreadelf-0.1.00.c -o myapp -pthread
xadmin@hw:~/xwks.git.1/myreadelf-c11$ ./myapp
  >> the app starting ... ...

0x007ffd868e3e38|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|60 56 8e 86 fd 7f 00 00  00 00 00 00 00 00 00 00|`V..............|
      0x00000010|68 56 8e 86 fd 7f 00 00  78 56 8e 86 fd 7f 00 00|hV......xV......|
      0x00000020|90 56 8e 86 fd 7f 00 00  a7 56 8e 86 fd 7f 00 00|.V.......V......|
      0x00000030|bb 56 8e 86 fd 7f 00 00  d3 56 8e 86 fd 7f 00 00|.V.......V......|
      0x00000040|fd 56 8e 86 fd 7f 00 00  0c 57 8e 86 fd 7f 00 00|.V.......W......|
      0x00000050|21 57 8e 86 fd 7f 00 00  30 57 8e 86 fd 7f 00 00|!W......0W......|
      0x00000060|42 57 8e 86 fd 7f 00 00  57 57 8e 86 fd 7f 00 00|BW......WW......|
      0x00000070|68 57 8e 86 fd 7f 00 00  4a 5d 8e 86 fd 7f 00 00|hW......J]......|
      0x00000080|7f 5d 8e 86 fd 7f 00 00  a1 5d 8e 86 fd 7f 00 00|.].......]......|
      0x00000090|b8 5d 8e 86 fd 7f 00 00  d6 5d 8e 86 fd 7f 00 00|.].......]......|
      0x000000a0|e1 5d 8e 86 fd 7f 00 00  01 5e 8e ** ** ** ** **|.].......^.*****|
      =============================================================================

  >> get_elf64_data(./myapp, len) entry;

0x00559a3c5b2890|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|
      =============================================================================
      0x00000000|7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00|.ELF............|
      0x00000010|03 00 3e 00 01 00 00 00  00 12 00 00 00 00 00 00|..>.............|
      0x00000020|40 00 00 00 00 00 00 00  00 56 00 00 00 00 00 00|@........V......|
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
      0x000000d0|c0 09 00 00 00 00 00 00  c0 09 00 00 00 00 00 00|................|
      0x000000e0|00 10 00 00 00 00 00 00  01 00 00 00 05 00 00 00|................|
      0x000000f0|00 10 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000100|00 10 00 00 00 00 00 00  c1 0c 00 00 00 00 00 00|................|
      0x00000110|c1 0c 00 00 00 00 00 00  00 10 00 00 00 00 00 00|................|
      0x00000120|01 00 00 00 04 00 00 00  00 20 00 00 00 00 00 00|......... ......|
      0x00000130|00 20 00 00 00 00 00 00  00 20 00 00 00 00 00 00|. ....... ......|
      0x00000140|70 04 00 00 00 ** ** **  ** ** ** ** ** ** ** **|p....***********|
      =============================================================================

  >> the app exit.
xadmin@hw:~/xwks.git.1/myreadelf-c11$ 
#endif
