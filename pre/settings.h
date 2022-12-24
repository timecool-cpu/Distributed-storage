#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>

// 输出彩色文字
void print_green_color(const char *text) { printf("\x1b[32m%s\x1b[39m", text); }
void print_red_color(const char *text) { printf("\x1b[31m%s\x1b[39m", text); }

// 测量文件大小的函数
unsigned long get_file_size(char *fname)
{
    long size;
    FILE *fgetfilesize;
    if ((fgetfilesize = fopen(fname, "rb")) == NULL)
    {
        printf("无法打开文件%s。\n", fname);
        return -1;
    }
    fseek(fgetfilesize, 0, SEEK_END);
    size = ftell(fgetfilesize);
    fclose(fgetfilesize);
    return size;
}

// fclose的多文件指定对应版
// 参数的末尾必须为空
int fcloses(FILE *fps, ...)
{
    FILE *fp;
    va_list ap;
    va_start(ap, fps);
    for (fp = fps; fp != NULL; fp = va_arg(ap, FILE *))
    {
        if (fclose(fp) != 0)
        {
            printf("fclose时出错。");
            va_end(ap);
            return -1;
        }
    }
    va_end(ap);
    return 0;
}

// free的多指针指定对应版
// 参数的末尾必须为空
int frees(void *ptrs, ...)
{
    FILE *ptr;
    va_list ap;
    va_start(ap, ptrs);
    for (ptr = ptrs; ptr != NULL; ptr = va_arg(ap, void *))
        free(ptr);
    va_end(ap);
    return 0;
}

/* -----------------------------------------------
 // 将无符号长整数转换为 16 进制 char 字符串的函数
    $0 char 数组地址，用于存储转换结果
    $1 需要转换的无符号长整数
 -----------------------------------------------*/
void convert_long_type_into_hex_string(char *result, const unsigned long x)
{
    unsigned long original = x;
    *result = '\0';
    do
    {
        char tmp;
        sprintf(&tmp, "%X", original % 16);
        strcat(result, &tmp);
    } while ((original /= 16) != 0);
    char t, *p, *q;
    for (p = result, q = &(result[strlen(result) - 1]); p < q; p++, q--)
        t = *p, *p = *q, *q = t;
}

/* -----------------------------------------------
 // 将 16 进制 char 字符串转换为无符号长整数的函数
    $0 需要转换的 char 数组地址
    @return 转换结果的无符号长整数
 -----------------------------------------------*/
unsigned long convert_hex_string_into_long_type(const char *x)
{
    unsigned long result = 0, exp = 1;
    int length = strlen(x) - 1, i;
    for (i = length; i >= 0; i--)
    {
        char tmp_char = *(x + i);
        unsigned long tmp_long;
        sscanf(&tmp_char, "%X", &tmp_long);
        result += tmp_long * exp;
        exp *= 16;
    }
    return result;
}

/* -----------------------------------------------
// 使用 mpz_t 生成随机值的函数
    $0 变量，用于存储生成的值
    $1 上限值
参考网站：https://sehermitage.web.fc2.com/etc/gmp_src.html
 -----------------------------------------------*/
void create_mpz_t_random(mpz_t op, const mpz_t n)
{
    gmp_randstate_t state;
    gmp_randinit_default(state);

    struct timeval tv, tv2;
    gettimeofday(&tv2, NULL);

    do
    {
        gettimeofday(&tv, NULL);
    } while (tv.tv_usec == tv2.tv_usec);

    gmp_randseed_ui(state, tv.tv_usec);
    mpz_urandomm(op, state, n);

    gmp_randclear(state);
}

// 确认文件存在的函数（0:false，1:true）
int file_exist(char *dir_path, char *filename)
{
    DIR *dir;
    struct dirent *dp;
    int ret = 0;

    dir = opendir(dir_path);
    for (dp = readdir(dir); dp != NULL; dp = readdir(dir))
        if (strcmp(dp->d_name, filename) == 0)
            ret = 1;
    closedir(dir);

    return ret;
}

// 输出错误内容的函数
// format: error_notice(code, memo, __func__, __LINE__);
void error_notice(int error_code, char *memo, const char *func_name, int line)
{
    printf("\x1b[31m"); // 输出红色字体
    printf("ERROR CODE(%d): ", error_code);
    switch (error_code)
    {
    case 1000:
        printf("MEMORY ALLOCATION ERROR\n");
        printf("无法分配 %s 的内存。\n", memo);
        break;
    case 1001:
        printf("FILE OPEN ERROR\n");
        printf("无法打开 %s.txt 来写入密钥。\n", memo);
        break;
    case 1002:
        printf("FILE OPEN ERROR\n");
        printf("无法打开 %s 来读取密钥。\n", memo);
        if (strcmp(memo, "keyC") == 0)
            printf("可能没有执行解密操作。\n");
        break;
    case 1003:
        printf("FOLDER OPEN ERROR\n");
        printf("无法打开文件夹 %s。\n", memo);
        break;
    case 2000:
        printf("DATA FORMAT ERROR\n");
        printf("无法解密的数据格式。\n");
        break;
    case 2001:
        printf("DATA FORMAT ERROR\n");
        printf("可以解密的数据格式。\n");
        break;
    case 2002:
        printf("DATA FORMAT ERROR\n");
        printf("仅可以加密一次的数据格式。\n");
        break;
    case 9999:
        printf("UNKNOWN ERROR\n");
        printf("发生未知错误。");
        break;
    default:
        printf("UNKNOWN ERROR\n");
        break;
    }
    printf("[debug info] %d: %s\n", line, func_name);
    printf("\x1b[39m"); // 还原字体颜色
    exit(1);
}
