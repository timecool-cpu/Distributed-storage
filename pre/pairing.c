// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto -fopenmp
// clang -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto -Xpreprocessor -fopenmp
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> //pass, getopt
// #include <omp.h>

#include <gmp.h>
#include <dirent.h>
#include "ec.h"
#include "settings.h"
// #include "openssl/evp.h"
#include <openssl/evp.h>

#define USER_A_DIR "A"
#define USER_B_DIR "B"
#define ENCRYPT_IN_DIR "Plain"
#define ENCRYPT_OUT_DIR "Enc"
#define RE_ENCRYPT_IN_DIR "Enc"
#define RE_ENCRYPT_OUT_DIR "Enc"
#define DECRYPT_IN_DIR "Enc"
#define DECRYPT_OUT_DIR "Dec"

EC_PAIRING p;
EC_POINT P, Q;
mpz_t limit, a, b, sec_key, r;
int data_print = 0, size_print = 0, time_print = 0;
char str[1000];
double start_time, finish_time;

void set_crypto_data();
void free_crypto_data();
char *get_str_data(char *user, char *data);
void option_analyze(int argc, char *argv[]);
void calc_result_str_convert_to_key_origin(char *key, Element calc_result);

// 实际运行AES的函数
int AES(char *in_fname, char *out_fname, unsigned char *key, unsigned char *iv, int do_encrypt)
{
    // do_encrypt: 1:暗号化 / 0:復号

    // Allow enough space in output buffer for additional block
    // Bogus key and IV: we'd normally set these from another source.

    // unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    unsigned char *inbuf, *outbuf;
    int inlen, outlen;

    FILE *fin, *fout;
    fin = fopen(in_fname, "rb");
    fout = fopen(out_fname, "wb");

    // 设置缓冲区大小
    unsigned long in_size;
    in_size = get_file_size(in_fname);
    if (size_print)
        printf("[size = %9lu]", in_size);

    if ((inbuf = malloc(sizeof(char) * in_size)) == NULL)
        error_notice(1000, "inbuf", __func__, __LINE__);
    if ((outbuf = malloc(sizeof(char) * (int)(in_size + EVP_MAX_BLOCK_LENGTH))) == NULL)
        error_notice(1000, "outbuf", __func__, __LINE__);
    start_time = omp_get_wtime();
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

    // 设置AES128的密钥和初始向量
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);
    for (;;)
    {
        // 从文件指针fin到缓冲器inbuf大小为1的数据in_导入size个
        // inlen返回导入的个数
        inlen = fread(inbuf, 1, in_size, fin);
        if (inlen <= 0)
            break;
        if (!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
        { // Error
            EVP_CIPHER_CTX_cleanup(&ctx);
            fcloses(fin, fout, NULL);
            frees(inbuf, outbuf, NULL);
            return 0;
        }
        fwrite(outbuf, 1, outlen, fout);
    }
    if (!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
    { // Error
        EVP_CIPHER_CTX_cleanup(&ctx);
        fcloses(fin, fout, NULL);
        frees(inbuf, outbuf, NULL);
        return 0;
    }
    fwrite(outbuf, 1, outlen, fout);
    finish_time = omp_get_wtime();
    if (time_print)
        printf("[time = %23.20lf] ", finish_time - start_time);
    EVP_CIPHER_CTX_cleanup(&ctx);
    fcloses(fin, fout, NULL);
    frees(inbuf, outbuf, NULL);
    return 1;
}

// 输出密钥的函数
void output_key_txt(char *output_name, char *outfolda, char *key1, char *key2)
{
    FILE *outfile;
    char openfilename[1000];
    sprintf(openfilename, "%s/%s.txt", outfolda, output_name);
    outfile = fopen(openfilename, "w+");
    if (outfile == NULL)
        error_notice(1001, output_name, __func__, __LINE__);
    fprintf(outfile, "%s\n", key1);
    fprintf(outfile, "%s", key2);
    fclose(outfile);
}

// 导入密钥的函数
void load_key_txt(char *load_name, char *infolda, char *key1, char *key2)
{
    FILE *loadfile;
    char loadfilename[1000], str[1024];
    sprintf(loadfilename, "%s/%s.txt", infolda, load_name);
    loadfile = fopen(loadfilename, "r");
    if (loadfile == NULL)
        error_notice(1002, loadfilename, __func__, __LINE__);
    fgets(str, 1024, loadfile);
    str[strlen(str) - 1] = '\0';
    strcpy(key1, str);
    fgets(str, 1024, loadfile);
    strcpy(key2, str);
    fclose(loadfile);
}

// 加密密钥的函数
void encipher_keyA(char *msg)
{
    int i, msg_len = strlen(msg), roop_num = msg_len / sizeof(long) + 1;
    start_time = omp_get_wtime();
    /* -- g = e(P, Q)^r 生成 --- */
    Element g;
    element_init(g, p->g3);
    pairing_map(g, P, Q, p);
    element_pow(g, g, r);
    /* --- 将明文设为long型后，转换为十六进制表示的char型 --- */
    unsigned long enc_msg_long[1024];
    memset(enc_msg_long, 0, sizeof(enc_msg_long));
    memcpy(enc_msg_long, msg, msg_len);
    /* --- 将十六进制表示的char型明文转换为Element型 --- */
    Element element_msg;
    element_init(element_msg, p->g3);
    char element_assign_str[1000] = "";
    for (i = 0; i < 12; i++)
    {
        if (roop_num > i)
        {
            char tmp[100];
            convert_long_type_into_hex_string(tmp, enc_msg_long[i]);
            strcat(element_assign_str, tmp);
        }
        else
            strcat(element_assign_str, "0");
        if (i != 11)
            strcat(element_assign_str, " ");
    }
    element_set_str(element_msg, element_assign_str);
    /* --- 字符串和密钥相乘 --- */
    Element element_msg_key_calc_result;
    element_init(element_msg_key_calc_result, p->g3);
    element_mul(element_msg_key_calc_result, element_msg, g);
    finish_time = omp_get_wtime();
    if (time_print)
        printf("[key encrypt time = %.20lf]\n", finish_time - start_time);
    /* --- 将计算结果插入到msg中 --- */
    element_get_str(msg, element_msg_key_calc_result);
    /* --- Field liberation --- */
    element_clear(g);
    element_clear(element_msg);
    element_clear(element_msg_key_calc_result);
}
void encipher_keyB_once_mode(char *keyB)
{
    /* --- g^(ra) 計算 --- */
    EC_POINT raP;
    point_init(raP, p->g1);
    point_set_str(raP, get_str_data(USER_A_DIR, "aP"));
    point_mul(raP, r, raP);
    Element gra;
    element_init(gra, p->g3);
    pairing_map(gra, raP, Q, p);
    element_get_str(keyB, gra);
    /* --- Field liberation --- */
    point_clear(raP);
    element_clear(gra);
}
void encipher_keyB_twice_mode(char *keyB)
{
    /* --- r(aQ) 計算 --- */
    EC_POINT raQ;
    point_init(raQ, p->g2);
    point_set_str(raQ, get_str_data(USER_A_DIR, "aQ"));
    point_mul(raQ, r, raQ);
    point_get_str(keyB, raQ);
    /* --- Field liberation --- */
    point_clear(raQ);
}

// 重新加密密钥的函数
void re_encipher_key(char *raQ_char, char *keyC)
{
    start_time = omp_get_wtime();
    /* --- r(aQ) 设置 --- */
    EC_POINT raQ;
    point_init(raQ, p->g2);
    point_set_str(raQ, raQ_char);
    /* --- 创建重新加密密钥（（1/a）bP） --- */
    /* --- 设置a --- */
    mpz_set_str(a, get_str_data(USER_A_DIR, "a"), 10);
    /* --- 计算1/a --- */
    mpz_t a_one;
    mpz_init(a_one);
    mpz_invert(a_one, a, limit);
    /* --- 设置bP --- */
    EC_POINT bP;
    point_init(bP, p->g1);
    point_set_str(bP, get_str_data(USER_A_DIR, "bP"));
    /* --- 生成重新加密密钥 --- */
    EC_POINT re_Key;
    point_init(re_Key, p->g1);
    point_mul(re_Key, a_one, bP);
    /* --- grb = e((1/a)bP, raQ) = e(P, Q)^rb --- */
    Element grb;
    element_init(grb, p->g3);
    pairing_map(grb, re_Key, raQ, p);
    finish_time = omp_get_wtime();
    if (time_print)
        printf("[key re-encrypt time = %.20lf]\n", finish_time - start_time);
    int grb_char_size = element_get_str_length(grb);
    char *grb_char;
    if ((grb_char = (char *)malloc(element_get_str_length(grb) + 1)) == NULL)
        error_notice(1000, "grb_char", __func__, __LINE__);
    element_get_str(grb_char, grb);
    strcpy(keyC, grb_char);
    /* --- free --- */
    point_clear(bP);
    point_clear(re_Key);
    mpz_clear(a_one);
    element_clear(grb);
}

// 实现解密的函数
void decode_key_type_point(char *key, char *point_char, char *user, char sec_key)
{
    start_time = omp_get_wtime();
    // / --- 设置 r(aQ) --- /
    EC_POINT raQ;
    point_init(raQ, p->g2);
    point_set_str(raQ, point_char);
    // / --- 设置 a --- /
    mpz_set_str(a, get_str_data(user, sec_key), 10);
    // / --- 计算 1/a --- /
    mpz_t a_one;
    mpz_init(a_one);
    mpz_invert(a_one, a, limit);
    // / --- 计算 (1/a)P --- /
    EC_POINT a1P;
    point_init(a1P, p->g1);
    point_mul(a1P, a_one, P);
    // / --- 计算 g2 = e((1/a)P, raQ) = e(P, Q)^r --- /
    Element g2;
    element_init(g2, p->g3);
    pairing_map(g2, a1P, raQ, p);
    // / --- 计算 g2 的逆元 --- /
    Element g2_inv;
    element_init(g2_inv, p->g3);
    element_inv(g2_inv, g2);
    // / --- 将密钥设置为 Element --- /
    Element mgr;
    element_init(mgr, p->g3);
    element_set_str(mgr, key);
    // / --- 进行除法（mg^r/g^r） --- /
    Element calc_result;
    element_init(calc_result, p->g3);
    element_mul(calc_result, mgr, g2_inv);
    // / --- 转换 --- /
    calc_result_str_convert_to_key_origin(key, calc_result);
    // / --- 释放内存 --- */
    mpz_clear(a_one);
    point_clear(raQ);
    point_clear(a1P);
    element_clear(g2);
    element_clear(g2_inv);
    element_clear(mgr);
    element_clear(calc_result);
}
// 实现解密的函数
void decode_key_type_element(char *key, char *grs_char, char *user, char sec_key_char)
{
    start_time = omp_get_wtime();
    // --- 设置元素（g^(ra)||g^(rb）--- /
    Element grs;
    element_init(grs, p->g3);
    element_set_str(grs, grs_char);
    // / --- 设置秘密键（a||b） --- /
    mpz_set_str(sec_key, get_str_data(user, sec_key_char), 10);
    // / --- 计算 1/(secret_key) --- /
    mpz_t sec_key_one;
    mpz_init(sec_key_one);
    mpz_invert(sec_key_one, sec_key, limit);
    // / --- 计算 g^r --- /
    Element gr;
    element_init(gr, p->g3);
    element_pow(gr, grs, sec_key_one);
    // / --- 计算 g^r 的逆元 --- /
    Element gr_inv;
    element_init(gr_inv, p->g3);
    element_inv(gr_inv, gr);
    // / --- 将密钥设置为 Element --- /
    Element mgr;
    element_init(mgr, p->g3);
    element_set_str(mgr, key);
    // / --- 进行除法（mg^r/g^r） --- /
    Element calc_result;
    element_init(calc_result, p->g3);
    element_mul(calc_result, mgr, gr_inv);
    // / --- 转换 --- /
    calc_result_str_convert_to_key_origin(key, calc_result);
    // / --- 释放内存 --- */
    element_clear(grs);
    element_clear(gr);
    element_clear(gr_inv);
    element_clear(mgr);
    element_clear(calc_result);
    mpz_clear(sec_key_one);
}
void decode_key_type_point(char *key, char *point_char, char *user, char *sec_key)
{
    start_time = omp_get_wtime();
    /* --- r(aQ) をセット --- */
    EC_POINT raQ;
    point_init(raQ, p->g2);
    point_set_str(raQ, point_char);
    /* --- aをセット --- */
    mpz_set_str(a, get_str_data(user, sec_key), 10);
    /* --- 1/aを計算 --- */
    mpz_t a_one;
    mpz_init(a_one);
    mpz_invert(a_one, a, limit);
    /* --- (1/a)Pを計算 --- */
    EC_POINT a1P;
    point_init(a1P, p->g1);
    point_mul(a1P, a_one, P);
    /* --- g2 = e((1/a)P, raQ) = e(P, Q)^r --- */
    Element g2;
    element_init(g2, p->g3);
    pairing_map(g2, a1P, raQ, p);
    /* --- g2の逆元を計算 --- */
    Element g2_inv;
    element_init(g2_inv, p->g3);
    element_inv(g2_inv, g2);
    /* --- 鍵をElementにセットする --- */
    Element mgr;
    element_init(mgr, p->g3);
    element_set_str(mgr, key);
    /* --- 割り算する(mg^r/g^r) --- */
    Element calc_result;
    element_init(calc_result, p->g3);
    element_mul(calc_result, mgr, g2_inv);
    /* --- 変換 --- */
    calc_result_str_convert_to_key_origin(key, calc_result);
    /* --- 領域解放 --- */
    mpz_clear(a_one);
    point_clear(raQ);
    point_clear(a1P);
    element_clear(g2);
    element_clear(g2_inv);
    element_clear(mgr);
    element_clear(calc_result);
}
// 将元素型m转换为char
void calc_result_str_convert_to_key_origin(char *key, Element calc_result)
{
    /* --- 将元素转换为十六进制字符串 --- */
    int calc_result_str_size = element_get_str_length(calc_result);
    char *calc_result_str;
    if ((calc_result_str = (char *)malloc(calc_result_str_size + 1)) == NULL)
        error_notice(1000, "calc_result_str", __func__, __LINE__);
    element_get_str(calc_result_str, calc_result);
    /* --- 用空格分隔str并将其转换为long型 --- */
    int i = 1;
    unsigned long dec_msg_long[12];
    char dec_msg_str[12][128], *ptr = strtok(calc_result_str, " ");
    strcpy(dec_msg_str[0], ptr);
    while (ptr != NULL)
    {
        ptr = strtok(NULL, " ");
        if (ptr != NULL)
            strcpy(dec_msg_str[i], ptr);
        i++;
    }
    for (i = 0; i < 12; i++)
        if (strcmp(dec_msg_str[i], "0") != 0)
            dec_msg_long[i] = convert_hex_string_into_long_type(dec_msg_str[i]);
    /* --- decode --- */
    char msg_decode[1024];
    memset(msg_decode, 0, sizeof(msg_decode));
    memcpy(msg_decode, dec_msg_long, sizeof(char) * 70); // 
    finish_time = omp_get_wtime();
    if (time_print)
        printf("[key decrypt time = %.20lf]\n", finish_time - start_time);
    print_green_color("AES key = ");
    printf("%s\n", msg_decode);
    strcpy(key, msg_decode);
    /* --- 領域解放 --- */
    free(calc_result_str);
}

// 检查不加密和解密的文件名
int check_filename(char *filename)
{
    int ret = 0;
    if (strcmp(filename, "C_a.txt") == 0)
        ret = 1;
    else if (strcmp(filename, "C_b.txt") == 0)
        ret = 1;
    return ret;
}

// 读取文件、加密、解密（执行函数）的函数
void file_conversion(int do_encrypt, char *infolda, char *outfolda, char *key, unsigned char *iv)
{
    DIR *indir;
    struct dirent *dp;
    char original[1024], operated[1024];
    indir = opendir(infolda);

    for (dp = readdir(indir); dp != NULL; dp = readdir(indir))
    {
        if (*dp->d_name != '.')
        {
            if (check_filename(dp->d_name))
            {
                if (do_encrypt)
                    printf("规格上不能加密“%s ，跳过加密．\n", dp->d_name);
                continue;
            }
            sprintf(original, "%s/%s", infolda, dp->d_name);  // 生成原始文件名
            sprintf(operated, "%s/%s", outfolda, dp->d_name); // 处理文件名生成
            AES(original, operated, key, iv, do_encrypt);     // 文件加密/解密处理
            printf("%s -> %s\n", original, operated);
        }
    }
    closedir(indir);
}

// 加密模式
void encrypt_mode(unsigned char *iv)
{
    int mode = 0;
    char keyA[1024], keyB[1024];

    while (1)
    {
        printf("如果不希望重新加密，请输入1，如果希望重新加密，请输入2： ");
        scanf("%d", &mode);
        if (mode != 0)
            break;
        print_red_color("请输入1或2。\n");
    }
    print_green_color("进行加密\n");
    while (1)
    {
        printf("输入AES密钥（15-70个字符）： ");
        scanf("%s", keyA);
        if (15 <= strlen(keyA) && strlen(keyA) <= 70)
            break;
        else
            print_red_color("请输入15个以上70个字符以内。\n");
    }

    // 文件加密
    file_conversion(1, ENCRYPT_IN_DIR, ENCRYPT_OUT_DIR, keyA, iv);

    // 密钥加密
    set_crypto_data();
    encipher_keyA(keyA);
    if (mode == 1)
        encipher_keyB_once_mode(keyB);
    else if (mode == 2)
        encipher_keyB_twice_mode(keyB);
    free_crypto_data();

    /* --- 输出 --- */
    output_key_txt("C_a", ENCRYPT_OUT_DIR, keyA, keyB);
    print_green_color("データの暗号化が完了しました．\n");
}

// 重新加密模式
void re_encrypt_mode()
{
    char keyA[1024], keyB[1024], keyC[1024];
    load_key_txt("C_a", RE_ENCRYPT_IN_DIR, keyA, keyB);
    if (*keyB != '[')
        error_notice(2000, "", __func__, __LINE__);
    print_green_color("重新加密．\n");
    set_crypto_data();
    re_encipher_key(keyB, keyC);
    free_crypto_data();
    output_key_txt("C_b", RE_ENCRYPT_OUT_DIR, keyA, keyC);
    print_green_color("重新加密已完成．\n");
}

// 解码模式
void decrypt_mode(unsigned char *iv)
{
    int mode;
    char keyA[1024], keyB[1024];

    // 解码模式决定
    if (file_exist("./Enc/", "C_b.txt"))
    {
        load_key_txt("C_b", DECRYPT_IN_DIR, keyA, keyB);
        mode = 1;
    }
    else
    {
        load_key_txt("C_a", DECRYPT_IN_DIR, keyA, keyB);
        mode = *keyB == '[' ? 2 : 3;
    }

    // Duplicate sign
    set_crypto_data();
    if (mode == 1)
    {
        print_green_color("开始解密重新加密的数据．\n");
        decode_key_type_element(keyA, keyB, USER_B_DIR, "b");
    }
    else if (mode == 2)
    {
        print_green_color("开始解密重新加密的数据．\n");
        decode_key_type_point(keyA, keyB, USER_A_DIR, "a");
    }
    else if (mode == 3)
    {
        print_green_color("开始解密无法重新加密的数据．\n");
        decode_key_type_element(keyA, keyB, USER_A_DIR, "a");
    }
    free_crypto_data();

    // 文件解密
    file_conversion(0, DECRYPT_IN_DIR, DECRYPT_OUT_DIR, keyA, iv);
    print_green_color("解密已完成．\n");
}

int main(int argc, char *argv[])
{
    // key -> A: mg^r, B: g^(ra)||r(aQ), C: g^rb
    unsigned char iv[] = "0123456789abcdef";
    int input, mode;

    // 选项识别
    option_analyze(argc, argv);

    // 模式确定
    while (1)
    {
        printf("要加密的话输入1,要再加密的话输入2,要解密的话输入0: ");
        scanf("%d", &mode);
        if (mode == 1 || mode == 2 || mode == 0)
            break;
        print_red_color("0, 1, 2中选择另一种天花板类型\n");
    }

    if (mode == 1)
        encrypt_mode(iv);
    else if (mode == 2)
        re_encrypt_mode(iv);
    else if (mode == 0)
        decrypt_mode(iv);

    return 0;
}

void set_crypto_data()
{
    /* --- 初期化 --- */
    pairing_init(p, "ECBN254a");
    point_init(P, p->g1);
    point_init(Q, p->g2);
    mpz_init(sec_key);
    mpz_init(a);
    mpz_init(b);
    mpz_init(r);
    mpz_init(limit);
    /* --- 设置上限值 --- */
    mpz_set_str(limit, get_str_data("ALL", "limit"), 10);
    /* --- 设置随机数r --- */
    create_mpz_t_random(r, limit);
    /* --- 设置点P、Q --- */
    point_init(P, p->g1);
    point_set_str(P, get_str_data("ALL", "P"));
    point_init(Q, p->g2);
    point_set_str(Q, get_str_data("ALL", "Q"));
}
void free_crypto_data()
{
    point_clear(P);
    point_clear(Q);
    mpz_clears(a, b, r, sec_key, limit, NULL);
    pairing_clear(p);
}

char *get_str_data(char *user, char *data)
{
    /* --- 通知 --- */
    if (data_print)
    {
        printf("\x1b[46m\x1b[30m");
        if (strcmp(user, "ALL") == 0)
            printf("已获取数据%s", data);
        else
            printf("User:%s  data: %s", user, data);
        printf("\x1b[49m\x1b[39m\n");
    }
    /* --- 装入 --- */
    FILE *loadfile;
    char loadfilename[1000];
    sprintf(loadfilename, "stakeholder/%s/%s.txt", user, data);
    loadfile = fopen(loadfilename, "r");
    if (loadfile == NULL)
        error_notice(1002, loadfilename, __func__, __LINE__);
    fgets(str, 1000, loadfile);
    fclose(loadfile);
    return str;
}

void option_analyze(int argc, char *argv[])
{
    int x;
    while ((x = getopt(argc, argv, "dts")) != -1)
    {
        switch (x)
        {
        case 'd': // 显示使用了哪个数据
            data_print = 1;
            break;
        case 't': // 显示处理时间
            time_print = 1;
            break;
        case 's': // 显示文件大小
            size_print = 1;
            break;
        default:
            printf("选择了无效的选项\n");
            break;
        }
    }
}
