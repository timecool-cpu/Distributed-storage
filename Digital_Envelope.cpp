#include <stdio.h>
#include <iostream>
#include <string>
#include <openssl/md5.h>

#include "base64.h"
#include "Crypto.h"
using namespace std;

string getMessage(const char *prompt)
{
    string message;

    printf(prompt);
    fflush(stdout);

    getline(std::cin, message);
    return message;
}

void encryptAES(Crypto &crypto, string message)
{
    // 使用AES对明文进行加密
    unsigned char *encryptedMessage = NULL;
    int encryptedMessageLength = crypto.aesEncrypt((const unsigned char *)message.c_str(), message.size() + 1, &encryptedMessage);

    if (encryptedMessageLength == -1)
    {
        fprintf(stderr, "Encryption failed\n");
        return;
    }

    // 输出加密结果
    char *b64Message = base64Encode(encryptedMessage, encryptedMessageLength);
    printf("Encrypted message: %s\n", b64Message);
}

void encryptokeyByRSA(Crypto &crypto)
{
    unsigned char *AESkey = crypto.getAesKey();
    string aes_key_str((char *)AESkey); //转为string类型
    cout << "aes_key_str:" << aes_key_str << endl;
    unsigned char *encryptedMessage = NULL;
    unsigned char *encryptedKey;
    unsigned char *iv;
    size_t encryptedKeyLength;
    size_t ivLength;
    int encryptedMessageLength = crypto.rsaEncrypt((const unsigned char *)aes_key_str.c_str(), aes_key_str.size() + 1,
                                                   &encryptedMessage, &encryptedKey, &encryptedKeyLength, &iv, &ivLength); //进行rsa加密

    if (encryptedMessageLength == -1)
    {
        fprintf(stderr, "Encryption failed\n");
        return;
    }
    cout << "encryptedMessageLength: " << encryptedMessageLength << endl;

    //密钥加密结果
    char *b64Message = base64Encode(encryptedMessage, encryptedMessageLength);
    printf("Encrypted message: %s\n", b64Message);

    char *decryptedMessage = NULL;
    int decryptedMessageLength = crypto.rsaDecrypt(encryptedMessage, (size_t)encryptedMessageLength,
                                                   encryptedKey, encryptedKeyLength, iv, ivLength, (unsigned char **)&decryptedMessage);

    if (encryptedMessageLength == -1)
    {
        fprintf(stderr, "Decryption failed\n");
        return;
    }
    cout << "encryptedMessageLength:" << encryptedMessageLength << endl;

    // printf("Decrypted message: %s\n", decryptedMessage);
    cout << "Decrypted message: " << decryptedMessage << endl;
    char *b64Message_de = base64Encode((const unsigned char *)decryptedMessage, decryptedMessageLength);
    printf("Decrypted message: %s\n", b64Message_de);
    char *b64Message_de2 = base64Encode((const unsigned char *)decryptedMessage, decryptedMessageLength);
    printf("Decrypted message: %s\n", b64Message_de2);
}

void print_AESkey(Crypto &crypto)
{
    //输出对称加密密钥
    unsigned char *AESkey = crypto.getAesKey();
    int AESkey_Length = crypto.getAesKey(&AESkey);
    char *b64Message = base64Encode(AESkey, AESkey_Length);
    printf("AESkey message: %s\n", b64Message);
}

void encryptRsa(Crypto *crypto)
{
    // 获取明文
    //string message = getMessage("Message to RSA encrypt: ");
    unsigned char *AESkey = crypto->getAesKey();

    string message((char *)AESkey);
    //cout<<"message"<<message<<endl;

    // Encrypt the message with RSA
    // +1 on the string length argument because we want to encrypt the NUL terminator too
    unsigned char *encryptedMessage = NULL;
    unsigned char *encryptedKey;
    unsigned char *iv;
    size_t encryptedKeyLength;
    size_t ivLength;

    int encryptedMessageLength = crypto->rsaEncrypt((const unsigned char *)message.c_str(), message.size() + 1,
                                                    &encryptedMessage, &encryptedKey, &encryptedKeyLength, &iv, &ivLength);

    if (encryptedMessageLength == -1)
    {
        fprintf(stderr, "Encryption failed\n");
        return;
    }
    //cout << "encryptedMessageLength: " << encryptedMessageLength << endl;

    // Print the encrypted message as a base64 string
    char *b64Message = base64Encode(encryptedMessage, encryptedMessageLength);
    printf("Encrypted message: %s\n", b64Message);

    // Decrypt the message
    unsigned char *decryptedMessage = NULL;

    int decryptedMessageLength = crypto->rsaDecrypt(encryptedMessage, (size_t)encryptedMessageLength,
                                                    encryptedKey, encryptedKeyLength, iv, ivLength, (unsigned char **)&decryptedMessage);

    if (decryptedMessageLength == -1)
    {
        fprintf(stderr, "Decryption failed\n");
        return;
    }
    //cout << "decryptedMessageLength:" << decryptedMessageLength << endl;

    int AESkey_Length = crypto->getAesKey(&AESkey);
    char *b64Message2 = base64Encode(decryptedMessage, AESkey_Length);
    printf("AESkey message: %s\n", b64Message2);

    // Clean up
    free(encryptedMessage);
    free(decryptedMessage);
    free(encryptedKey);
    free(iv);
    free(b64Message);

    encryptedMessage = NULL;
    decryptedMessage = NULL;
    encryptedKey = NULL;
    iv = NULL;
    b64Message = NULL;
}

int main()
{
    Crypto crypto;
    //输入明文
    string message = getMessage("Message to  encrypt: ");

    //对明文进行AES加密并打印密文
    encryptAES(crypto, message);

    //输出AES的加密密钥
    print_AESkey(crypto);

    //使用RSA对对称加密密钥加密
    encryptRsa(&crypto);

    return 0;
}