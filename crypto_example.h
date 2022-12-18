#ifndef CRYPTO_EXAMPLE_H
#define CRYPTO_EXAMPLE_H

#include <stdio.h>
#include <iostream>
#include <string>

#include "base64.h"
#include "Crypto.h"

// #define PRINT_KEYS

void encryptRsa(Crypto *crypto);
void encryptAes(Crypto *crypto);
void printKeys(Crypto *crypto);
void printBytesAsHex(unsigned char *bytes, size_t length, const char *message);
std::string getMessage(const char *prompt);

#endif
