#include "blowfish.h"
// g++ main.cpp -o out // -lgmpxx -lgmp

static uint32_t F(uint32_t leftHalf)
{
    uint8_t box0 = (uint8_t)(leftHalf >> 24);
    uint8_t box1 = (uint8_t)(leftHalf >> 16);
    uint8_t box2 = (uint8_t)(leftHalf >> 8);
    uint8_t box3 = (uint8_t)leftHalf;

    uint32_t a = sbox[0][box0];
    uint32_t b = sbox[1][box1];
    uint32_t c = sbox[2][box2];
    uint32_t d = sbox[3][box3];

    uint32_t out;
    out = a + b; // Modulo not neccesary due to overflow being removed due to the size limit of uint32_t
    out = out ^ c;
    out = out + d;

    return out;
}

static void cryptBlock(uint64_t *block, bool encrypt)
{
    uint32_t rightHalf = (uint32_t)(*block & 0xFFFFFFFF);
    uint32_t leftHalf = (uint32_t)(*block >> 32);
    uint32_t temp;
    int index;
    for (int i = 0; i < pArrayLength - 2; ++i)
    {
        if (encrypt)
        {
            index = i;
        }
        else
        {
            index = pArrayLength - 1 - i;
        }
        leftHalf = leftHalf ^ pArray[index];
        rightHalf = F(leftHalf) ^ rightHalf;
        temp = leftHalf;
        leftHalf = rightHalf;
        rightHalf = temp;
    }

    temp = leftHalf;
    leftHalf = rightHalf;
    rightHalf = temp;
    if (encrypt)
    {
        rightHalf = rightHalf ^ pArray[++index];
        leftHalf = leftHalf ^ pArray[++index];
    }
    else
    {
        rightHalf = rightHalf ^ pArray[--index];
        leftHalf = leftHalf ^ pArray[--index];
    }

    *block = ((uint64_t)leftHalf << 32) | rightHalf;
}

void encryptBlock(uint64_t *block)
{
    cryptBlock(block, true);
    // printf("Encrypting block\n");
    /*
    uint32_t rightHalf = (uint32_t)(*block & 0xFFFFFFFF);
    uint32_t leftHalf = (uint32_t)(*block >> 32);
    uint32_t temp;

    for (int i = 0; i < pArrayLength - 2; ++i)
    {
        leftHalf = leftHalf ^ pArray[i];
        rightHalf = F(leftHalf) ^ rightHalf;
        temp = leftHalf;
        leftHalf = rightHalf;
        rightHalf = temp;
    }

    temp = leftHalf;
    leftHalf = rightHalf;
    rightHalf = temp;

    rightHalf = rightHalf ^ pArray[16];
    leftHalf = leftHalf ^ pArray[17];

    *block = ((uint64_t)leftHalf << 32) | rightHalf;
    */
}

void decryptBlock(uint64_t *block)
{
    cryptBlock(block, false);
    // printf("Encrypting block\n");
    /*
    uint32_t rightHalf = (uint32_t)(*block & 0xFFFFFFFF);
    uint32_t leftHalf = (uint32_t)(*block >> 32);
    uint32_t temp;

    for (int i = pArrayLength - 1; i > 1; --i)
    {
        leftHalf = leftHalf ^ pArray[i];
        rightHalf = F(leftHalf) ^ rightHalf;
        temp = leftHalf;
        leftHalf = rightHalf;
        rightHalf = temp;
    }

    temp = leftHalf;
    leftHalf = rightHalf;
    rightHalf = temp;

    rightHalf = rightHalf ^ pArray[1];
    leftHalf = leftHalf ^ pArray[0];

    *block = ((uint64_t)leftHalf << 32) | rightHalf;
    */
}

void encryptData(uint64_t *data, size_t dataLength)
{
    for (int i = 0; i < dataLength; ++i)
    {
        encryptBlock(&data[i]);
    }
}

void decryptData(uint64_t *data, size_t dataLength)
{
    for (int i = 0; i < dataLength; ++i)
    {
        decryptBlock(&data[i]);
    }
}

void initBlowfish(uint8_t *key, size_t keyLength)
{
    int keyIndex = 0;
    for (int i = 0; i < pArrayLength * sizeof(uint32_t); ++i)
    {
        if (keyIndex >= keyLength)
        {
            keyIndex = 0;
        }
        pArray[i / 4] = (pArray[i / 4] & (uint32_t)(0xFFFFFFFF00FFFFFF >> (24 - (8 * (i % 4))))) | ((uint32_t)((uint8_t)(pArray[i / 4] >> (8 * (i % 4))) ^ key[keyIndex++])) << (8 * (i % 4));
    }
    uint64_t block = 0x0000000000000000;
    for (int i = 0; i < pArrayLength; i += 2)
    {
        encryptBlock(&block);
        uint32_t rightHalf = (uint32_t)(block);
        uint32_t leftHalf = (uint32_t)(block >> 32);
        pArray[i] = leftHalf;
        pArray[i + 1] = rightHalf;
    }
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 256; j += 2)
        {
            encryptBlock(&block);
            uint32_t rightHalf = (uint32_t)(block);
            uint32_t leftHalf = (uint32_t)(block >> 32);
            sbox[i][j] = leftHalf;
            sbox[i][j + 1] = rightHalf;
        }
    }
}

void printData(uint64_t *data, size_t length)
{
    for (int i = 0; i < length; ++i)
    {
        printf("%0lX\n", data[i]);
    }
}

void printText(uint64_t *data, size_t length)
{
    for (int i = 0; i < length; ++i)
    {
        for (int i = 0; i < sizeof(uint64_t); ++i)
            printf("%c", (uint8_t)(data[i] >> 8 * (i % 4)));
    }
}

#define keyLength 1
#define dataLength 2

int main()
{
    // uint8_t set_key[24] = {0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    // uint8_t set_key[] = "\x96\xCA\x99\x9F\x8D\xDA\x9A\x87\xD7\xCD\xD9\xBB\x93\xD1\xBE\xC0\xD7\x91\x71\xDC\x9E\xD9\x8D\xD0\xD1\x8C\xD8\xC3\xA0\xB0\xC6\x95\xC3\x9C\x93\xBB\xCC\xCC\xA7\xD3\xB9\xD9\xD9\xD0\x8E\x93\xBE\xDA\xAE\xD1\x8D\x77\xD5\xD3\xA3\x96\xCA\x99\x9F\x8D\xDA\x9A\x87\xD7\xCD\xD9\xBB\x93\xD1\xBE\xC0\xD7\x91\x71\xDC\x9E\xD9\x8D\xD0\xD1\x8C\xD8\xC3\xA0\xB0\xC6\x95\xC3\x9C\x93\xBB\xCC\xCC\xA7\xD3\xB9\xD9\xD9\xD0\x8E\x93\xBE\xDA\xAE\xD1\x8D\x77\xD5\xD3\xA3";
    // uint8_t set_key[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    // uint8_t set_key[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    uint8_t key[] = "\xFF";
    uint64_t plainText[dataLength] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
    // extendKey(key, keyLength, extendedKey);
    initBlowfish(key, keyLength);
    encryptData(plainText, dataLength);
    printData(plainText, dataLength);
    decryptData(plainText, dataLength);
    printData(plainText, dataLength);
    return 0;
}
