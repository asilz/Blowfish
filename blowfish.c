#include "blowfish.h"

// g++ main.cpp -o out // -lgmpxx -lgmp

#define textLength 2

uint64_t F(uint32_t leftHalf)
{
    uint8_t box0 = (uint8_t)(leftHalf >> 24);
    uint8_t box1 = (uint8_t)(leftHalf >> 16);
    uint8_t box2 = (uint8_t)(leftHalf >> 8);
    uint8_t box3 = (uint8_t)leftHalf;

    uint32_t a = sbox0[box0];
    uint32_t b = sbox1[box1];
    uint32_t c = sbox2[box2];
    uint32_t d = sbox3[box3];

    uint64_t out;
    out = a + b;
    out = out ^ c;
    out = out + d;

    return out;
}

void encryptBlock(uint64_t *block)
{
    // printf("Encrypting block\n");
    uint32_t rightHalf = (uint32_t)(*block & 0xFFFFFFFF);
    uint32_t leftHalf = (uint32_t)(*block >> 32);
    uint32_t temp;

    for (int i = 0; i < pArrayLength - 2; ++i)
    {
        leftHalf = leftHalf ^ pARRAY[i];
        rightHalf = F(leftHalf) ^ rightHalf;
        temp = leftHalf;
        leftHalf = rightHalf;
        rightHalf = temp;
    }

    temp = leftHalf;
    leftHalf = rightHalf;
    rightHalf = temp;

    rightHalf = rightHalf ^ pARRAY[16];
    leftHalf = leftHalf ^ pARRAY[17];

    *block = ((uint64_t)leftHalf << 32) | rightHalf;
}

void decryptBlock(uint64_t *block)
{
    // printf("Encrypting block\n");
    uint32_t rightHalf = (uint32_t)(*block & 0xFFFFFFFF);
    uint32_t leftHalf = (uint32_t)(*block >> 32);
    uint32_t temp;

    for (int i = pArrayLength - 1; i > 1; --i)
    {
        leftHalf = leftHalf ^ pARRAY[i];
        rightHalf = F(leftHalf) ^ rightHalf;
        temp = leftHalf;
        leftHalf = rightHalf;
        rightHalf = temp;
    }

    temp = leftHalf;
    leftHalf = rightHalf;
    rightHalf = temp;

    rightHalf = rightHalf ^ pARRAY[1];
    leftHalf = leftHalf ^ pARRAY[0];

    *block = ((uint64_t)leftHalf << 32) | rightHalf;
}

void parrayInit(uint8_t *extendedKey)
{
    for (int i = 0; i < pArrayLength; ++i)
    {
        // printf("%0x\n", ((uint32_t)((uint8_t)(pARRAY[i] >> 16) ^ extendedKey[(i * 4) + 2])) << 16);
        pARRAY[i] = (pARRAY[i] & 0xFFFFFF00) | (uint32_t)((uint8_t)(pARRAY[i] >> 0) ^ extendedKey[(i * 4)]);
        pARRAY[i] = (pARRAY[i] & 0xFFFF00FF) | ((uint32_t)((uint8_t)(pARRAY[i] >> 8) ^ extendedKey[(i * 4) + 1])) << 8;
        pARRAY[i] = (pARRAY[i] & 0xFF00FFFF) | ((uint32_t)((uint8_t)(pARRAY[i] >> 16) ^ extendedKey[(i * 4) + 2])) << 16;
        pARRAY[i] = (pARRAY[i] & 0x00FFFFFF) | ((uint32_t)((uint8_t)(pARRAY[i] >> 24) ^ extendedKey[(i * 4) + 3])) << 24;
    }

    uint64_t block = 0x0000000000000000;
    for (int i = 0; i < pArrayLength; i += 2)
    {
        // printf("pARRAY init encrypting\n");
        encryptBlock(&block);
        uint32_t rightHalf = (uint32_t)(block);
        uint32_t leftHalf = (uint32_t)(block >> 32);
        pARRAY[i] = leftHalf;
        pARRAY[i + 1] = rightHalf;
    }
    for (int i = 0; i < 256; i += 2)
    {
        encryptBlock(&block);
        uint32_t rightHalf = (uint32_t)(block);
        uint32_t leftHalf = (uint32_t)(block >> 32);
        sbox0[i] = leftHalf;
        sbox0[i + 1] = rightHalf;
    }
    for (int i = 0; i < 256; i += 2)
    {
        encryptBlock(&block);
        uint32_t rightHalf = (uint32_t)(block);
        uint32_t leftHalf = (uint32_t)(block >> 32);
        sbox1[i] = leftHalf;
        sbox1[i + 1] = rightHalf;
    }
    for (int i = 0; i < 256; i += 2)
    {
        encryptBlock(&block);
        uint32_t rightHalf = (uint32_t)(block);
        uint32_t leftHalf = (uint32_t)(block >> 32);
        sbox2[i] = leftHalf;
        sbox2[i + 1] = rightHalf;
    }
    for (int i = 0; i < 256; i += 2)
    {
        // printf("sBox3 encrypting\n");
        encryptBlock(&block);
        uint32_t rightHalf = (uint32_t)(block);
        uint32_t leftHalf = (uint32_t)(block >> 32);
        sbox3[i] = leftHalf;
        sbox3[i + 1] = rightHalf;
    }
}

void extendKey(uint8_t *key, size_t keyLength, uint8_t *extendedKey)
{
    // printf("Extending Key\n");
    size_t nKey = 0;
    for (int i = 0; i < 18 * sizeof(uint32_t); ++i)
    {
        if (nKey == keyLength)
        {
            nKey = 0;
        }
        extendedKey[i] = key[nKey];
        ++nKey;
        // printf("%x", extendedKey[i]);
    }
    // printf("Extended Key\n");
}

#define keyLength 11

int main()
{
    // uint8_t set_key[24] = {0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    // uint8_t set_key[] = "\x96\xCA\x99\x9F\x8D\xDA\x9A\x87\xD7\xCD\xD9\xBB\x93\xD1\xBE\xC0\xD7\x91\x71\xDC\x9E\xD9\x8D\xD0\xD1\x8C\xD8\xC3\xA0\xB0\xC6\x95\xC3\x9C\x93\xBB\xCC\xCC\xA7\xD3\xB9\xD9\xD9\xD0\x8E\x93\xBE\xDA\xAE\xD1\x8D\x77\xD5\xD3\xA3";
    // uint8_t set_key[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    uint8_t set_key[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    uint64_t plainText[2] = {0x0000000000000000, 0xFFFFFFFFFFFFFFFF};
    uint8_t *key = set_key;
    uint8_t *extendedKey = malloc(18 * sizeof(uint32_t));
    extendKey(key, keyLength, extendedKey);
    parrayInit(extendedKey);
    printf("\nparray inited\n");
    for (int i = 0; i < textLength; ++i)
    {
        printf("%lx\n", plainText[i]);
        encryptBlock(&plainText[i]);
        printf("%lx\n", plainText[i]);
        decryptBlock(&plainText[i]);
        printf("%lx\n", plainText[i]);
    }

    free(extendedKey);
    return 0;
}
