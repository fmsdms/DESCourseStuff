#define _CRT_SECURE_NO_WARNINGS//VS 宏，抑制使用不安全函数报错的
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>//clock()可以获得当前时间，两次clock相减为中间间隔运行时间（ms）
#include <io.h>

typedef char int8;
typedef unsigned char uint8;
typedef uint8 byte;
typedef short int16;
typedef unsigned short uint16;
typedef long long int int64;
typedef unsigned long long int uint64;

const char* DES_MODE[] = { "ECB","CBC","CFB","OFB" };

const byte IP[] = {
	58, 50, 42, 34, 26, 18, 10,  2,
	60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6,
	64, 56, 48, 40, 32, 24, 16,  8,
	57, 49, 41, 33, 25, 17,  9,  1,
	59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5,
	63, 55, 47, 39, 31, 23, 15,  7,
};

const byte ReverseIP[] = {
	40,  8, 48, 16, 56, 24, 64, 32,
	39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30,
	37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28,
	35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26,
	33,  1, 41,  9, 49, 17, 57, 25,
};

const byte E[] = {
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1,
};

static byte S[][4][16] = {
	{
		/* S1 */
		{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,},
		 {0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,},
		 {4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,},
		{15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
	},
	{
		/* S2 */
		{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
		{3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
		{0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
		{13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
	},
	{
		/* S3 */
		{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,},
		{13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,},
		{13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,},
		 {1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
	},
	{
		/* S4 */
		 {7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,},
		{13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,},
		{10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,},
		 {3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
	},
	{
		/* S5 */
		 {2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,},
		{14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,},
		 {4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,},
		{11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
	},
	{
		/* S6 */
		{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,},
		{10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,},
		 {9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,},
		 {4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
	},
	{
		/* S7 */
		 {4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,},
		{13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,},
		 {1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,},
		 {6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
	},
	{
		/* S8 */
		{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,},
		 {1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,},
		 {7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,},
		 {2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
	}
};

const byte P[] = {
	16,  7, 20, 21,
	29, 12, 28, 17,
	 1, 15, 23, 26,
	 5, 18, 31, 10,
	 2,  8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25
};

const byte PC1[] = {
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4,
};

const byte PC2[] = {
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
};

const byte LS[] = { 1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1 };	//DES加密用的生成子密钥时每轮左移位数
const byte DCPTLS[] = { 0,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1 };//DES解密用的生成子密钥时每轮右移位数

char* plainfile = NULL;
char* keyfile = NULL;
char* vifile = NULL;
char* mode = NULL;
char* cipherfile = NULL;

byte* plaintext = NULL;
byte* keytext = NULL;
byte* vitext = NULL;
byte* ciphertext = NULL;

uint64 plaintextlength = 0;
uint64 vitextlegnth = 0;
uint64 keytextlength = 0;
uint64 ciphertextlength = 0;

void print_usage() {
	/*
	参数输入错误提示，并推出程序
	*/
	printf("\n非法输入,支持的参数有以下：\n-p plainfile 指定明文文件的位置和名称\n-k keyfile  指定密钥文件的位置和名称\n-v vifile  指定初始化向量文件的位置和名称\n-m mode  指定加密的操作模式(ECB,CBC,CFB,OFB)\n-c cipherfile 指定密文文件的位置和名称。\n");
	exit(-1);
}

bool readfile2memory(const char* filename, byte** memory, uint64* memorylength) {
	/*
	读取文件到内存，同时把字符“4e” 转成一个字节0x4e
	*/
	FILE* fp = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (size % 2 != 0) {
		printf("%s:文件字节数不为偶数！\n", filename);
		fclose(fp);
		return false;
	}
	byte* tmp = malloc(size);
	memset(tmp, 0, size);

	fread(tmp, size, 1, fp);
	if (ferror(fp)) {
		printf("读取%s出错了！\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}

	*memory = malloc(size / 2);
	memset(*memory, 0, size / 2);
	*memorylength = size / 2;

	byte parsewalker[3] = { 0 };
	printf("readfile2memory debug info:");
	for (int i = 0; i < size; i += 2) {
		parsewalker[0] = tmp[i];
		parsewalker[1] = tmp[i + 1];
		(*memory)[i / 2] = strtol(parsewalker, 0, 16);
		printf("%c", (*memory)[i / 2]);
	}
	printf("\n");

	free(tmp);

	return true;
}

void leftshift1(byte key[7]) {
	/*
	子密钥左移一位
	*/
	byte carry[8] = { 0 };
	carry[0] = key[0] & (1 << 7);
	carry[1] = key[1] & (1 << 7);
	carry[2] = key[2] & (1 << 7);
	carry[3] = key[3] & (1 << 7);
	carry[4] = key[3] & (1 << 3);
	carry[5] = key[4] & (1 << 7);
	carry[6] = key[5] & (1 << 7);
	carry[7] = key[6] & (1 << 7);

	for (int i = 0; i < 7; i++) {
		key[i] <<= 1;
	}

	key[0] &= (0xfe);
	key[0] |= (carry[1] != 0 ? 1 : 0);
	key[1] &= (0xfe);
	key[1] |= (carry[2] != 0 ? 1 : 0);
	key[2] &= (0xfe);
	key[2] |= (carry[3] != 0 ? 1 : 0);
	key[3] &= (0xee);
	key[3] |= (carry[0] != 0 ? (1 << 4) : 0);
	key[3] |= (carry[5] != 0 ? 1 : 0);
	key[4] &= (0xfe);
	key[4] |= (carry[6] != 0 ? 1 : 0);
	key[5] &= (0xfe);
	key[5] |= (carry[7] != 0 ? 1 : 0);
	key[6] &= (0xfe);
	key[6] |= (carry[4] != 0 ? 1 : 0);
}

void leftshift2(byte key[7]) {
	/*
	子密钥左移两位
	*/
	byte carry[8][2] = { 0 };
	carry[0][0] = key[0] & (1 << 7);
	carry[0][1] = key[0] & (1 << 6);
	carry[1][0] = key[1] & (1 << 7);
	carry[1][1] = key[1] & (1 << 6);
	carry[2][0] = key[2] & (1 << 7);
	carry[2][1] = key[2] & (1 << 6);
	carry[3][0] = key[3] & (1 << 7);
	carry[3][1] = key[3] & (1 << 6);
	carry[4][0] = key[3] & (1 << 3);
	carry[4][1] = key[3] & (1 << 2);
	carry[5][0] = key[4] & (1 << 7);
	carry[5][1] = key[4] & (1 << 6);
	carry[6][0] = key[5] & (1 << 7);
	carry[6][1] = key[5] & (1 << 6);
	carry[7][0] = key[6] & (1 << 7);
	carry[7][1] = key[6] & (1 << 6);

	for (int i = 0; i < 7; i++) {
		key[i] <<= 2;
	}

	key[0] &= (0xfc);
	key[0] |= (carry[1][0] != 0 ? 2 : 0);
	key[0] |= (carry[1][1] != 0 ? 1 : 0);
	key[1] &= (0xfc);
	key[1] |= (carry[2][0] != 0 ? 2 : 0);
	key[1] |= (carry[2][1] != 0 ? 1 : 0);
	key[2] &= (0xfc);
	key[2] |= (carry[3][0] != 0 ? 2 : 0);
	key[2] |= (carry[3][1] != 0 ? 1 : 0);
	key[3] &= (0xcc);
	key[3] |= (carry[0][0] != 0 ? (1 << 5) : 0);
	key[3] |= (carry[0][1] != 0 ? (1 << 4) : 0);
	key[3] |= (carry[5][0] != 0 ? 2 : 0);
	key[3] |= (carry[5][1] != 0 ? 1 : 0);
	key[4] &= (0xfc);
	key[4] |= (carry[6][0] != 0 ? 2 : 0);
	key[4] |= (carry[6][1] != 0 ? 1 : 0);
	key[5] &= (0xfc);
	key[5] |= (carry[7][0] != 0 ? 2 : 0);
	key[5] |= (carry[7][1] != 0 ? 1 : 0);
	key[6] &= (0xfc);
	key[6] |= (carry[4][0] != 0 ? 2 : 0);
	key[6] |= (carry[4][1] != 0 ? 1 : 0);

}

void leftshift(byte key[7], uint8 round) {
	/*
	子密钥左移情况判定
	*/
	if (LS[round] == 1)
		return leftshift1(key);
	else
		return leftshift2(key);
}

void rightshift1(byte key[7]) {
	/*
	子密钥右移一位
	*/
	byte carry[8] = { 0 };
	carry[0] = key[0] & (1);
	carry[1] = key[1] & (1);
	carry[2] = key[2] & (1);
	carry[3] = key[3] & (1 << 4);
	carry[4] = key[3] & (1);
	carry[5] = key[4] & (1);
	carry[6] = key[5] & (1);
	carry[7] = key[6] & (1);

	for (int i = 0; i < 7; i++) {
		key[i] >>= 1;
	}

	key[0] &= (0x7f);
	key[0] |= (carry[3] != 0 ? (1 << 7) : 0);
	key[1] &= (0x7f);
	key[1] |= (carry[0] != 0 ? (1 << 7) : 0);
	key[2] &= (0x7f);
	key[2] |= (carry[1] != 0 ? (1 << 7) : 0);
	key[3] &= (0x77);
	key[3] |= (carry[2] != 0 ? (1 << 7) : 0);
	key[3] |= (carry[7] != 0 ? (1 << 3) : 0);
	key[4] &= (0x7f);
	key[4] |= (carry[4] != 0 ? (1 << 7) : 0);
	key[5] &= (0x7f);
	key[5] |= (carry[5] != 0 ? (1 << 7) : 0);
	key[6] &= (0x7f);
	key[6] |= (carry[6] != 0 ? (1 << 7) : 0);
}

void rightshift2(byte key[7]) {
	/*
	子密钥右移两位
	*/
	byte carry[8][2] = { 0 };
	carry[0][0] = key[0] & 1;
	carry[0][1] = key[0] & 2;
	carry[1][0] = key[1] & 1;
	carry[1][1] = key[1] & 2;
	carry[2][0] = key[2] & 1;
	carry[2][1] = key[2] & 2;
	carry[3][0] = key[3] & (1 << 4);
	carry[3][1] = key[3] & (1 << 5);
	carry[4][0] = key[3] & 1;
	carry[4][1] = key[3] & 2;
	carry[5][0] = key[4] & 1;
	carry[5][1] = key[4] & 2;
	carry[6][0] = key[5] & 1;
	carry[6][1] = key[5] & 2;
	carry[7][0] = key[6] & 1;
	carry[7][1] = key[6] & 2;

	for (int i = 0; i < 7; i++) {
		key[i] >>= 2;
	}

	key[0] &= (0x3f);
	key[1] &= (0x3f);
	key[2] &= (0x3f);
	key[3] &= (0x33);
	key[4] &= (0x3f);
	key[5] &= (0x3f);
	key[6] &= (0x3f);
	key[0] |= (carry[3][0] != 0 ? (1 << 6) : 0);
	key[0] |= (carry[3][1] != 0 ? (1 << 7) : 0);
	key[1] |= (carry[0][0] != 0 ? (1 << 6) : 0);
	key[1] |= (carry[0][1] != 0 ? (1 << 7) : 0);
	key[2] |= (carry[1][0] != 0 ? (1 << 6) : 0);
	key[2] |= (carry[1][1] != 0 ? (1 << 7) : 0);
	key[3] |= (carry[2][0] != 0 ? (1 << 6) : 0);
	key[3] |= (carry[2][1] != 0 ? (1 << 7) : 0);
	key[3] |= (carry[7][0] != 0 ? (1 << 2) : 0);
	key[3] |= (carry[7][1] != 0 ? (1 << 3) : 0);
	key[4] |= (carry[4][0] != 0 ? (1 << 6) : 0);
	key[4] |= (carry[4][1] != 0 ? (1 << 7) : 0);
	key[5] |= (carry[5][0] != 0 ? (1 << 6) : 0);
	key[5] |= (carry[5][1] != 0 ? (1 << 7) : 0);
	key[6] |= (carry[6][0] != 0 ? (1 << 6) : 0);
	key[6] |= (carry[6][1] != 0 ? (1 << 7) : 0);


}

void rightshift(byte key[7], uint8 round) {
	/*
	子密钥右移情况
	*/
	if (DCPTLS[round] == 1)
		return rightshift1(key);
	else if (DCPTLS[round] == 2)
		return rightshift2(key);
	else
		return;
}

void print_help(char* bufname, byte* buf, uint8 bytes) {
	/*
	打印调试信息
	*/
	printf("%s信息:\n", bufname);
	/*for (int i = 0; i < bytes; i++) {
		printf("%c", buf[i]);
	}*/
	//printf("\n");
	for (int i = 0; i < bytes; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n\n");
	/*for (int i = 0; i < bytes; i++) {
		for (int j = 7; j >= 0; j--) {
			if (buf[i] & 1 << j) {
				printf("1");
			}
			else {
				printf("0");
			}
		}
		printf("\n");
	}
	printf("\n\n");*/
}

void DES(const byte* inputtext, const byte* inputkey, char mode, byte* output) {
	/*
	DES 加解密函数，
	@inputtext: 输入的明文字符序列指针，大小为64位即8字节
	@inputkey: 输入的密文字符序列指针，大小为64位即8字节
	@mode: 模式，'e'为加密模式，'d'为解密模式
	@output: 输出的字符序列指针，大小为64位即8字节
	*/
	assert(inputtext != NULL && inputkey != NULL && output != NULL);

	//print_help("明文", inputtext, 8);
	//print_help("密文", inputkey, 8);

	//IP
	byte text[8] = { 0 };
	for (int i = 0; i < 64; i++) {
		uint8 bitfield = IP[i];
		uint8 row = (bitfield - 1) / 8;
		uint8 col = (bitfield - 1) % 8;
		uint8 set = inputtext[row] & (1 << (7 - col));
		if (set) {
			text[i / 8] |= (1 << (7 - (i % 8)));
		}
	}
	//print_help("IP后的明文", text, 8);

	//PC-1
	byte key[7] = { 0 };
	for (int i = 0; i < 56; i++) {
		uint8 bitfield = PC1[i];
		uint8 row = (bitfield - 1) / 8;
		uint8 col = (bitfield - 1) % 8;
		uint8 set = inputkey[row] & (1 << (7 - col));
		if (set) {
			key[i / 8] |= (1 << (7 - (i % 8)));
		}
	}

	//print_help("PC-1置换后的密文", key, 7);

	byte L[4] = { 0 };
	byte R[4] = { 0 };
	memcpy(L, text, 4);
	memcpy(R, text + 4, 4);

	//printf("开始循环咯...\n\n");
	//16 round
	for (int round = 0; round < 16; round++) {
		//printf("第%d轮：\n", round + 1);

		//print_help("左半部分L", L, 4);
		//print_help("右半部分R", R, 4);
		//deal with sub key
		if (mode == 'e') {
			//print_help("左移密钥前密钥", key, 7);
			leftshift(key, round);
			//print_help("左移密钥后密钥", key, 7);
		}
		else if (mode == 'd') {
			//print_help("右移密钥前密钥", key, 7);
			rightshift(key, round);
			//print_help("右移密钥后密钥", key, 7);
		}

		byte subkey[6] = { 0 };
		for (int i = 0; i < 48; i++) {
			uint8 bitfield = PC2[i];
			uint8 row = (bitfield - 1) / 8;
			uint8 col = (bitfield - 1) % 8;
			uint8 set = key[row] & (1 << (7 - col));
			if (set) {
				subkey[i / 8] |= (1 << (7 - (i % 8)));
			}
		}
		//print_help("PC-2置换截取后的子密钥密文", subkey, 6);
		//Ext
		byte ER[6] = { 0 };
		for (int i = 0; i < 48; i++) {
			uint8 bitfield = E[i];
			uint8 row = (bitfield - 1) / 8;
			uint8 col = (bitfield - 1) % 8;
			uint8 set = R[row] & (1 << (7 - col));
			if (set) {
				ER[i / 8] |= (1 << (7 - (i % 8)));
			}
		}
		//print_help("E拓展右边明文后的结果", ER, 6);
		//xor
		byte XOR[6] = { 0 };
		for (int i = 0; i < 6; i++) {
			XOR[i] = ER[i] ^ subkey[i];
		}
		//print_help("拓展后的右明文与子密钥异或后的结果", XOR, 6);
		//S-box
		byte NewR[4] = { 0 };
		for (int i = 0; i < 8; i++) {
			uint8 row = 0;
			uint8 col = 0;

			//1
			uint8 bit1location = i * 6 + 0;
			if (XOR[bit1location / 8] & (1 << (7 - bit1location % 8))) {
				row |= 0b10;
			}
			//6
			uint8 bit6location = i * 6 + 5;
			if (XOR[bit6location / 8] & (1 << (7 - bit6location % 8))) {
				row |= 0b01;
			}
			//2-5
			uint8 bit2location = i * 6 + 1;
			uint8 bit3location = i * 6 + 2;
			uint8 bit4location = i * 6 + 3;
			uint8 bit5location = i * 6 + 4;
			if (XOR[bit2location / 8] & (1 << (7 - bit2location % 8))) {
				col |= 0b1000;
			}
			if (XOR[bit3location / 8] & (1 << (7 - bit3location % 8))) {
				col |= 0b0100;
			}
			if (XOR[bit4location / 8] & (1 << (7 - bit4location % 8))) {
				col |= 0b0010;
			}
			if (XOR[bit5location / 8] & (1 << (7 - bit5location % 8))) {
				col |= 0b0001;
			}

			//S
			uint8 value = S[i][row][col];
			NewR[i / 2] |= (i % 2 == 0 ? (value << 4 & 0xf0) : (value & 0x0f));
		}

		//print_help("异或然后进入S盒后的结果", NewR, 4);

		//P
		byte NewR2[4] = { 0 };
		for (int i = 0; i < 32; i++) {
			uint8 bitfield = P[i];
			uint8 row = (bitfield - 1) / 8;
			uint8 col = (bitfield - 1) % 8;
			uint8 set = NewR[row] & (1 << (7 - col));
			if (set) {
				NewR2[i / 8] |= (1 << (7 - (i % 8)));
			}
		}

		//print_help("S盒后P置换的结果", NewR2, 4);

		//XOR L
		for (int i = 0; i < 4; i++) {
			NewR2[i] = NewR2[i] ^ L[i];
		}
		//print_help("P置换后与左半部分异或的结果", NewR2, 4);

		memcpy(L, R, 4);
		memcpy(R, NewR2, 4);

		memcpy(output, L, 4);
		memcpy(output + 4, R, 4);

		//print_help("这轮结果：", output, 8);
	}

	//write back to text
	memcpy(text, R, 4);
	memcpy(text + 4, L, 4);
	//print_help("16论完后拼接的结果", text, 8);

	//IPreverse
	memset(output, 0, 8);
	for (int i = 0; i < 64; i++) {
		uint8 bitfield = ReverseIP[i];
		uint8 row = (bitfield - 1) / 8;
		uint8 col = (bitfield - 1) % 8;
		uint8 set = text[row] & (1 << (7 - col));
		if (set) {
			output[i / 8] |= (1 << (7 - (i % 8)));
		}
	}
	//print_help("逆IP的结果", output, 8);
	return;
}

void ECBe(const byte* plaintext, const uint64 plainlength, const byte* keytext, byte** ciphertext, uint64* cipherlength) {
	/*
	DES ECB模式加密函数，
	@plaintext: 输入的明文字符序列指针，
	@plainlength: 输入的明文字符序列长度（字节）
	@keytext: 输入的密文字符序列指针，密文长度默认为64位即8字节
	@ciphertext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@cipherlength:待输出的字符序列的长度
	*/
	byte output[8];
	//byte cipher[8] = { 0x6b, 0x86, 0x6c, 0x00, 0xd3, 0x37, 0xca, 0xa8 };
	//int plainlength = strlen(plaintext);
	int group = plainlength % 8 == 0 ? plainlength / 8 : plainlength / 8 + 1;
	*ciphertext = malloc(group * 8);
	*cipherlength = group * 8;
	memset(*ciphertext, 0, group * 8);
	for (int i = 0; i < group; i++) {
		DES(plaintext + i * 8, keytext, 'e', (*ciphertext) + i * 8);
	}


	//DES(plaintext, keytext, 'e',output);
	//DES(cipher, keytext, 'd', output);

	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
}

void CBCe(const byte* plaintext, const uint64 plainlength, const byte* keytext, const byte* vitext, byte** ciphertext, uint64* cipherlength) {
	/*
	DES CBC模式加密函数，
	@plaintext: 输入的明文字符序列指针，
	@plainlength: 输入的明文字符序列长度（字节）
	@keytext: 输入的密文字符序列指针，密文长度默认为64位即8字节
	@vitext: 输入的初始化向量字符序列指针
	@ciphertext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@cipherlength:待输出的字符序列的长度
	*/

	byte C[8] = { 0 };
	memcpy(C, vitext, 8);

	//int plainlength = strlen(plaintext);
	int group = plainlength % 8 == 0 ? plainlength / 8 : plainlength / 8 + 1;
	*ciphertext = malloc(group * 8);
	*cipherlength = group * 8;
	memset(*ciphertext, 0, group * 8);
	for (int i = 0; i < group; i++) {
		*((uint64*)C) = *((uint64*)C) ^ *((uint64*)(plaintext + i * 8));
		DES(C, keytext, 'e', (*ciphertext) + i * 8);
		*((uint64*)C) = *((uint64*)(*ciphertext + i * 8));
	}

	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
}

void CFBe(const byte* plaintext, const uint64 plainlength, const byte* keytext, const byte* vitext, byte** ciphertext, uint64* cipherlength) {
	/*
	DES CFB模式加密函数，
	@plaintext: 输入的明文字符序列指针，
	@plainlength: 输入的明文字符序列长度（字节）
	@keytext: 输入的密文字符序列指针，密文长度默认为64位即8字节
	@vitext: 输入的初始化向量字符序列指针
	@ciphertext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@cipherlength:待输出的字符序列的长度
	*/
	char reg[8] = { 0 };
	char desoutput[8] = { 0 };
	memcpy(reg, vitext, 8);
	//int plainlength = strlen(plaintext);
	*ciphertext = malloc(plainlength);
	*cipherlength = plainlength;
	memset(*ciphertext, 0, plainlength);

	for (int i = 0; i < plainlength; i++) {
		DES(reg, keytext, 'e', desoutput);
		byte C = *(plaintext + i) ^ *desoutput;
		*(*ciphertext + i) = C;
		for (int j = 0; j < 7; j++) {
			reg[j] = reg[j + 1];
		}
		reg[7] = C;
	}

	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
}

void OFBe(const byte* plaintext, const uint64 plainlength, const byte* keytext, const byte* vitext, byte** ciphertext, uint64* cipherlength) {
	/*
	DES OFB模式加密函数，
	@plaintext: 输入的明文字符序列指针，
	@plainlength: 输入的明文字符序列长度（字节）
	@keytext: 输入的密文字符序列指针，密文长度默认为64位即8字节
	@vitext: 输入的初始化向量字符序列指针
	@ciphertext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@cipherlength:待输出的字符序列的长度
	*/
	char reg[8] = { 0 };
	char desoutput[8] = { 0 };
	memcpy(reg, vitext, 8);
	//int plainlength = strlen(plaintext);
	*ciphertext = malloc(plainlength);
	*cipherlength = plainlength;
	memset(*ciphertext, 0, plainlength);

	for (int i = 0; i < plainlength; i++) {
		DES(reg, keytext, 'e', desoutput);
		byte C = *(plaintext + i) ^ *desoutput;
		*(*ciphertext + i) = C;
		for (int j = 0; j < 7; j++) {
			reg[j] = reg[j + 1];
		}
		reg[7] = *desoutput;
	}

	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
}

void ECBd(const byte* ciphertext, const uint64 cipherlength, const byte* keytext, byte** plaintext, uint64* plainlength) {
	/*
	DES ECB模式解密函数，
	@ciphertext: 输入的密文字符序列指针，
	@cipherlength: 输入的密文字符序列长度（字节）
	@keytext: 输入的密文字符序列指针，密文长度默认为64位即8字节
	@plaintext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@plainlength:待输出的字符序列的长度
	*/
	assert(cipherlength % 8 == 0);

	int group = cipherlength / 8;
	*plaintext = malloc(cipherlength);
	*plainlength = cipherlength;
	memset(*plaintext, 0, cipherlength);
	for (int i = 0; i < group; i++) {
		DES(ciphertext + 8 * i, keytext, 'd', *plaintext + 8 * i);
	}

}

void CBCd(const byte* ciphertext, const uint64 cipherlength, const byte* keytext, const byte* vitext, byte** plaintext, uint64* plainlength) {
	/*
	DES CBC模式解密函数，
	@ciphertext: 输入的密文字符序列指针，
	@cipherlength: 输入的密文字符序列长度（字节）
	@keytext: 输入的密文字符序列指针，密文长度默认为64位即8字节
	@vitext: 输入的初始化向量字符序列指针
	@plaintext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@plainlength:待输出的字符序列的长度
	*/
	//printf("cipherttext length:%d", cipherlength);
	assert(cipherlength % 8 == 0);
	byte iv[8] = { 0 };
	memcpy(iv, vitext, 8);
	byte desoutput[8] = { 0 };
	int group = cipherlength / 8;
	*plaintext = malloc(cipherlength);
	*plainlength = cipherlength;
	memset(*plaintext, 0, cipherlength);
	for (int i = 0; i < group; i++) {
		DES(ciphertext + 8 * i, keytext, 'd', desoutput);
		for (int j = 0; j < 8; j++) {
			*(*plaintext + 8 * i + j) = iv[j] ^ desoutput[j];
		}
		memcpy(iv, ciphertext + 8 * i, 8);
	}
}

void CFBd(const byte* ciphertext, const uint64 cipherlength, const byte* keytext, const byte* vitext, byte** plaintext, uint64* plainlength) {
	/*
	DES CFB模式解密函数，
	@ciphertext: 输入的密文字符序列指针，
	@cipherlength: 输入的密文字符序列长度（字节）
	@keytext: 输入的密文字符序列指针，密文长度默认为64位即8字节
	@vitext: 输入的初始化向量字符序列指针
	@plaintext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@plainlength:待输出的字符序列的长度
	*/
	char reg[8] = { 0 };
	char desoutput[8] = { 0 };
	memcpy(reg, vitext, 8);
	//int cipherlength = strlen(ciphertext);
	*plaintext = malloc(cipherlength);
	*plainlength = cipherlength;
	memset(*plaintext, 0, cipherlength);

	for (int i = 0; i < cipherlength; i++) {
		DES(reg, keytext, 'e', desoutput);
		byte M = *(ciphertext + i) ^ *desoutput;
		*(*plaintext + i) = M;
		for (int j = 0; j < 7; j++) {
			reg[j] = reg[j + 1];
		}
		reg[7] = *(ciphertext + i);
	}
}

void OFBd(const byte* ciphertext, const uint64 cipherlength, const byte* keytext, const byte* vitext, byte** plaintext, uint64* plainlength) {
	/*
	DES OFB模式解密函数，
	@ciphertext: 输入的密文字符序列指针，
	@cipherlength: 输入的密文字符序列长度（字节）
	@keytext: 输入的密文字符序列指针，密文长度默认为64位即8字节
	@vitext: 输入的初始化向量字符序列指针
	@plaintext: 待输出的字符序列二级指针，请分配空间，分配失败的，请搜索关键字：C 二级指针 传参 分配空间
	@plainlength:待输出的字符序列的长度
	*/
	char reg[8] = { 0 };
	char desoutput[8] = { 0 };
	memcpy(reg, vitext, 8);
	//int cipherlength = strlen(ciphertext);
	*plaintext = malloc(cipherlength);
	*plainlength = cipherlength;
	memset(*plaintext, 0, cipherlength);

	for (int i = 0; i < cipherlength; i++) {
		DES(reg, keytext, 'e', desoutput);
		byte M = *(ciphertext + i) ^ *desoutput;
		*(*plaintext + i) = M;
		for (int j = 0; j < 7; j++) {
			reg[j] = reg[j + 1];
		}
		reg[7] = *desoutput;
	}
}

void benchmark() {
	/*
	性能测试函数
	*/
	//byte plaintext[5 * 1024 * 1024] = { 1 };
	uint64 plaintextlength = 5 * 1024 * 1024;
	byte* plaintext = malloc(plaintextlength);
	memset(plaintext, 1, plaintextlength);
	byte key[8] = { 0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef };
	int starttime, endtime;
	starttime = clock();
	for (int i = 0; i < 20; i++) {
		byte* plain;
		uint64 plainlen;
		byte* cipher;
		uint64 cipherlen;
		ECBe(plaintext, plaintextlength, key, &cipher, &cipherlen);
		ECBd(cipher, cipherlen, key, &plain, &plainlen);
		free(plain);
		free(cipher);
	}
	endtime = clock();
	printf("耗时：%02f秒", (endtime - starttime) / 1000.0);
}

int main(int argc, char** argv) {
	//argc 表示参数的个数，argv表示每个参数的一个字符串数组
	_write(1, "wocao", 8);
	char c;
	scanf("%c", &c);
	printf("%c", c);
	//benchmark();
	return 0;
	printf("argc:%d\n", argc);
	for (int i = 0; i < argc; i++) {
		printf("%d : %s\n", i, argv[i]);
	}

	/*
	-p plainfile 指定明文文件的位置和名称
	-k keyfile  指定密钥文件的位置和名称
	-v vifile  指定初始化向量文件的位置和名称
	-m mode  指定加密的操作模式
	-c cipherfile 指定密文文件的位置和名称。
	*/

	if (argc % 2 == 0) {
		print_usage();
	}

	for (int i = 1; i < argc; i += 2) {
		if (strlen(argv[i]) != 2) {
			print_usage();
		}
		switch (argv[i][1]) {
		case 'p':
			plainfile = argv[i + 1];
			break;
		case 'k':
			keyfile = argv[i + 1];
			break;
		case 'v':
			vifile = argv[i + 1];
			break;
		case 'm':
			if (strcmp(argv[i + 1], DES_MODE[0]) != 0 && strcmp(argv[i + 1], DES_MODE[1]) != 0 && strcmp(argv[i + 1], DES_MODE[2]) != 0 && strcmp(argv[i + 1], DES_MODE[3]) != 0) {
				print_usage();
			}
			mode = argv[i + 1];
			break;
		case 'c':
			cipherfile = argv[i + 1];
			break;
		default:
			print_usage();
		}
	}

	if (plainfile == NULL || keyfile == NULL || mode == NULL || cipherfile == NULL) {
		print_usage();
	}

	if (strcmp(mode, "ECB") != 0 && vifile == NULL) {
		print_usage();
	}

	printf("解析参数完成！\n");
	printf("参数为明文文件的位置和名称:%s\n", plainfile);
	printf("参数为密钥文件的位置和名称:%s\n", keyfile);
	if (strcmp(mode, "ECB") != 0) {
		printf("参数为初始化向量文件文件的位置和名称:%s\n", vifile);
	}
	printf("参数为密文文件的位置和名称:%s\n", cipherfile);
	printf("参数为加密的模式:%s\n", mode);

	printf("现在开始读取文件！\n");

	printf("读取明文文件...\n");
	bool read_result = readfile2memory(plainfile, &plaintext, &plaintextlength);
	if (read_result == false) {
		printf("读取明文文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取明文文件成功！\n");

	printf("读取密钥文件...\n");
	read_result = readfile2memory(keyfile, &keytext, &keytextlength);
	if (read_result == false) {
		printf("读取密钥文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取密钥文件成功！\n");

	if (strcmp(mode, "ECB") != 0) {
		printf("读取初始向量文件...\n");
		read_result = readfile2memory(vifile, &vitext, &vitextlegnth);
		if (read_result == false) {
			printf("读取初始向量文件失败，请检查路径及文件是否存在\n");
			exit(-1);
		}
		printf("读取初始向量文件成功！\n");
	}

	if (strcmp(mode, "ECB") == 0) {
		//uint64 cipherlength;
		ECBe(plaintext, plaintextlength, keytext, &ciphertext, &ciphertextlength);
		//byte* plain;
		//uint64 plainlength;
		//ECBd(ciphertext,ciphertextlength， keytext, &plain，&plainlength);
		//print_help("plaintext:", plaintext, 16);
		//print_help("plain:", plain, 16);
	}
	else if (strcmp(mode, "CBC") == 0) {
		CBCe(plaintext, plaintextlength, keytext, vitext, &ciphertext, &ciphertextlength);
		//byte* plain;
		//uint64 plainlength;
		//CBCd(ciphertext,ciphertextlength, keytext,vitext, &plain，&plainlength);
		//print_help("plaintext:", plaintext, 16);
		//print_help("plain:", plain, 16);
	}
	else if (strcmp(mode, "CFB") == 0) {
		CFBe(plaintext, plaintextlength, keytext, vitext, &ciphertext, &ciphertextlength);
		//byte* plain;
		//uint64 plainlength;
		//CFBd(ciphertext,ciphertextlength, keytext, vitext, &plain，&plainlength);
		//print_help("plaintext:", plaintext, 16);
		//print_help("plain:", plain, 16);
	}
	else if (strcmp(mode, "OFB") == 0) {
		OFBe(plaintext, plaintextlength, keytext, vitext, &ciphertext, &ciphertextlength);
		//byte* plain;
		//uint64 plainlength;
		//OFBd(ciphertext,ciphertextlength, keytext, vitext, &plain，&plainlength);
		//print_help("plaintext:", plaintext, 16);
		//print_help("plain:", plain, 16);
	}
	else {
		//不应该能到达这里
		printf("致命错误！！！\n");
		exit(-2);
	}


	if (ciphertext == NULL) {
		printf("同学，ciphertext没有分配内存哦，需要补补基础~\n失败，程序退出中...");
		exit(-1);
	}

	printf("解密出来的字符串为:%s\n", ciphertext);
	printf("16进制表示为:");

	int count = ciphertextlength;
	byte* cipherhex = malloc(count * 2);
	memset(cipherhex, 0, count * 2);

	for (int i = 0; i < count; i++) {
		sprintf(cipherhex + i * 2, "%02X", ciphertext[i]);
	}
	printf("%s\n写入文件中...\n", cipherhex);

	FILE* fp = fopen(cipherfile, "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", cipherfile);
		exit(-1);
	}

	int writecount = fwrite(cipherhex, count * 2, 1, fp);
	if (writecount != 1) {
		printf("写入文件出现故障，请重新尝试！");
		fclose(fp);
		exit(-1);
	}
	fclose(fp);
	benchmark();
	printf("恭喜你完成了该程序，请提交代码!");

	return 0;
}


