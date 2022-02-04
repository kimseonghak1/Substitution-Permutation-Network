#include <stdio.h>

int plaintext = 0xABCD; // 16비트
int Key1[5] = { 0x1234,0x2345,0x3456,0x4567,0x5678 }; // 16비트

int plaintext1 = 0xD178; // 0x7563, 0xD178;
int plaintext2 = 0xC178; //0x7562, 0xC178;

int sBox1[4][16] = {
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
    {0,15,7,4,14,2,13,10,3,6,12,11,9,5,3,8},
    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
};

int pBox1[16] = { 1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16 };

void substitute(int n, int inBlock[16], int outBlock[16], int sBox1[4][16]) { // 4bit -> 4bit
    int col, value;
    for (int i = 0; i < 4; i++) {
        col = 8 * inBlock[i * 4 + 0] + 4 * inBlock[i * 4 + 1] + 2 * inBlock[i * 4 + 2] + 1 * inBlock[i * 4 + 3];

        value = sBox1[n][col];

        outBlock[i * 4] = value / 8; 
        value = value % 8; 
        outBlock[i * 4 + 1] = value / 4; 
        value = value % 4; 
        outBlock[i * 4 + 2] = value / 2; 
        value = value % 2; 
        outBlock[i * 4 + 3] = value; 
        //outBlock[i * 4 + 3] = value % 2;
        //value = value / 2;
        //outBlock[i * 4 + 2] = value % 2;
        //value = value / 2;
        //outBlock[i * 4 + 1] = value % 2;
        //value = value / 2;
        //outBlock[i * 4] = value % 2;
    }
}

void permute(int substitutetext[16], int outPtext[16], int pBox1[16]) { // Permutation P-box
    for (int i = 0; i < 16; i++) {
        outPtext[i] = substitutetext[pBox1[i] - 1];
    }
}

void exclusiveOr(int text[], int key[], int XORtext[]) { // XOR 
    for (int i = 0; i < 16; i++) {
        XORtext[i] = text[i] ^ key[i];
    }
}

void mixer(int n, int inBlock[16], int outPBlock[16], int KeyBlock[16]) {
    int mixingtext[16], outBlock[16];
    exclusiveOr(inBlock, KeyBlock, mixingtext);
    substitute(n,mixingtext, outBlock, sBox1);
    permute(outBlock, outPBlock, pBox1);
}

void mixer1(int n, int inBlock[16], int outPBlock[16], int KeyBlock[16]) {
    int mixingtext[16], outBlock[16];
    exclusiveOr(inBlock, KeyBlock, mixingtext);
    //substitute(mixingtext, outBlock, sBox1);
    permute(mixingtext, outPBlock, pBox1);
}

void SPNcihper(int plaintext[16], int KeyBlock[5][16], int ciphertext[16]) {
    int mixingtext[16], outBlock[16], outPBlock[16], lastBlock[16];
    for (int round = 0; round < 4; round++) {
        mixer(round, plaintext, outPBlock, KeyBlock[round]); // round 1
        if (round > 0 && round < 3) { // round 2,3
            mixer(round, outPBlock, outBlock, KeyBlock[round]);
        }
        if (round == 3) { // round 4
            exclusiveOr(outBlock, KeyBlock[round], mixingtext);
            substitute(round, mixingtext, lastBlock, sBox1);
        }
    }
    exclusiveOr(lastBlock, KeyBlock[4], ciphertext); // subkey K5 mixing
}

void SPNcihper1(int plaintext[16], int KeyBlock[5][16], int ciphertext[16]) {
    int mixingtext[16], outBlock[16], outPBlock[16], lastBlock[16];
    for (int round = 0; round < 4; round++) {
        mixer1(round, plaintext, outPBlock, KeyBlock[round]); // round 1
        if (round > 0 && round < 3) { // round 2,3
            mixer1(round, outPBlock, outBlock, KeyBlock[round]);
        }
        if (round == 3) { // round 4
            exclusiveOr(outBlock, KeyBlock[round], mixingtext);
        }
    }
    exclusiveOr(mixingtext, KeyBlock[4], ciphertext); // subkey K5 mixing
}

int main() {
    printf("\n\n======================[KEY]=======================\n");
    int KEYBlock[5][16];
    for (int i = 0; i < 5; i++) {
        printf("[KEY]16진수: %X\n", Key1[i]);
    }
    for (int i = 0; i < 5; i++) {
        for (int j = 15; j >= 0; j--) {
            KEYBlock[i][j] = Key1[i] % 2;
            Key1[i] = Key1[i] / 2;
        }
    }
    for (int i = 0; i < 5; i++) {
        printf("[KEY]2진수: ");
        for (int j = 0; j < 16; j++) {
            printf("%d", KEYBlock[i][j]);
        }
        puts("");
    }
    printf("==================================================");
    printf("\n\n======================[평문]======================\n");

    printf("[평문]16진수: %X\n", plaintext1);
    int plainBlock1[16] = { 0, }, ciphertext1[16];
    for (int i = 15; i >= 0; i--) {
        plainBlock1[i] = plaintext1 % 2;
        plaintext1 = plaintext1 / 2;
    }
    printf("[평문]2진수: ");
    for (int i = 0; i < 16; i++) {
        printf("%d", plainBlock1[i]);
    }

    printf("\n\n====================[S-Box(X)]=====================\n");
    SPNcihper1(plainBlock1, KEYBlock, ciphertext1);
    printf("[암호문]2진수: ");
    for (int i = 0; i < 16; i++) {
        printf("%d", ciphertext1[i]);
    }
    printf("\n\n====================[S-Box(O)]=====================\n");
    SPNcihper(plainBlock1, KEYBlock, ciphertext1);
    printf("[암호문]2진수: ");
    for (int i = 0; i < 16; i++) {
        printf("%d", ciphertext1[i]);
    }

    printf("\n\n======================[평문]======================\n");
    printf("[평문]16진수: %X\n", plaintext2);
    int plainBlock2[16] = { 0, }, ciphertext2[16];
    for (int i = 15; i >= 0; i--) {
        plainBlock2[i] = plaintext2 % 2;
        plaintext2 = plaintext2 / 2;
    }
    printf("[평문]2진수: ");
    for (int i = 0; i < 16; i++) {
        printf("%d", plainBlock2[i]);
    }

    printf("\n\n====================[S-Box(X)]=====================\n");
    SPNcihper1(plainBlock2, KEYBlock, ciphertext2);
    printf("[암호문]2진수: ");
    for (int i = 0; i < 16; i++) {
        printf("%d", ciphertext2[i]);
    }
    printf("\n\n====================[S-Box(O)]=====================\n");
    SPNcihper(plainBlock2, KEYBlock, ciphertext2);
    printf("[암호문]2진수: ");
    for (int i = 0; i < 16; i++) {
        printf("%d", ciphertext2[i]);
    }
    puts("  ");
}