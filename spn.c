#include <stdio.h> //[SPN구조를 이용] 주어진 평문1,평문2가 1비트만 달라도  S-Box (o) = (완전 다른 값) but, S-Box (x), P-Box만(o) = (1비트만 달라짐)
int plaintext0 = 0x1234;
int plaintext = 0xABCD; // 16비트
int Key1[5] = { 0x1234,0x2345,0x3456,0x4567,0x5678 }; // 16비트

int plaintext1 = 0xD178; // BIN { 0,1,1,1,0,1,0,1,0,1,1,0,0,0,1,1 } 011
int plaintext2 = 0xC178; // BUN { 0,1,1,1,0,1,0,1,0,1,1,0,0,0,1,0 }

int sBox1[16] = {
   14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7
};

int pBox1[16] = { 1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16 };

void substitute(int inBlock[16], int outBlock[16], int sBox1[16]) { // 4bit -> 4bit
    int col, value;
    for (int i = 0; i < 4; i++) {
        col = 8 * inBlock[i * 4 + 0] + 4 * inBlock[i * 4 + 1] + 2 * inBlock[i * 4 + 2] + 1 * inBlock[i * 4 + 3];
        value = sBox1[col];

        outBlock[i * 4 + 3] = value % 2;
        value = value / 2;
        outBlock[i * 4 + 2] = value % 2;
        value = value / 2;
        outBlock[i * 4 + 1] = value % 2;
        value = value / 2;
        outBlock[i * 4 + 0] = value % 2;
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

void mixer(int inBlock[16], int outPBlock[16], int KEYBlock[16]) {
    int outBlock[16] = { 0, }, outSBlock[16] = { 0, };
    exclusiveOr(inBlock, KEYBlock, outBlock);
    substitute(outBlock, outSBlock, sBox1);
    permute(outSBlock, outPBlock, pBox1);
}

void mixer1(int inBlock[16], int outPBlock[16], int KEYBlock[16]) {
    int mixingtext[16], outBlock[16];
    exclusiveOr(inBlock, KEYBlock, mixingtext);
    //substitute(mixingtext, outBlock, sBox1);
    permute(mixingtext, outPBlock, pBox1);
}

void SPNcihper(int plaintext[16], int KeyBlock[5][16], int ciphertext[16]) {
    int outBlock[16] = { 0, }, mixingBlock[16] = { 0, }, lastBlock[16] = { 0, };
    for (int round = 0; round < 5; round++) {
        if (round == 0) {
            mixer(plaintext, mixingBlock, KeyBlock[round]);
        }
        if (round > 0 && round < 3) {
            mixer(mixingBlock, mixingBlock, KeyBlock[round]);
        }
        if (round == 3) {
            exclusiveOr(mixingBlock, KeyBlock[round], outBlock);
            substitute(outBlock, lastBlock, sBox1);
        }
        if (round == 4) {
            exclusiveOr(lastBlock, KeyBlock[4], ciphertext); 
        }
    }
}

void SPNcihper0(int plaintext[16], int KeyBlock[5][16], int ciphertext[16]) {
    int T1[16], T2[16], T3[16];
    for (int round = 0; round < 4; round++) {
        if (round == 0) mixer(plaintext, T1, KeyBlock[round]); // round 1
        if (round > 0 && round < 3) { // round 2~3
            mixer(T1, T1, KeyBlock[round]);
        }
        if (round == 3) { // round 4
            exclusiveOr(T1, KeyBlock[round], T2);
            substitute(T2, T3, sBox1);
        }
    }
    exclusiveOr(T3, KeyBlock[4], ciphertext); // subkey K5 mixing
}

void SPNcihper1(int plaintext[16], int KeyBlock[5][16], int ciphertext[16]) {
    int Block[16] = { 0, }, outBlock[16];
    for (int round = 0; round < 4; round++) {
        
        if(round ==0) mixer1(plaintext, Block, KeyBlock[round]); // round 1
        if (round > 0 && round < 3) { // round 2,3
            mixer1(Block, Block, KeyBlock[round]);
        }
        if (round == 3) { // round 4
            exclusiveOr(Block, KeyBlock[round], outBlock);
        }
    }
    exclusiveOr(outBlock, KeyBlock[4], ciphertext); // subkey K5 mixing
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
    int plainBlock0[16] = { 0, }, ciphertext0[16]={0,}, mixingSBlock[16], mixingPBlock[16], mixer0[16];
    printf("[평문]16진수: %X\n", plaintext0);
    for (int i = 15; i >= 0; i--) {
        plainBlock0[i] = plaintext0 % 2;
        plaintext0 = plaintext0 / 2;
    }
    printf("[평문]2진수: ");
    for (int i = 0; i < 16; i++) {
        printf("%d", plainBlock0[i]);
    }
    printf("\n\n=======================[CIPHERBLOCK]====================");
    printf("\n    [CIPHERTEXT]: ");
    SPNcihper0(plainBlock0, KEYBlock, ciphertext0);
    for (int i = 0; i < 16; i++) {
        printf("%d", ciphertext0[i]);
    }

    printf("\n\n=======================[ROUND(1)]=======================");
    printf("\n     {K1 mixing}: ");
    mixer(plainBlock0, mixer0, KEYBlock[0]);    
    for (int i = 0; i < 16; i++) {
        printf("%d", mixer0[i]);
    }
    printf("\n     [K1 mixing]: ");
    exclusiveOr(plainBlock0, KEYBlock[0], plainBlock0);
    for (int i = 0; i < 16; i++) {
        printf("%d", plainBlock0[i]);
    }
    printf("\n[{SUB}K1 mixing]: ");
    substitute(plainBlock0, mixingSBlock, sBox1);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingSBlock[i]);
    }
    printf("\n[{PER}K1 mixing]: ");
    permute(mixingSBlock, mixingPBlock, pBox1);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingPBlock[i]);
    }

    printf("\n\n=======================[ROUND(2)]=======================");
    printf("\n     {K2 mixing}: ");
    mixer(mixingPBlock, mixer0, KEYBlock[1]);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixer0[i]);
    }
    printf("\n     [K2 mixing]: ");
    exclusiveOr(mixingPBlock, KEYBlock[1], mixingPBlock);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingPBlock[i]);
    }
    printf("\n[{SUB}K2 mixing]: ");
    substitute(mixingPBlock, mixingSBlock, sBox1);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingSBlock[i]);
    }
    printf("\n[{PER}K2 mixing]: ");
    permute(mixingSBlock, mixingPBlock, pBox1);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingPBlock[i]);
    }
    printf("\n\n=======================[ROUND(3)]=======================");
    printf("\n     {K3 mixing}: ");
    mixer(mixingPBlock, mixer0, KEYBlock[2]);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixer0[i]);
    }
    printf("\n     [K3 mixing]: ");
    exclusiveOr(mixingPBlock, KEYBlock[2], mixingPBlock);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingPBlock[i]);
    }
    printf("\n[{SUB}K3 mixing]: ");
    substitute(mixingPBlock, mixingSBlock, sBox1);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingSBlock[i]);
    }
    printf("\n[{PER}K3 mixing]: ");
    permute(mixingSBlock, mixingPBlock, pBox1);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingPBlock[i]);
    }
    printf("\n\n=======================[ROUND(4)]=======================");
    printf("\n     [K4 mixing]: ");
    exclusiveOr(mixingPBlock, KEYBlock[3], mixingPBlock);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingPBlock[i]);
    }
    printf("\n[{SUB}K4 mixing]: ");
    substitute(mixingPBlock, mixingSBlock, sBox1);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingSBlock[i]);
    }
    printf("\n\n=======================[KEY5 MIXING]====================");
    printf("\n     [K5 mixing]: ");
    exclusiveOr(mixingSBlock, KEYBlock[4], mixingPBlock);
    for (int i = 0; i < 16; i++) {
        printf("%d", mixingPBlock[i]);
    }
    printf("\n\n ");
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
