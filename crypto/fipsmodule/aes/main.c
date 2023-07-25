// #include <stdio.h>
// #include <stdlib.h>
// #include "aes_nohw.c"

// int main() {
//     AES_KEY key;
//     unsigned char plainText[16];
//     unsigned char cipherText[16];
//     unsigned char keyData[16];

//     // Generate a random key.
//     for (int i = 0; i < 16; i++) {
//         keyData[i] = rand() % 256;
//     }

//     // Generate some random plaintext.
//     for (int i = 0; i < 16; i++) {
//         plainText[i] = rand() % 256;
//     }

//     GFp_aes_nohw_set_encrypt_key(&key, keyData, 128);
//     GFp_aes_nohw_encrypt(plainText, cipherText, &key);

//     // Print the ciphertext.
//     for (int i = 0; i < 16; i++) {
//         printf("%02x ", cipherText[i]);
//     }
//     printf("\n");

//     return 0;
// }
