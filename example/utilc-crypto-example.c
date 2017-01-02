/**
* @file utilc-template-example.c
* @author Cameron A. Craig
* @date 27 Nov 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief Example usage of utilc-template library.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*/
#include <utilc-crypto.h>

#include <stdlib.h>
#include <stdio.h>

int main (int argc, char *argv[]){
	unsigned char plaintext[16] = "abcdefghijklmnop";
	unsigned char plaintext2[16] = "bcdefghijklmnopq";
	unsigned char key[16] = "000000000000000";
	unsigned char iv[16] = "000000000000000";
	unsigned char ciphertext[16] = "0000000000000000";

	struct uc_crypto_options opts = {
		.cipher = AES_ECB,
		.cipher_len = 16,
		.op = ENCRYPT,
		.impl = SW,
		.key = key,
		.key_len = 16,
	};

	uc_crypto_cipher(plaintext, ciphertext, &opts);

	printf("plaintext:\t");
	uc_str(plaintext, 16);
	printf("\n");

	printf("key:\t\t");
	uc_str(key, 16);
	printf("\n");

	printf("iv:\t\t");
	uc_str(iv, 16);
	printf("\n");

	printf("ciphertext:\t");
	uc_str(ciphertext, 16);
	printf("\n");

	opts.op = DECRYPT;
	uc_crypto_cipher(ciphertext, plaintext2, &opts);

	printf("plaintext2:\t");
	uc_str(plaintext2, 16);
	printf("\n");

	printf("Valid: %s\n", memcmp(plaintext, plaintext2, 16) ? "No" : "Yes");
}
