/**
* @file aes.h
* @author Cameron A. Craig
* @date 31 Dec 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief Defines uc_timing_h handle and function prototypes.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*/

#ifndef UTILC_CRYPTO_AES_IMPL_H
#define UTILC_CRYPTO_AES_IMPL_H

#include <stdint.h>

typedef unsigned char state_t[4][4];
typedef state_t* state_h;

typedef struct utilc_crypto_cipher_aes* aes_h;
struct utilc_crypto_cipher_aes {
	uint8_t Nk;
	uint8_t Nr;

	unsigned length;

	//state_h state;

	// The array that stores the round keys.
	//unsigned char RoundKey[176];

	unsigned char* key;
	unsigned key_len;

	unsigned char* iv; //initialisation vector not used in ECB mode
	// IV length is always 16 bytes (block size)

};

uint32_t uc_crypto_sw_cipher_aes(unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts);
uint32_t uc_crypto_sw_encrypt_aes(unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts);
uint32_t uc_crypto_sw_decrypt_aes(unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts);

uint32_t aes_ecb_encrypt_block(unsigned char* input, unsigned char* output, aes_h aes);
uint32_t aes_ecb_decrypt_block(unsigned char* input, unsigned char* output, aes_h aes);

#endif //_AES_H_
