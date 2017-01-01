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

typedef uint8_t state_t[4][4];
struct utilc_crypto_cipher_aes {
	// Nb is always 4
	uint8_t Nk;
	uint8_t Nr;

	state_t state;

	// The array that stores the round keys.
	unsigned char RoundKey[176];

	unsigned char* key;


	unsigned char* iv;






};

uint32_t uc_crypto_sw_cipher_aes(unsigned char *src, unsigned char *dst, unsigned char *key, struct uc_crypto_options *opts);
uint32_t uc_crypto_sw_encrypt_aes(unsigned char *src, unsigned char *dst, unsigned char *key, struct uc_crypto_options *opts);
uint32_t uc_crypto_sw_decrypt_aes(unsigned char *src, unsigned char *dst, unsigned char *key, struct uc_crypto_options *opts);

uint32_t AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t* output);
uint32_t AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t* output);

#endif //_AES_H_
