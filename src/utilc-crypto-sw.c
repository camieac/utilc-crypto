/**
* @file utic-sw-crypto.c
* @author Cameron A. Craig
* @date 31 Dec 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief Measure time without thinking about the arithmetic.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*/

#include <stdint.h>

#include "utilc-crypto-common.h"
#include "utilc-crypto-sw.h"
#include "aes/aes.h"

uint32_t uc_crypto_sw_cipher(unsigned char * src, unsigned char * dst, struct uc_crypto_options *opts) {
	switch(opts->cipher){
		case AES_CBC:
		case AES_ECB:
			uc_crypto_sw_cipher_aes(src, dst, opts);
		break;

	}
}

uint32_t uc_crypto_sw_encrypt(unsigned char * src, unsigned char * dst, struct uc_crypto_options *opts) {
	switch(opts->cipher){
		case AES_CBC:
		case AES_ECB:
			uc_crypto_sw_encrypt_aes(src, dst, opts);
		break;
	}
}

uint32_t uc_crypto_sw_decrypt(unsigned char * src, unsigned char * dst, struct uc_crypto_options *opts) {
	switch(opts->cipher){
		case AES_CBC:
		case AES_ECB:
			uc_crypto_sw_decrypt_aes(src, dst, opts);
		break;
	}
	}
