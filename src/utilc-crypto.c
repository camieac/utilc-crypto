/**
* @file utilc-timing.c
* @author Cameron A. Craig
* @date 28 Dec 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief Measure time without thinking about the arithmetic.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*/

#include <stdint.h>
#include <stdio.h>

#include "utilc-crypto-common.h"
#include "utilc-crypto.h"
#include "utilc-crypto-sw.h"
#include "utilc-crypto-hw.h"

inline uint32_t uc_crypto_cipher(char * src, char * dst, char * key, struct uc_crypto_options * opts){
	switch(opts->op) {
		case ENCRYPT:
			return uc_crypto_encrypt(src, dst, key, opts);
		case DECRYPT:
			return uc_crypto_decrypt(src, dst, key, opts);
		default:
			return UC_CRYPTO_INVALID_OP_CODE;
	}
}

inline uint32_t uc_crypto_encrypt(char * src, char * dst, char * key, struct uc_crypto_options * opts){
	switch(opts->impl) {
		case SW:
			return uc_crypto_sw_encrypt(src, dst, key, opts);
		case HW:
			return uc_crypto_hw_encrypt(src, dst, key, opts);
		default:
			return UC_CRYPTO_INVALID_IMPL_CODE;
	}
}

inline uint32_t uc_crypto_decrypt(char * src, char * dst, char * key, struct uc_crypto_options * opts){
	switch(opts->impl) {
		case SW:
			return uc_crypto_sw_decrypt(src, dst, key, opts);
		case HW:
			return uc_crypto_hw_decrypt(src, dst, key, opts);
		default:
			return UC_CRYPTO_INVALID_IMPL_CODE;
	}
}

void  uc_str(char * buffer, uint32_t length) {
	int i;
	for (i = 0; i < length; i++){
	    printf("%02X", buffer[i]);
	}
}
