/**
* @file utilc-crypto-common.h
* @author Cameron A. Craig
* @date 28 Dec 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief Defines uc_timing_h handle and function prototypes.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*/

#ifndef UTILC_CRYPTO_COMMON_H
#define UTILC_CRYPTO_COMMON_H

#include <string.h>
#include <stdint.h>

enum uc_crypto_cipher_e{
	//Symmetric Block Ciphers
	AES_CBC,
	AES_ECB,
	TRIPLE_DES,
	BLOWFISH,
	TWOFISH,

	//Asymmetic Public Key Ciphers
	RSA,

	//Hash functions
	MD5,
	SHA_3
};

enum uc_crypto_op_e {
	ENCRYPT,
	DECRYPT
};

enum uc_crypto_impl_e {
	SW,
	HW
};

struct uc_crypto_options {
	enum uc_crypto_cipher_e cipher;
	enum uc_crypto_op_e op;
	enum uc_crypto_impl_e impl;
	unsigned char *iv;
	unsigned char *key;
	unsigned key_len;
	unsigned cipher_len;
};

enum uc_crypto_error_codes_e {
	UC_CRYPTO_SUCCESS,
	UC_CRYPTO_ERROR,

	UC_CRYPTO_INVALID_OP_CODE,
	UC_CRYPTO_INVALID_IMPL_CODE,

	UC_CRYPTO_INVALID_LENGTH,

};

#endif //UTILC_COMMON
