/**
* @file rsa.h
* @author Cameron A. Craig
* @date 5 Jan 2017
* @version 0.1.0
* @copyright 2017 Cameron A. Craig
* @brief RSA software implementation.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*/

#ifndef UTILC_CRYPTO_RSA_IMPL_H
#define UTILC_CRYPTO_RSA_IMPL_H

#include <stdint.h>

typedef unsigned char state_t[4][4];
typedef state_t* state_h;

typedef struct utilc_crypto_cipher_rsa* aes_h;
struct utilc_crypto_cipher_rsa {

};

uint32_t uc_crypto_sw_cipher_rsa(unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts);
uint32_t uc_crypto_sw_encrypt_rsa(unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts);
uint32_t uc_crypto_sw_decrypt_rsa(unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts);

#endif //UTILC_CRYPTO_RSA_IMPL_H
