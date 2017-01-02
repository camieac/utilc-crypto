/**
* @file utilc-sw-crypto.h
* @author Cameron A. Craig
* @date 31 Dec 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief Defines uc_timing_h handle and function prototypes.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*/

#ifndef UTILC_SW_CRYPTO_H
#define UTILC_SW_CRYPTO_H

#include "aes/aes.h"
#include <stdint.h>

uint32_t uc_crypto_sw_cipher(unsigned char * src, unsigned char * dst, struct uc_crypto_options *opts);
uint32_t uc_crypto_sw_encrypt(unsigned char * src, unsigned char * dst, struct uc_crypto_options *opts);
uint32_t uc_crypto_sw_decrypt(unsigned char * src, unsigned char * dst, struct uc_crypto_options *opts);

#endif
