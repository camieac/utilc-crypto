/**
* @file utilc-hw-crypto.h
* @author Cameron A. Craig
* @date 31 Dec 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief Defines uc_timing_h handle and function prototypes.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*/

#ifndef UTILC_HW_CRYPTO_H
#define UTILC_HW_CRYPTO_H

#include <stdint.h>


uint32_t uc_crypto_hw_encrypt(unsigned char * src, unsigned char * dst, unsigned char * key);

uint32_t uc_crypto_hw_decrypt(unsigned char * src, unsigned char * dst, unsigned char * key);

#endif
