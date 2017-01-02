/**
* @file utilc-sw-aes-impl.c
* @author Cameron A. Craig
* @date 31 Dec 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief AES (ECB, CBC) implementation.
* -- RULE_3_2_CD_do_not_use_special_characters_in_filename
* -- RULE_8_1_A_provide_file_info_comment
*
* Based on https://github.com/kokke/tiny-AES128-C
*/

#include <stdint.h>
#include <string.h> // CBC mode, for memset
#include "utilc-crypto-common.h"
#include "aes/aes.h"
#include "aes/luts.h"

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/

// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEY_LEN 16
// The number of rounds in AES Cipher.
#define Nr 10

#define AES_BLOCK_SIZE 16 //Each block is 16 bytes
#define Nb 4							//Number of columns in block


// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
/*
inputs: key,
outputs: Nb(Nr+1) round keys

*/
static void KeyExpansion(const unsigned char *key, unsigned char *round_key) {
  uint32_t i, j, k;
  unsigned char tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for(i = 0; i < Nk; ++i)
  {
    round_key[(i * 4) + 0] = key[(i * 4) + 0];
    round_key[(i * 4) + 1] = key[(i * 4) + 1];
    round_key[(i * 4) + 2] = key[(i * 4) + 2];
    round_key[(i * 4) + 3] = key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j] = round_key[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }
    }
    round_key[i * 4 + 0] = round_key[(i - Nk) * 4 + 0] ^ tempa[0];
    round_key[i * 4 + 1] = round_key[(i - Nk) * 4 + 1] ^ tempa[1];
    round_key[i * 4 + 2] = round_key[(i - Nk) * 4 + 2] ^ tempa[2];
    round_key[i * 4 + 3] = round_key[(i - Nk) * 4 + 3] ^ tempa[3];
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_h state, unsigned char *round_key) {
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= round_key[round * Nb * 4 + i * Nb + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_h state) {
  uint8_t i, j;
  for(i = 0; i < 4; ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[j][i] = sbox[(*state)[j][i]];
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_h state) {
  unsigned char temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp       = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp       = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static unsigned char xtime(unsigned char x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

static void XorWithIv(unsigned char* buf, const unsigned char *iv) {
  uint8_t i;
  for(i = 0; i < KEY_LEN; ++i)
  {
    buf[i] ^= iv[i];
  }
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_h state) {
  uint8_t i;
  uint8_t Tmp,Tm,t;
  for(i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
static uint8_t Multiply(uint8_t x, uint8_t y) {
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}


// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_h state) {
  int i;
  unsigned char a,b,c,d;
  for(i = 0; i < 4; ++i) {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_h state)
{
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j=0;j<4;++j)
    {
      (*state)[j][i] = inv_sbox[(*state)[j][i]];
    }
  }
}

static void InvShiftRows(state_h state) {
  unsigned char temp;

  // Rotate first row 1 columns to right
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp=(*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}


// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_h state, unsigned char *round_keys) {
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, round_keys);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round = 1; round < Nr; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, round_keys);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, state, round_keys);
}

static void InvCipher(state_h state, unsigned char *round_keys) {
  uint8_t round=0;
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, round_keys);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round=Nr-1;round>0;round--)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, round_keys);
    InvMixColumns(state);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, state, round_keys);
}

/***********************************
* ECB block encrypt functions
************************************/

uint32_t aes_ecb_encrypt_block(unsigned char* plaintext_in, unsigned char* ciphertext_out, aes_h aes) {
	if(aes->length % AES_BLOCK_SIZE){
		return UC_CRYPTO_INVALID_LENGTH;
	}

	state_h state;
	unsigned char round_keys[176];
  // Copy plaintext_in to output, and work in-memory on ciphertext_out
  memcpy(ciphertext_out, plaintext_in, AES_BLOCK_SIZE);
  state = (state_h) ciphertext_out;

  KeyExpansion(aes->key, round_keys);

  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher(state, round_keys);

	return UC_CRYPTO_SUCCESS;
}

uint32_t aes_ecb_decrypt_block(unsigned char* ciphertext_in, unsigned char* plaintext_out, aes_h aes) {
	if(aes->length % AES_BLOCK_SIZE){
		return UC_CRYPTO_INVALID_LENGTH;
	}

	state_h state;
	unsigned char round_keys[176];
  // Copy input to output, and work in-memory on plaintext_out
  memcpy(plaintext_out, ciphertext_in, AES_BLOCK_SIZE);
  state = (state_h) plaintext_out;

  // The KeyExpansion routine must be called before encryption.
  KeyExpansion(aes->key, round_keys);

  InvCipher(state, round_keys);

	return UC_CRYPTO_SUCCESS;
}

/***********************************
* ECB block encrypt functions
************************************/


uint32_t aes_cbc_encrypt_buffer(unsigned char* ciphertext_out, unsigned char* plaintext_in, aes_h aes) {
	if(aes->length % AES_BLOCK_SIZE){
		return UC_CRYPTO_INVALID_LENGTH;
	}

	state_h state;
	unsigned char round_keys[176];
  uintptr_t i;



  memcpy(ciphertext_out, plaintext_in, KEY_LEN);
  state = (state_h) ciphertext_out;

  // Skip the key expansion if key is passed as 0
  if(0 != aes->key)
  {
    KeyExpansion(aes->key, round_keys);
  }
	// TODO: check IV for NULL?
  // if(iv != 0)
  // {
  //   Iv = (uint8_t*)iv;
  // }

  for(i = 0; i < aes->length; i += KEY_LEN)
  {
    XorWithIv(plaintext_in, aes->iv);
    memcpy(ciphertext_out, plaintext_in, KEY_LEN);
    state = (state_t*)ciphertext_out;
    Cipher(state, round_keys);
    aes->iv = ciphertext_out;
    plaintext_in += KEY_LEN;
    ciphertext_out += KEY_LEN;
  }

	return UC_CRYPTO_SUCCESS;
}

uint32_t aes_cbc_decrypt_buffer(unsigned char* plaintext_out, unsigned char* ciphertext_in, aes_h aes) {
	state_h state;
	unsigned char round_keys[176];
  uintptr_t i;

	//Length must be integer multiple of AES_BLOCK_SIZE
  if(aes->length % AES_BLOCK_SIZE){
		return UC_CRYPTO_INVALID_LENGTH;
	}

  memcpy(plaintext_out, ciphertext_in, KEY_LEN);
  state = (state_h) plaintext_out;

  // Skip the key expansion if key is passed as 0
  if(0 != aes->key)
  {
    KeyExpansion(aes->key, round_keys);
  }

  // If iv is passed as 0, we continue to encrypt without re-setting the Iv
  // if(iv != 0)
  // {
  //   Iv = (uint8_t*)iv;
  // }

  for(i = 0; i < aes->length; i += KEY_LEN)
  {
    memcpy(plaintext_out, ciphertext_in, KEY_LEN);
    state = (state_h) plaintext_out;
    InvCipher(state, round_keys);
    XorWithIv(plaintext_out, aes->iv);
    aes->iv = ciphertext_in;
    ciphertext_in += KEY_LEN;
    plaintext_out += KEY_LEN;
  }

	return UC_CRYPTO_SUCCESS;
}

uint32_t aes_ecb_encrypt_buffer(unsigned char* ciphertext_out, unsigned char* plaintext_in, aes_h aes) {
	uint32_t i;
	uint32_t ret;
	for(i = 0; i < aes->length; i += AES_BLOCK_SIZE) {
		if((ret = aes_ecb_encrypt_block(plaintext_in + i, ciphertext_out + i, aes)) != UC_CRYPTO_SUCCESS){
			return ret;
		}
	}
	return UC_CRYPTO_SUCCESS;
}

uint32_t aes_ecb_decrypt_buffer(unsigned char* plaintext_out, unsigned char* ciphertext_in, aes_h aes) {
	uint32_t i;
	uint32_t ret;
	for(i = 0; i < aes->length; i += AES_BLOCK_SIZE) {
		if((ret = aes_ecb_decrypt_block(ciphertext_in + i, plaintext_out + i, aes)) != UC_CRYPTO_SUCCESS){
			return ret;
		}
	}
	return UC_CRYPTO_SUCCESS;
}


uint32_t uc_crypto_sw_cipher_aes (unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts){
	// struct utilc_crypto_cipher_aes aes = {
	// 	.key = opts->key,
	// 	.key_len = opts->key_len,
	// 	.length = opts->cipher_len,
	// 	.iv = opts->iv,
	// };

	switch(opts->op){
		case ENCRYPT:
			return uc_crypto_sw_encrypt_aes(src, dst, opts);
		case DECRYPT:
			return uc_crypto_sw_decrypt_aes(src, dst, opts);
		break;
	}
}

uint32_t uc_crypto_sw_encrypt_aes(unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts) {
	struct utilc_crypto_cipher_aes aes = {
		.key = opts->key,
		.key_len = opts->key_len,
		.length = opts->cipher_len,
		.iv = opts->iv,
	};

	switch(opts->cipher){
		case AES_CBC:
			return aes_cbc_encrypt_buffer(dst, src, &aes);
		break;
		case AES_ECB:
			return aes_ecb_encrypt_buffer(dst, src, &aes);
		break;
	}
}

uint32_t uc_crypto_sw_decrypt_aes(unsigned char *src, unsigned char *dst, struct uc_crypto_options *opts){
	struct utilc_crypto_cipher_aes aes = {
		.key = opts->key,
		.key_len = opts->key_len,
		.length = opts->cipher_len,
		.iv = opts->iv,
	};

	switch(opts->cipher){
		case AES_CBC:
			return aes_cbc_decrypt_buffer(dst, src, &aes);
		break;

		case AES_ECB:
			return aes_ecb_decrypt_buffer(dst, src, &aes);
		break;
	}
}
