/**
* @file utilc-sw-aes-impl.c
* @author Cameron A. Craig
* @date 31 Dec 2016
* @version 0.1.0
* @copyright 2016 Cameron A. Craig
* @brief Measure time without thinking about the arithmetic.
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

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEY_LEN 16
// The number of rounds in AES Cipher.
#define Nr 10

#define AES_BLOCK_SIZE 16

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/

// The array that stores the round keys.
static uint8_t RoundKey[176];

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
/*
inputs: key,
outputs: Nb(Nr+1) round keys

*/
static void KeyExpansion(unsigned char *key)
{
  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for(i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=RoundKey[(i-1) * 4 + j];
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
    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_h state)
{
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_h state)
{
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
static void ShiftRows(state_h state)
{
  uint8_t temp;

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

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_h state)
{
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
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
  }


// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_h state)
{
  int i;
  uint8_t a,b,c,d;
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

static void InvShiftRows(state_h state)
{
  uint8_t temp;

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
static void Cipher(state_h state)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round = 1; round < Nr; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, state);
}

static void InvCipher(state_h state)
{
  uint8_t round=0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round=Nr-1;round>0;round--)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state);
    InvMixColumns(state);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, state);
}

uint32_t AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t* output)
{
	state_h state;
  // Copy input to output, and work in-memory on output
  memcpy(output, input, KEY_LEN);
  state = (state_h) output;

  KeyExpansion(key);

  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher(state);

	return UC_CRYPTO_SUCCESS;
}

uint32_t AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t *output)
{
	state_h state;
  // Copy input to output, and work in-memory on output
  memcpy(output, input, KEY_LEN);
  state = (state_h) output;

  // The KeyExpansion routine must be called before encryption.
  KeyExpansion(key);

  InvCipher(state);

	return UC_CRYPTO_SUCCESS;
}

static void XorWithIv(uint8_t* buf, unsigned char *iv)
{
  uint8_t i;
  for(i = 0; i < KEY_LEN; ++i)
  {
    buf[i] ^= iv[i];
  }
}

uint32_t AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
	state_h state;
  uintptr_t i;
  uint8_t remainders = length % KEY_LEN; /* Remaining bytes in the last non-full block */

  memcpy(output, input, KEY_LEN);
  state = (state_h) output;

  // Skip the key expansion if key is passed as 0
  if(0 != key)
  {
    KeyExpansion(key);
  }
	// TODO: check IV for NULL?
  // if(iv != 0)
  // {
  //   Iv = (uint8_t*)iv;
  // }

  for(i = 0; i < length; i += KEY_LEN)
  {
    XorWithIv(input, iv);
    memcpy(output, input, KEY_LEN);
    state = (state_t*)output;
    Cipher(state);
    iv = output;
    input += KEY_LEN;
    output += KEY_LEN;
  }

  if(remainders)
  {
    memcpy(output, input, KEY_LEN);
    memset(output + remainders, 0, KEY_LEN - remainders); /* add 0-padding */
    state = (state_t*)output;
    Cipher(state);
  }

	return UC_CRYPTO_SUCCESS;
}

uint32_t AES128_CBC_decrypt_buffer(unsigned char* output, unsigned char* input, uint32_t length, unsigned char* key, unsigned char* iv)
{
	state_h state;
  uintptr_t i;

	//Length must be integer multiple of AES_BLOCK_SIZE
  if(length % AES_BLOCK_SIZE){
		return UC_CRYPTO_INVALID_LENGTH;
	}

  memcpy(output, input, KEY_LEN);
  state = (state_h) output;

  // Skip the key expansion if key is passed as 0
  if(0 != key)
  {
    KeyExpansion(key);
  }

  // If iv is passed as 0, we continue to encrypt without re-setting the Iv
  // if(iv != 0)
  // {
  //   Iv = (uint8_t*)iv;
  // }

  for(i = 0; i < length; i += KEY_LEN)
  {
    memcpy(output, input, KEY_LEN);
    state = (state_h) output;
    InvCipher(state);
    XorWithIv(output, iv);
    iv = input;
    input += KEY_LEN;
    output += KEY_LEN;
  }

	return UC_CRYPTO_SUCCESS;
}

uint32_t AES128_ECB_encrypt_buffer(unsigned char* output, unsigned char* input, uint32_t length, unsigned char* key) {
	uint32_t i;
	uint32_t ret;
	for(i = 0; i < length; i += AES_BLOCK_SIZE) {
		if((ret = AES128_ECB_encrypt(input + i, key, output + i)) != UC_CRYPTO_SUCCESS){
			return ret;
		}
	}
	return UC_CRYPTO_SUCCESS;
}

uint32_t AES128_ECB_decrypt_buffer(unsigned char* output, unsigned char* input, uint32_t length, unsigned char* key) {
	uint32_t i;
	uint32_t ret;
	for(i = 0; i < length; i += AES_BLOCK_SIZE) {
		if((ret = AES128_ECB_decrypt(input + i, key, output + i)) != UC_CRYPTO_SUCCESS){
			return ret;
		}
	}
	return UC_CRYPTO_SUCCESS;
}


uint32_t uc_crypto_sw_cipher_aes (unsigned char *src, unsigned char *dst, unsigned char *key, struct uc_crypto_options *opts){
	switch(opts->op){
		case ENCRYPT:
			return uc_crypto_sw_encrypt_aes(src, dst, key, opts);
		case DECRYPT:
			return uc_crypto_sw_decrypt_aes(src, dst, key, opts);
		break;
	}
}

uint32_t uc_crypto_sw_encrypt_aes(unsigned char *src, unsigned char *dst, unsigned char *key, struct uc_crypto_options *opts){
	switch(opts->cipher){
		case AES_CBC:
			return AES128_CBC_encrypt_buffer(dst, src, opts->cipher_len, key, opts->iv);
		break;
		case AES_ECB:
			return AES128_ECB_encrypt_buffer(dst, src, opts->cipher_len, key);
		break;
	}
}

uint32_t uc_crypto_sw_decrypt_aes(unsigned char *src, unsigned char *dst, unsigned char *key, struct uc_crypto_options *opts){
	switch(opts->cipher){
		case AES_CBC:
			return AES128_CBC_decrypt_buffer(dst, src, opts->cipher_len, key, opts->iv);
		break;

		case AES_ECB:
			return AES128_ECB_decrypt_buffer(dst, src, opts->cipher_len, key);
		break;
	}
}
