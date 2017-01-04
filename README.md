# utilc-crypto

## Introduction

`utilc-crypto` is a collection of implementations for common cryptographic algorithms.
All implementations are verified against test vectors provided by the appropriate certification institution (see [tests](https://github.com/camieac/utilc-crypto/tree/master/tests)).

Supported algorithms:
- AES ECB (128-bit, 192-bit, 256-bit)
- AES CBC (128-bit, 192-bit, 256-bit)

## Purpose

This library offers a simple API accessing only the most popular cryptography algorithms. Each algorithm is implemented in it's own uncoupled folder, so if you only need to use one algorithm, simple take that folder. Algorithms can also be enabled/disbaled at compile time using macros defined in [utilc-crypto.h](https://github.com/camieac/utilc-crypto/blob/master/include/utilc-crypto.h).

## Code Example

A full example, making use of the full `utilc-crypto` API is available in [example](https://github.com/camieac/utilc-crypto/blob/master/example/utilc-crypto-example.c). A shortened example is given below:
```
unsigned char plaintext[16] = "abcdefghijklmnop";
unsigned char plaintext2[16] = "bcdefghijklmnopq";
unsigned char key[16] = "000000000000000";
unsigned char iv[16] = "000000000000000";
unsigned char ciphertext[16];

struct uc_crypto_options opts = {
	.cipher = AES_ECB,
	.cipher_len = 16,
	.op = ENCRYPT,
	.impl = SW,
	.key = key,
	.key_len = 16,
};

uc_crypto_cipher(plaintext, ciphertext, &opts);
```

## Installation

This project uses [CMake](https://cmake.org/) to build, test, and install `utic-timing`. Installation instructions are contained within [INSTALL.md](https://github.com/camieac/utilc-crypto/blob/master/INSTALL.md), and summarised below:

```
git clone https://github.com/camieac/utilc-crypto.git
cd utilc-crypto
cmake .
make
sudo make install
```

You are also free to add the source files to your own project, and build yourself. Subject the GPL-3.0 license.

## License
This project is released under the [General Public License 3.0 (GPL-3.0)](https://github.com/camieac/utilc-template/blob/master/LICENSE).

## Contributing
Any contribution is welcome. The best way to do this is through Pull Requests. See [CONTRIBUTING.md](https://github.com/camieac/utilc-crypto/blob/master/CONTRIBUTING.md) for more info. In summary: fork, commit changes to fork, pull request. See the [Github Help](https://help.github.com/articles/creating-a-pull-request-from-a-fork/) pages for further information.

## Authors
Cameron A. Craig (@camieac)
