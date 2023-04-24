/* William Panlener
 * wepanlen@olemiss.edu
 *
 * ENGR 596-69: Cryptography
 * Spring 2019
 * Assignment 2
 *
 * Implement DES cipher for encryption and decryption
 *
 * Due Friday, February 15, 2019
 * Submit to: Pavani Konagala <pkonagal@olemiss.edu>
 *
 * NOTES FOR GRADER:
 * The interface intentionally parallels that of OpenSSL. This is used both to
 * test the accuracy of the implemented ciphers and to learn how to use
 * real-world cryptography tools.
 *
 * BUILD: gcc -o myssl myssl.c -lgmp
 *
 * DES Cipher
 * ENCRYPT EXAMPLE: echo "The dog runs fast." | ./myssl enc -des-ecb -K ABCDEF12ABCDEF12 > out.enc
 * DECRYPT EXAMPLE: ./myssl enc -des-ecb -d -K ABCDEF12ABCDEF12 < out.enc
 *
 * Caesar Cipher
 * This implementation makes a few assumptions about the caesar cipher:
 * 1. All lowercase alpha-characters are treated as uppercase.
 * 2. Non-alpha characters are not substituted.
 *
 * ENCRYPT EXAMPLE: echo "The dog runs fast." | ./myssl enc -caesar-ecb -K 3
 * DECRYPT EXAMPLE: echo "WKH GRJ UXQV IDVW." | ./myssl enc -caesar-ecb -K 3 -d
 */

/*
 * Copyright 2019 William Panlener
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <gmp.h>
#include <getopt.h>
#include <assert.h>

#define CIPHER_CAESAR_ECB 1
#define CIPHER_DES_ECB    2

#define DEBUG 1
#define TEST 0

void enc_help() {
	printf("Valid options are:\n");
	printf(" -help               Display this summary\n");
	//printf(" -ciphers            List ciphers\n");
	//printf(" -in infile          Input file\n");
	//printf(" -out outfile        Output file\n");
	//printf(" -pass val           Passphrase source\n");
	//printf(" -e                  Encrypt\n");
	printf(" -d                  Decrypt\n");
	//printf(" -p                  Print the iv/key\n");
	//printf(" -P                  Print the iv/key and exit\n");
	//printf(" -v                  Verbose output\n");
	//printf(" -nopad              Disable standard block padding\n");
	//printf(" -salt               Use salt in the KDF (default)\n");
	//printf(" -nosalt             Do not use salt in the KDF\n");
	//printf(" -debug              Print debug info\n");
	//printf(" -a                  Base64 encode/decode, depending on encryption flag\n");
	//printf(" -base64             Same as option -a\n");
	//printf(" -A                  Used with -[base64|a] to specify base64 buffer as a single line\n");
	//printf(" -bufsize val        Buffer size\n");
	//printf(" -k val              Passphrase\n");
	//printf(" -kfile infile       Read passphrase from file\n");
	printf(" -K val              Raw key, in hex\n");
	//printf(" -S val              Salt, in hex\n");
	//printf(" -iv val             IV in hex\n");
	//printf(" -md val             Use specified digest to create a key from the passphrase\n");
	//printf(" -iter +int          Specify the iteration count and force use of PBKDF2\n");
	//printf(" -pbkdf2             Use password-based key derivation function 2\n");
	//printf(" -none               Don't encrypt\n");
	printf(" -*                  Any supported cipher\n");
	//printf(" -rand val           Load the file(s) into the random number generator\n");
	//printf(" -writerand outfile  Write random data to the specified file\n");
	//printf(" -engine val         Use engine, possibly a hardware device\n");
}

int _des_check_odd_parity(mpz_t key) {
	int parity = 0;

	for(mp_bitcnt_t i = 0; i < 64; i++) {
		parity += mpz_tstbit(key, i);

		if(i % 8 == 7) {
			if(parity % 2 == 0) {
				return 0;
			}

			parity = 0;
		}
	}

	return 1;
}

void _des_xor(const int *a, const int *b, int size, int *out) {
	#if DEBUG
	for(int i = 0; i < size; i++) {
		assert(a[i] == 0 || a[i] == 1);
		assert(b[i] == 0 || b[i] == 1);
	}
	#endif

	for(int i = 0; i < size; i++) {
		out[i] = a[i] ^ b[i];
	}
}

void _des_assign(int *to, const int *from, int size) {
	for(int i = 0; i < size; i++) {
		to[i] = from[i];
	}
}

void _des_permute(const int *src, const int *permutation, int size, int *out) {
	for(int i = 0; i < size; i++) {
		out[i] = src[permutation[i] - 1];
	}
}

void _des_feistel_expansion(const int *halfblock, int *out) {
	int expansion[48] = {
		32, 	1, 	2, 	3, 	4, 	5,
		4, 	5, 	6, 	7, 	8, 	9,
		8, 	9, 	10, 	11, 	12, 	13,
		12, 	13, 	14, 	15, 	16, 	17,
		16, 	17, 	18, 	19, 	20, 	21,
		20, 	21, 	22, 	23, 	24, 	25,
		24, 	25, 	26, 	27, 	28, 	29,
		28, 	29, 	30, 	31, 	32, 	1,
	};

	_des_permute(halfblock, expansion, 48, out);
}

void _des_feistel_substitution(int *block, int *out_halfblock) {
	#if DEBUG
	for(int i = 0; i < 48; i++) {
		assert(block[i] == 1 || block[i] == 0);
	}
	#endif

	int s[8][64] = {
	{
		14, 	4, 	13, 	1, 	2, 	15, 	11, 	8, 	3, 	10, 	6, 	12, 	5, 	9, 	0, 	7,
		0, 	15, 	7, 	4, 	14, 	2, 	13, 	1, 	10, 	6, 	12, 	11, 	9, 	5, 	3, 	8,
		4, 	1, 	14, 	8, 	13, 	6, 	2, 	11, 	15, 	12, 	9, 	7, 	3, 	10, 	5, 	0,
		15, 	12, 	8, 	2, 	4, 	9, 	1, 	7, 	5, 	11, 	3, 	14, 	10, 	0, 	6, 	13,
	},
	{
		15, 	1, 	8, 	14, 	6, 	11, 	3, 	4, 	9, 	7, 	2, 	13, 	12, 	0, 	5, 	10,
		3, 	13, 	4, 	7, 	15, 	2, 	8, 	14, 	12, 	0, 	1, 	10, 	6, 	9, 	11, 	5,
		0, 	14, 	7, 	11, 	10, 	4, 	13, 	1, 	5, 	8, 	12, 	6, 	9, 	3, 	2, 	15,
		13, 	8, 	10, 	1, 	3, 	15, 	4, 	2, 	11, 	6, 	7, 	12, 	0, 	5, 	14, 	9,
	},
	{
		10, 	0, 	9, 	14, 	6, 	3, 	15, 	5, 	1, 	13, 	12, 	7, 	11, 	4, 	2, 	8,
		13, 	7, 	0, 	9, 	3, 	4, 	6, 	10, 	2, 	8, 	5, 	14, 	12, 	11, 	15, 	1,
		13, 	6, 	4, 	9, 	8, 	15, 	3, 	0, 	11, 	1, 	2, 	12, 	5, 	10, 	14, 	7,
		1, 	10, 	13, 	0, 	6, 	9, 	8, 	7, 	4, 	15, 	14, 	3, 	11, 	5, 	2, 	12,
	},
	{
		7, 	13, 	14, 	3, 	0, 	6, 	9, 	10, 	1, 	2, 	8, 	5, 	11, 	12, 	4, 	15,
		13, 	8, 	11, 	5, 	6, 	15, 	0, 	3, 	4, 	7, 	2, 	12, 	1, 	10, 	14, 	9,
		10, 	6, 	9, 	0, 	12, 	11, 	7, 	13, 	15, 	1, 	3, 	14, 	5, 	2, 	8, 	4,
		3, 	15, 	0, 	6, 	10, 	1, 	13, 	8, 	9, 	4, 	5, 	11, 	12, 	7, 	2, 	14,
	},
	{
		2, 	12, 	4, 	1, 	7, 	10, 	11, 	6, 	8, 	5, 	3, 	15, 	13, 	0, 	14, 	9,
		14, 	11, 	2, 	12, 	4, 	7, 	13, 	1, 	5, 	0, 	15, 	10, 	3, 	9, 	8, 	6,
		4, 	2, 	1, 	11, 	10, 	13, 	7, 	8, 	15, 	9, 	12, 	5, 	6, 	3, 	0, 	14,
		11, 	8, 	12, 	7, 	1, 	14, 	2, 	13, 	6, 	15, 	0, 	9, 	10, 	4, 	5, 	3,
	},
	{
		12, 	1, 	10, 	15, 	9, 	2, 	6, 	8, 	0, 	13, 	3, 	4, 	14, 	7, 	5, 	11,
		10, 	15, 	4, 	2, 	7, 	12, 	9, 	5, 	6, 	1, 	13, 	14, 	0, 	11, 	3, 	8,
		9, 	14, 	15, 	5, 	2, 	8, 	12, 	3, 	7, 	0, 	4, 	10, 	1, 	13, 	11, 	6,
		4, 	3, 	2, 	12, 	9, 	5, 	15, 	10, 	11, 	14, 	1, 	7, 	6, 	0, 	8, 	13,
	},
	{
		4, 	11, 	2, 	14, 	15, 	0, 	8, 	13, 	3, 	12, 	9, 	7, 	5, 	10, 	6, 	1,
		13, 	0, 	11, 	7, 	4, 	9, 	1, 	10, 	14, 	3, 	5, 	12, 	2, 	15, 	8, 	6,
		1, 	4, 	11, 	13, 	12, 	3, 	7, 	14, 	10, 	15, 	6, 	8, 	0, 	5, 	9, 	2,
		6, 	11, 	13, 	8, 	1, 	4, 	10, 	7, 	9, 	5, 	0, 	15, 	14, 	2, 	3, 	12,
	},
	{
		13, 	2, 	8, 	4, 	6, 	15, 	11, 	1, 	10, 	9, 	3, 	14, 	5, 	0, 	12, 	7,
		1, 	15, 	13, 	8, 	10, 	3, 	7, 	4, 	12, 	5, 	6, 	11, 	0, 	14, 	9, 	2,
		7, 	11, 	4, 	1, 	9, 	12, 	14, 	2, 	0, 	6, 	10, 	13, 	15, 	3, 	5, 	8,
		2, 	1, 	14, 	7, 	4, 	10, 	8, 	13, 	15, 	12, 	9, 	0, 	3, 	5, 	6, 	11,
	},
	};

	int r, c;
	int s_value;

	for(int i = 0; i < 8; i++) {
		c = 8 * block[6 * i + 1] + 
		    4 * block[6 * i + 2] + 
		    2 * block[6 * i + 3] +
		    1 * block[6 * i + 4];

		r = 2 * block[6 * i + 0] +
		    1 * block[6 * i + 5];

		s_value = s[i][16 * r + c];

		out_halfblock[4 * i + 0] = (s_value >> 3) & 1;
		out_halfblock[4 * i + 1] = (s_value >> 2) & 1;
		out_halfblock[4 * i + 2] = (s_value >> 1) & 1;
		out_halfblock[4 * i + 3] = (s_value >> 0) & 1;
	}
}

void _des_feistel_permutation(int *halfblock) {
	int temp[32];

	int permutation[32] = {
		16, 	7, 	20, 	21, 	29, 	12, 	28, 	17,
		1, 	15, 	23, 	26, 	5, 	18, 	31, 	10,
		2, 	8, 	24, 	14, 	32, 	27, 	3, 	9,
		19, 	13, 	30, 	6, 	22, 	11, 	4, 	25,
	};

	_des_assign(temp, halfblock, 32);
	_des_permute(temp, permutation, 32, halfblock);
}

void _des_feistel(const int *halfblock, const int *subkey, int *out_halfblock) {
	int temp[48];

	_des_feistel_expansion(halfblock, temp);
	_des_xor(temp, subkey, 48, temp);
	_des_feistel_substitution(temp, out_halfblock);
	_des_feistel_permutation(out_halfblock);
}

void _des_keyschedule_pc1(int *key, int *left_half, int *right_half) {
	int left_permute[28] = {
		57,     49,     41,     33,     25,     17,     9,
		1,      58,     50,     42,     34,     26,     18,
		10,     2,      59,     51,     43,     35,     27,
		19,     11,     3,      60,     52,     44,     36,
	};

	int right_permute[28] = {
		63,     55,     47,     39,     31,     23,     15,
		7,      62,     54,     46,     38,     30,     22,
		14,     6,      61,     53,     45,     37,     29,
		21,     13,     5,      28,     20,     12,     4,
	};

	_des_permute(key, left_permute, 28, left_half);
	_des_permute(key, right_permute, 28, right_half);
}

void _des_lrotate_halfkey(int *halfkey) {
	int temp = halfkey[0];

	for(int i = 0; i < 27; i++) {
		halfkey[i] = halfkey[i+1];
	}

	halfkey[27] = temp;
}

void _des_keyschedule_pc2(int *left_half, int *right_half, int *subkey) {
	int permute[48] = {
		14,     17,     11,     24,     1,      5,
		3,      28,     15,     6,      21,     10,
		23,     19,     12,     4,      26,     8,
		16,     7,      27,     20,     13,     2,
		41,     52,     31,     37,     47,     55,
		30,     40,     51,     45,     33,     48,
		44,     49,     39,     56,     34,     53,
		46,     42,     50,     36,     29,     32,
	};

	int state[56];

	_des_assign(state, left_half, 28);
	_des_assign(&state[28], right_half, 28);
	_des_permute(state, permute, 48, subkey);
}

void _des_keyschedule(int *key, int **subkey) {
	int left_half[28];
	int right_half[28];

	int bit_rotation[16] = {
		1,      1,      2,      2,
		2,      2,      2,      2,
		1,      2,      2,      2,
		2,      2,      2,      1,
	};

	_des_keyschedule_pc1(key, left_half, right_half);

	for(int i = 0; i < 16; i++) {
		for(int j = 0; j < bit_rotation[i]; j++) {
			_des_lrotate_halfkey(left_half);
			_des_lrotate_halfkey(right_half);
		}

		_des_keyschedule_pc2(left_half, right_half, subkey[i]);
	}
}

void _des_crypt_ip(const int* text, int *left_half, int *right_half) {
	int left_permute[32] = {
		58, 	50, 	42, 	34, 	26, 	18, 	10, 	2,
		60, 	52, 	44, 	36, 	28, 	20, 	12, 	4,
		62, 	54, 	46, 	38, 	30, 	22, 	14, 	6,
		64, 	56, 	48, 	40, 	32, 	24, 	16, 	8,
	};

	int right_permute[32] = {
		57, 	49, 	41, 	33, 	25, 	17, 	9, 	1,
		59, 	51, 	43, 	35, 	27, 	19, 	11, 	3,
		61, 	53, 	45, 	37, 	29, 	21, 	13, 	5,
		63, 	55, 	47, 	39, 	31, 	23, 	15, 	7,
	};

	_des_permute(text, left_permute, 32, left_half);
	_des_permute(text, right_permute, 32, right_half);
}

void _des_crypt_fp(int *text, int *left_half, int *right_half) {
	int permute[64] = {
		40, 	8, 	48, 	16, 	56, 	24, 	64, 	32,
		39, 	7, 	47, 	15, 	55, 	23, 	63, 	31,
		38, 	6, 	46, 	14, 	54, 	22, 	62, 	30,
		37, 	5, 	45, 	13, 	53, 	21, 	61, 	29,
		36, 	4, 	44, 	12, 	52, 	20, 	60, 	28,
		35, 	3, 	43, 	11, 	51, 	19, 	59, 	27,
		34, 	2, 	42, 	10, 	50, 	18, 	58, 	26,
		33, 	1, 	41, 	9, 	49, 	17, 	57, 	25,
	};

	int state[64];

	_des_assign(state, left_half, 32);
	_des_assign(&state[32], right_half, 32);
	_des_permute(state, permute, 64, text);
}

int ** des_init(mpz_t _key) {
	int key[64];
	int **subkey;

	subkey = (int **) malloc(16 * sizeof(int *));
	for(int i = 0; i < 16; i++) {
		subkey[i] = (int *) malloc(48 * sizeof(int *));
	}

	for(int i = 0; i < 64; i++) {
		key[i] = mpz_tstbit(_key, 63 - i); 
	}

	_des_keyschedule(key, subkey);

	return subkey;
}

void des_destroy(int **subkeys) {
	for(int i = 0; i < 16; i++) {
		free(subkeys[i]);
	}

	free(subkeys);
}

void _des_chararray_to_bitfield(const char *arr, int *bitfield, int arr_size) {
	for(int i = 0; i < arr_size; i++) {
		for(int j = 0; j < 8; j++) {
			bitfield[i * 8 + j] = (arr[i] >> (7 - j)) & 1;
		}
	}
}

void _des_crypt(int **subkey, FILE *in, FILE *out, int encrypt) {
	char msg_c[8];
	int msg[64];
	int left_half[32];
	int right_half[32];
	int temp[32];
	size_t bytes_read;
	int c;

	int buffer_size = 0;

	while(!feof(in)) {
		bytes_read = fread(&msg_c[buffer_size], sizeof(char), 1, in); 
		buffer_size += bytes_read;

		if(buffer_size < 8 && !feof(in)) {
			continue;
		} else if(encrypt) {
			/* PKCS#7 padding */
			for(int i = buffer_size; i < 8; i++) {
				msg_c[i] = (char) (8 - buffer_size);
			}
		}

		buffer_size = 0;

		_des_chararray_to_bitfield(msg_c, msg, 8);		
		_des_crypt_ip(msg, left_half, right_half);

		for(int i = 0; i < 16; i++) {
			_des_feistel(right_half, subkey[i], temp);
			_des_xor(left_half, temp, 32, temp);
			_des_assign(left_half, right_half, 32);
			_des_assign(right_half, temp, 32);
		}

		/* Thanks for the bad diagram wikipedia... swap left and right half after round 16 */
		_des_crypt_fp(msg, right_half, left_half);

		/* bitfield -> char[] */
		for(int i = 0; i < 8; i++) {
			msg_c[i] = 0;

			for(int j = 0; j < 8; j++) {
				msg_c[i] += msg[8 * i + j] << (7 - j);
			}
		}
		if(!encrypt) {
			c = fgetc(in);

			if(feof(in)) {
				/* Remove PKCS#7 padding */
				#if DEBUG
				fprintf(stderr, "Found %d bytes of PKCS#7 padding.\n", msg_c[7]);
				assert(msg_c[7] >= 1 && msg_c[7] <= 8);
				#endif

				fwrite(msg_c, 1, 8 - msg_c[7], out);
			} else {
				fwrite(msg_c, 1, 8, out);
			}

			ungetc(c, in);
		} else {
			fwrite(msg_c, 1, 8, out);
		}
	}
}

void des_encrypt(int **_subkey, FILE *in, FILE *out) {
	_des_crypt(_subkey, in, out, 1);
}

void des_decrypt(int **_subkey, FILE *in, FILE *out) {
	int *subkey[16];

	for(int i = 0; i < 16; i++) {
		subkey[i] = _subkey[15 - i];
	}

	_des_crypt(subkey, in, out, 0);
}

void des_test() {
	/* Tests created using intermediate cipher states published in:
	 * Grabbe, J. Orlin. "The DES algorithm illustrated." (2010).
         *
	 * @misc{grabbe2010algorithm,
 	 *   title={The DES algorithm illustrated},
	 *   author={Grabbe, J Orlin}
	 * } 
	 */

	mpz_t key;
	int **subkey;
        int left_half[32];
        int right_half[32];
        int temp[32];

	mpz_init_set_str(key, "133457799BBCDFF1", 16);

	subkey = des_init(key);

	int expected_subkeys[16][48] = {
	{0,0,0,1,1,0, 1,1,0,0,0,0, 0,0,1,0,1,1, 1,0,1,1,1,1, 1,1,1,1,1,1, 0,0,0,1,1,1, 0,0,0,0,0,1, 1,1,0,0,1,0,},
	{0,1,1,1,1,0, 0,1,1,0,1,0, 1,1,1,0,1,1, 0,1,1,0,0,1, 1,1,0,1,1,0, 1,1,1,1,0,0, 1,0,0,1,1,1, 1,0,0,1,0,1,},
	{0,1,0,1,0,1, 0,1,1,1,1,1, 1,1,0,0,1,0, 0,0,1,0,1,0, 0,1,0,0,0,0, 1,0,1,1,0,0, 1,1,1,1,1,0, 0,1,1,0,0,1,},
	{0,1,1,1,0,0, 1,0,1,0,1,0, 1,1,0,1,1,1, 0,1,0,1,1,0, 1,1,0,1,1,0, 1,1,0,0,1,1, 0,1,0,1,0,0, 0,1,1,1,0,1,},
	{0,1,1,1,1,1, 0,0,1,1,1,0, 1,1,0,0,0,0, 0,0,0,1,1,1, 1,1,1,0,1,0, 1,1,0,1,0,1, 0,0,1,1,1,0, 1,0,1,0,0,0,},
	{0,1,1,0,0,0, 1,1,1,0,1,0, 0,1,0,1,0,0, 1,1,1,1,1,0, 0,1,0,1,0,0, 0,0,0,1,1,1, 1,0,1,1,0,0, 1,0,1,1,1,1,},
	{1,1,1,0,1,1, 0,0,1,0,0,0, 0,1,0,0,1,0, 1,1,0,1,1,1, 1,1,1,1,0,1, 1,0,0,0,0,1, 1,0,0,0,1,0, 1,1,1,1,0,0,},
	{1,1,1,1,0,1, 1,1,1,0,0,0, 1,0,1,0,0,0, 1,1,1,0,1,0, 1,1,0,0,0,0, 0,1,0,0,1,1, 1,0,1,1,1,1, 1,1,1,0,1,1,},
	{1,1,1,0,0,0, 0,0,1,1,0,1, 1,0,1,1,1,1, 1,0,1,0,1,1, 1,1,1,0,1,1, 0,1,1,1,1,0, 0,1,1,1,1,0, 0,0,0,0,0,1,},
	{1,0,1,1,0,0, 0,1,1,1,1,1, 0,0,1,1,0,1, 0,0,0,1,1,1, 1,0,1,1,1,0, 1,0,0,1,0,0, 0,1,1,0,0,1, 0,0,1,1,1,1,},
	{0,0,1,0,0,0, 0,1,0,1,0,1, 1,1,1,1,1,1, 0,1,0,0,1,1, 1,1,0,1,1,1, 1,0,1,1,0,1, 0,0,1,1,1,0, 0,0,0,1,1,0,},
	{0,1,1,1,0,1, 0,1,0,1,1,1, 0,0,0,1,1,1, 1,1,0,1,0,1, 1,0,0,1,0,1, 0,0,0,1,1,0, 0,1,1,1,1,1, 1,0,1,0,0,1,},
	{1,0,0,1,0,1, 1,1,1,1,0,0, 0,1,0,1,1,1, 0,1,0,0,0,1, 1,1,1,1,1,0, 1,0,1,0,1,1, 1,0,1,0,0,1, 0,0,0,0,0,1,},
	{0,1,0,1,1,1, 1,1,0,1,0,0, 0,0,1,1,1,0, 1,1,0,1,1,1, 1,1,1,1,0,0, 1,0,1,1,1,0, 0,1,1,1,0,0, 1,1,1,0,1,0,},
	{1,0,1,1,1,1, 1,1,1,0,0,1, 0,0,0,1,1,0, 0,0,1,1,0,1, 0,0,1,1,1,1, 0,1,0,0,1,1, 1,1,1,1,0,0, 0,0,1,0,1,0,},
	{1,1,0,0,1,0, 1,1,0,0,1,1, 1,1,0,1,1,0, 0,0,1,0,1,1, 0,0,0,0,1,1, 1,0,0,0,0,1, 0,1,1,1,1,1, 1,1,0,1,0,1,},
	};

	int subkey_test = 1;
	for(int i = 0; i < 16; i++) {
		for(int j = 0; j < 48; j++) {
			if(subkey[i][j] != expected_subkeys[i][j]) {
				subkey_test = 0;
			}
		}
		assert(subkey_test);
	}

	char message_chararray[8] = {
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xAB, 0xCD, 0xEF,
	};

	int expected_message_bitfield[64] = {
		0,0,0,0, 0,0,0,1, 0,0,1,0, 0,0,1,1,
		0,1,0,0, 0,1,0,1, 0,1,1,0, 0,1,1,1,
		1,0,0,0, 1,0,0,1, 1,0,1,0, 1,0,1,1,
		1,1,0,0, 1,1,0,1, 1,1,1,0, 1,1,1,1,
	};

	int message_bitfield[64];
	_des_chararray_to_bitfield(message_chararray, message_bitfield, 8);

	int carr_bfield_test = 1;
	for(int i = 0; i < 64; i++) {
		if(message_bitfield[i] != expected_message_bitfield[i]) {
			carr_bfield_test = 0;
		}
	}
	assert(carr_bfield_test);

	_des_crypt_ip(message_bitfield, left_half, right_half);

	int expected_ipout_left[32] = {
		1,1,0,0, 1,1,0,0, 0,0,0,0, 0,0,0,0, 1,1,0,0, 1,1,0,0, 1,1,1,1, 1,1,1,1,
	};

	int expected_ipout_right[32] = {
		1,1,1,1, 0,0,0,0, 1,0,1,0, 1,0,1,0, 1,1,1,1, 0,0,0,0, 1,0,1,0, 1,0,1,0, 
	};

	int ipout_left_test = 1;
	for(int i = 0; i < 32; i++) {
		if(left_half[i] != expected_ipout_left[i]) {
			ipout_left_test = 0;
		}
	}
	assert(ipout_left_test);

	int ipout_right_test = 1;
	for(int i = 0; i < 32; i++) {
		if(right_half[i] != expected_ipout_right[i]) {
			ipout_right_test = 0;
		}
	}
	assert(ipout_right_test);

	int expected_feistel[32] = {
		0,0,1,0, 0,0,1,1, 0,1,0,0, 1,0,1,0, 1,0,1,0, 1,0,0,1, 1,0,1,1, 1,0,1,1,
	};

	int feistel_test = 1;
	_des_feistel(right_half, subkey[0], temp);
	for(int i = 0; i < 32; i++) {
		if(temp[i] != expected_feistel[i]) {
			feistel_test = 0;
		}
	}
	assert(feistel_test);

	for(int i = 0; i < 16; i++) {
		_des_feistel(right_half, subkey[i], temp);
		_des_xor(left_half, temp, 32, temp);
		_des_assign(left_half, right_half, 32);
		_des_assign(right_half, temp, 32);
	}

	int expected_round16_left[32] = {
		 0,1,0,0, 0,0,1,1, 0,1,0,0, 0,0,1,0, 0,0,1,1, 0,0,1,0, 0,0,1,1, 0,1,0,0,
	};

	int expected_round16_right[32] = {
		0,0,0,0, 1,0,1,0, 0,1,0,0, 1,1,0,0, 1,1,0,1, 1,0,0,1, 1,0,0,1, 0,1,0,1,
	};

	int round16_left_test = 1;
	for(int i = 0; i < 32; i++) {
		if(left_half[i] != expected_round16_left[i]) {
			round16_left_test = 0;
		}
	}
	assert(round16_left_test);

	int round16_right_test = 1;
	for(int i = 0; i < 32; i++) {
		if(right_half[i] != expected_round16_right[i]) {
			round16_right_test = 0;
		}
	}
	assert(round16_right_test);

	_des_crypt_fp(message_bitfield, right_half, left_half);

	int expected_fpout_bitfield[64] = {
		1,0,0,0,0,1,0,1, 1,1,1,0,1,0,0,0, 0,0,0,1,0,0,1,1, 0,1,0,1,0,1,0,0, 0,0,0,0,1,1,1,1, 0,0,0,0,1,0,1,0, 1,0,1,1,0,1,0,0, 0,0,0,0,0,1,0,1, 
	};

	int fpout_test = 1;
	for(int i = 0; i < 64; i++) {
		if(message_bitfield[i] != expected_fpout_bitfield[i]) {
			fpout_test = 0;
		}
	}
	assert(fpout_test);

	des_destroy(subkey);
}

void caesar_encrypt(mpz_t _key, FILE *in, FILE *out) {
	int c;
	char key;

	mpz_t mod_key;
	mpz_init(mod_key);
	mpz_mod_ui(mod_key, _key, (unsigned long int) 26);

	key = (char) mpz_get_si(mod_key);

	mpz_clear(mod_key);

	while((c = fgetc(in)) != EOF) {
		if(isalpha(c)) {
			c = toupper(c);
			c = (c - (int) 'A' + key) % 26 + (int) 'A';
		}

		fputc(c, out);
	}
}

void caesar_decrypt(mpz_t _key, FILE *in, FILE *out) {
	mpz_t neg_key;

	mpz_init(neg_key);
	mpz_neg(neg_key, _key);

	caesar_encrypt(neg_key, in, out);

	mpz_clear(neg_key);
}

int help() {
	printf("Standard commands\n");
	printf("enc               help\n");
	//printf("crl               crl2pkcs7         dgst              dhparam")

	printf("\n");

	printf("Cipher commands (see the `enc' command for more details)\n");
	printf("caesar-ecb        des-ecb\n");
	//printf("aes-256-cbc       aes-256-ecb       aria-128-cbc      aria-128-cfb");

	printf("\n");

	return 0;
}

int enc(int argc, char **argv) {
	mpz_t key;

	int c;
	int kopt = 0;
	int dopt = 0;
	int cipher = 0;
	int hopt = 0;
	int indexptr = 0;
	int badopt = 0;

	/* openssl enc -d -des-ecb -K abcdef12abcdef12 */
	struct option long_options[] = {
		{"des-ecb",      no_argument,       &cipher,  CIPHER_DES_ECB    },
		{"caesar-ecb",   no_argument,       &cipher,  CIPHER_CAESAR_ECB },
		{"help",         no_argument,       &hopt,    1 },
		{0,              0,                 0,        0 }
	};

	opterr = 0;

	while((c = getopt_long_only(argc, argv, "K:d", long_options, &indexptr)) != -1) {
		switch(c) {
		case 'K':
			if(mpz_init_set_str(key, optarg, 16) == -1) {
				fprintf(stderr, "non-hex digit\n");
				fprintf(stderr, "invalid hex key value\n");
			}
			kopt = 1;
			break;
		case 'd':
			dopt = 1;
			break;
		case 0:
			break;
		default:
			badopt = 1;

			if(optopt) {
				fprintf(stderr, "enc: Unrecognized flag %c\n", optopt);
			} else {
				fprintf(stderr, "enc: Unrecognized flag %s\n", &argv[optind - 1][1]);
			}

			break;
		}
	}

	if(hopt) {
		enc_help();

		return 0;
	}

	if(badopt) {
		fprintf(stderr, "enc: Use -help for summary.\n");

		return EXIT_FAILURE;
	}

	if(cipher == 0) {
		fprintf(stderr, "enc: Cipher not specified.\n");

		return EXIT_FAILURE;
	}

	if(!kopt) {
		fprintf(stderr, "enc: Cipher key not specified.\n");

		return EXIT_FAILURE;
	}

	if(optind != argc) {
		fprintf(stderr, "Extra arguments given.\n");
		fprintf(stderr, "enc: Use -help for summary.\n");

		return EXIT_FAILURE;
	}

	if(cipher == CIPHER_CAESAR_ECB) {
		if(dopt) {
			caesar_decrypt(key, stdin, stdout);
		} else {
			caesar_encrypt(key, stdin, stdout);
		}
	}

	if(cipher == CIPHER_DES_ECB) {
		int **subkey = des_init(key);

		if(dopt) {
			des_decrypt(subkey, stdin, stdout);
		} else {
			des_encrypt(subkey, stdin, stdout);
		}

		des_destroy(subkey);
	}
 
	if(kopt) {
		mpz_clear(key);
	}

	return 0;
}

int main(int argc, char **argv) {
	#if TEST
	des_test();

	return 0;
	#endif

	if(argc < 2) {
		fprintf(stderr, "Interactive mode not implemented\n");

		return EXIT_FAILURE;
	}

	if(strcmp("enc", argv[1]) == 0) {
		return enc(argc - 1, &argv[1]);
	} else if(strcmp("help", argv[1]) == 0) {
		return help();
	} else {
		fprintf(stderr, "Invalid command '%s'; type \"help\" for a list.\n", argv[1]);

		return EXIT_FAILURE;
	}

	return 0;
}
