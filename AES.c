// Implementation of AES 128

#include <assert.h>
#include <bits/pthreadtypes.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define Nk 4 // # of 32 bit words comprising the key
#define Nr 10 // number of rounds

#define IN_LEN 16 // input size

// A couple C macros to help with treating int arrays as bit arrays
#define SetBit(A,k)     ( A[(k/32)] |= (1 << (k%32)) )  
#define ClearBit(A,k)   ( A[(k/32)] &= ~(1 << (k%32)) )

// If this is nonzero, then the corresponding bit is 1
// If it's zero, then the corresponding bit is 0
#define TestBit(A,k)    ( A[(k/32)] & (1 << (k%32)) )

static const uint8_t sbox[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t inv_sbox[256] = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static const uint32_t Rcon[10] = {0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x0000001B, 0x00000036};

static uint8_t* TEST_INPUT = (uint8_t*) "Two One Nine Two";
static uint32_t* TEST_KEY = (uint32_t*) "Thats my Kung Fu";

static uint8_t TEST_STATE[4][4] = {{1, 2, 3, 4},
			           {2, 3, 4, 5},
			           {3, 4, 5, 6},
			           {4, 5, 6, 7}};

// Works
uint32_t* key_generation() {
  uint32_t* key = (uint32_t*) malloc(4 * sizeof(uint32_t));
  srand(time(0));
  for (int i = 0; i < 128; i++) {
    int r = rand() % 2;
    assert(r == 0 || r == 1);
    if (r) {
      SetBit(key, i);
    }
    else {
      ClearBit(key, i);
    }
  }
  return key;
}

void print_state(uint8_t state[4][4]) {
  for (int r = 0; r < 4; r++) {
    for (int c = 0; c < 4; c++) {
      printf("%x ", state[r][c]);
    }
    printf("\n");
  }
  printf("\n");
}

// Works
uint32_t rot_word(uint32_t word) {
  uint32_t ret = 0;
  uint8_t byte0 = (word >> 0) & 0xFF;
  uint8_t byte1 = (word >> 8) & 0xFF;
  uint8_t byte2 = (word >> 16) & 0xFF;
  uint8_t byte3 = (word >> 24) & 0xFF;

  ret = (ret & 0xFFFFFF00) | byte1;
  ret = (ret & 0xFFFF00FF) | (byte2 << 8);
  ret = (ret & 0xFF00FFFF) | (byte3 << 16);
  ret = (ret & 0x00FFFFFF) | (byte0 << 24);
  return ret;
}

// Works
uint32_t sub_word(uint32_t word) {
  uint32_t ret = 0;
  uint8_t byte0 = (word >> 0) & 0xFF;
  uint8_t byte1 = (word >> 8) & 0xFF;
  uint8_t byte2 = (word >> 16) & 0xFF;
  uint8_t byte3 = (word >> 24) & 0xFF;

  uint8_t new_byte0 = sbox[byte0];
  uint8_t new_byte1 = sbox[byte1];
  uint8_t new_byte2 = sbox[byte2];
  uint8_t new_byte3 = sbox[byte3];

  ret = (ret & 0xFFFFFF00) | new_byte0;
  ret = (ret & 0xFFFF00FF) | (new_byte1 << 8);
  ret = (ret & 0xFF00FFFF) | (new_byte2 << 16);
  ret = (ret & 0x00FFFFFF) | (new_byte3 << 24);
  return ret;
}

// Works
uint32_t* key_expansion(uint32_t key[]) {
  uint32_t* w = (uint32_t*) malloc((4 * (Nr + 1)) * sizeof(uint32_t));
  int i = 0;
  while (i <= Nk - 1) {
    w[i] = key[i];
    i++;
  }
  while (i <= 4 * Nr + 3) {
    uint32_t temp = w[i - 1];
    if (i % Nk == 0) {
      temp = sub_word(rot_word(temp)) ^ Rcon[i/Nk - 1];
    }
    else if (Nk > 6 && i % Nk == 4) {
      temp = sub_word(temp);
    }
    w[i] = w[i - Nk] ^ temp;
    i++;
  }
  return w;
} 

// Appears to work
void sub_bytes(uint8_t state[4][4]) {
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      uint8_t val = state[row][col];
      uint8_t new_val = sbox[val];
      state[row][col] = new_val;
    }
  }
}

// Appears to work
void shift_rows(uint8_t state[4][4]) {
  uint8_t temp_state[4][4];
  memcpy(temp_state, state, sizeof(uint8_t) * 4 * 4);
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      state[row][col] = temp_state[row][(row + col) % 4];
    }
  }
}

// Appears to work
uint8_t x_times(uint8_t b) {
  if (b & 0x80) {
    return (b << 1) ^ 0x1b;
  }
  return b << 1;
}

// Appears to work
// Got this from chatgpt, the implementation confused me
uint8_t mult(uint8_t b, uint8_t a) {
  uint8_t result = 0;
  uint8_t current = b;
  
  // Process each bit of a
  while (a > 0) {
    if (a & 1) {
      result ^= current;
    }
    current = x_times(current);
    a >>= 1;
  }
  return result;
}

// Appears to work
void mix_columns(uint8_t state[4][4]) {
  uint8_t s[4][4];
  memcpy(s, state, sizeof(uint8_t) * 4 * 4);

  for (int col = 0; col < 4; col++) {
    state[0][col] = mult(0x02, s[0][col]) ^ mult(0x03, s[1][col]) ^ s[2][col] ^ s[3][col];
    state[1][col] = s[0][col] ^ mult(0x02, s[1][col]) ^ mult(0x03, s[2][col]) ^ s[3][col];
    state[2][col] = s[0][col] ^ s[1][col] ^ mult(0x02, s[2][col]) ^ mult(0x03, s[3][col]);
    state[3][col] = mult(0x03, s[0][col]) ^ s[1][col] ^ s[2][col] ^ mult(0x02, s[3][col]);
  }
}

// Appears to work
void add_round_key(uint8_t state[4][4], int round, uint32_t* w) {
  uint8_t s[4][4];
  memcpy(s, state, sizeof(uint8_t) * 4 * 4);
  for (int col = 0; col < 4; col++) {
    uint32_t word = w[4 * round + col];
    uint8_t byte0 = (word >> 0) & 0xFF;
    uint8_t byte1 = (word >> 8) & 0xFF;
    uint8_t byte2 = (word >> 16) & 0xFF;
    uint8_t byte3 = (word >> 24) & 0xFF;

    state[0][col] = s[0][col] ^ byte0;
    state[1][col] = s[1][col] ^ byte1;
    state[2][col] = s[2][col] ^ byte2;
    state[3][col] = s[3][col] ^ byte3;
  }
}

// Appears to work
uint8_t* flatten_state(uint8_t state[4][4]) {
  uint8_t* output = malloc(16 * sizeof(uint8_t));
  for (int c = 0; c < 4; c++) {
    for (int r = 0; r < 4; r++) {
      output[4 * c + r] = state[r][c];
    }
  }
  return output;
}

// Input must be 16 bytes
// Appears to work
uint8_t* cipher(uint8_t in[], uint32_t* key) {
  uint8_t state[4][4];
  for(int i = 0; i < IN_LEN; i++) {
    int r = i % 4;
    int c = i / 4;
    state[r][c] = in[i];
  }
  uint32_t* w = key_expansion(key);
  add_round_key(state, 0, w);
  for (int round = 1; round < Nr; round++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, round, w);
  }
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, Nr, w);
  free(w);
  return flatten_state(state);
}

// Appears to work
void inv_shift_rows(uint8_t state[4][4]) {
  uint8_t temp_state[4][4];
  memcpy(temp_state, state, sizeof(uint8_t) * 4 * 4);
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      int shift = (col - row) % 4;
      shift = (shift < 0) ? (shift + 4) : shift;
      state[row][col] = temp_state[row][shift];
    }
  }
}

void inv_sub_bytes(uint8_t state[4][4]) {
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      uint8_t val = state[row][col];
      uint8_t new_val = inv_sbox[val];
      state[row][col] = new_val;
    }
  }
}

void inv_mix_columns(uint8_t state[4][4]) {
  uint8_t s[4][4];
  memcpy(s, state, sizeof(uint8_t) * 4 * 4);

  for (int col = 0; col < 4; col++) {
    state[0][col] = mult(0x0e, s[0][col]) ^ mult(0x0b, s[1][col]) ^ mult(0x0d, s[2][col]) ^ mult(0x09, s[3][col]);
    state[1][col] = mult(0x09, s[0][col]) ^ mult(0x0e, s[1][col]) ^ mult(0x0b, s[2][col]) ^ mult(0x0d, s[3][col]);
    state[2][col] = mult(0x0d, s[0][col]) ^ mult(0x09, s[1][col]) ^ mult(0x0e, s[2][col]) ^ mult(0x0b, s[3][col]);
    state[3][col] = mult(0x0b, s[0][col]) ^ mult(0x0d, s[1][col]) ^ mult(0x09, s[2][col]) ^ mult(0x0e, s[3][col]);
  }
}

uint8_t* inv_cipher(uint8_t in[], uint32_t* key) {
  uint8_t state[4][4];
  for(int i = 0; i < IN_LEN; i++) {
    int r = i % 4;
    int c = i / 4;
    state[r][c] = in[i];
  }
  uint32_t* w = key_expansion(key);
  add_round_key(state, Nr, w);
  for (int round = Nr - 1; round >= 1; round--) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round, w);
    inv_mix_columns(state);
  }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, 0, w);
    free(w);
    return flatten_state(state);
}

int main() {
  uint32_t* key = key_generation();
  
  printf("Our message (in hex) is\n");
  for (int i = 0; i < 16; i++) {
    printf("%x ", TEST_INPUT[i]);
  }

  printf("\n\n");

  uint8_t* cipher_text = cipher(TEST_INPUT, key);
  printf("Our ciphertext (in hex) is\n");
  for (int i = 0; i < 16; i++) {
    printf("%x ", cipher_text[i]);
  }

  printf("\n\n");

  printf("Our decrypted message (in hex) is\n");
  uint8_t* text_conv = inv_cipher(cipher_text, key);
  for (int i = 0; i < 16; i++) {
    printf("%x ", text_conv[i]);
  }

  printf("\n");

  free(cipher_text);
  free(text_conv);
  free(key);
}
