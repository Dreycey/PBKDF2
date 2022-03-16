/*
 * pbkdf2.c
 *
 * A perfectly legitimate implementation of HMAC and PBKDF2, but based
 * on the "ISHA" insecure and bad hashing algorithm.
 * 
 * Author: Howdy Pierce, howdy.pierce@colorado.edu
 */

#include <assert.h>

#include "pbkdf2.h"

/*
 * See function description in pbkdf2.h
 */
void hmac_isha(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *digest)
{
  uint8_t ipad[ISHA_BLOCKLEN];
  uint8_t opad[ISHA_BLOCKLEN];
  uint8_t keypad[ISHA_BLOCKLEN];
  uint8_t inner_digest[ISHA_DIGESTLEN];
  size_t i;
  ISHAContext ctx;

  /* Dreycey:
   *     This puts the key into keypad
   *     depending on the key's length
   */

  memcpy(keypad,key,key_len);
  memset(keypad+key_len,0x00,ISHA_BLOCKLEN);

  i = 0;
  // XOR key into ipad and opad
  while (i<ISHA_BLOCKLEN) {
    ipad[i] = keypad[i] ^ 0x36;
    opad[i] = keypad[i] ^ 0x5c;
    i++;
  }

  // Perform inner ISHA
  ISHAReset(&ctx);
  ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);
  ISHAInput(&ctx, msg, msg_len);
  ISHAResult(&ctx, inner_digest);

  // perform outer ISHA
  ISHAReset(&ctx);
  ISHAInput(&ctx, opad, ISHA_BLOCKLEN);
  ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);
  ISHAResult(&ctx, digest);
}


/*
 * Implements the F function as defined in RFC 8018 section 5.2
 *
 * Parameters:
 *   pass      The password
 *   pass_len  length of pass
 *   salt      The salt
 *   salt_len  length of salt
 *   iter      The iteration count ("c" in RFC 8018)
 *   blkidx    the block index ("i" in RFC 8018)
 *   result    The result, which is ISHA_DIGESTLEN bytes long
 * 
 * Returns:
 *   The result of computing the F function, in result
 */
static void F(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len,
    int iter, unsigned int blkidx, uint8_t *result)
{
  uint8_t temp[ISHA_DIGESTLEN];
  uint8_t saltplus[2048];
  size_t i;
  assert(salt_len + 4 <= sizeof(saltplus));

  memcpy(saltplus, salt, salt_len); // optimization: memcpy
  i = salt_len; // i must be incremented to salt len

  // append blkidx in 4 bytes big endian 
  saltplus[i] = (blkidx & 0xff000000) >> 24;
  saltplus[i+1] = (blkidx & 0x00ff0000) >> 16;
  saltplus[i+2] = (blkidx & 0x0000ff00) >> 8;
  saltplus[i+3] = (blkidx & 0x000000ff);

  hmac_isha(pass, pass_len, saltplus, salt_len+4, temp);
  memcpy(result, temp, ISHA_DIGESTLEN); // optimize: great place for mem-copy

  int j=1;
  while(j<iter) {
      hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);
      // UNROLL THE XOR
	  result[0] ^= temp[0];
	  result[1] ^= temp[1];
	  result[2] ^= temp[2];
	  result[3] ^= temp[3];
	  result[4] ^= temp[4];
	  result[5] ^= temp[5];
	  result[6] ^= temp[6];
	  result[7] ^= temp[7];
	  result[8] ^= temp[8];
	  result[9] ^= temp[9];
	  result[10] ^= temp[10];
	  result[11] ^= temp[11];
	  result[12] ^= temp[12];
	  result[13] ^= temp[13];
	  result[14] ^= temp[14];
	  result[15] ^= temp[15];
	  result[16] ^= temp[16];
	  result[17] ^= temp[17];
	  result[18] ^= temp[18];
	  result[19] ^= temp[19];
      j++;
  }

}


/*
 * See function description in pbkdf2.h
 */
void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK)
{
  uint8_t accumulator[2560];
  assert(dkLen < sizeof(accumulator));

  int l = dkLen / ISHA_DIGESTLEN + 1;
  for (int i=0; i<l; i++) {
    F(pass, pass_len, salt, salt_len, iter, i+1, accumulator + i*ISHA_DIGESTLEN);
  }
  memcpy(DK,accumulator,dkLen); // optimization: use memcpy for adding accumulator to DK
}



