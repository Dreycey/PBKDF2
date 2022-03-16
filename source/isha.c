/*
 * isha.c
 *
 * A completely insecure and bad hashing algorithm, based loosely on
 * SHA-1 (which is itself no longer considered a good hashing
 * algorithm)
 *
 * Based on code for sha1 processing from Paul E. Jones, available at
 * https://www.packetizer.com/security/sha1/
 */

#include "isha.h"


/*
 * circular shift macro
 */
#define ISHACircularShift(bits,word) \
  ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))


/*  
 * Processes the next 512 bits of the message stored in the MBlock
 * array.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAProcessMessageBlock(ISHAContext *ctx)
{
  uint32_t temp;
//  register int t = 0;
//  uint32_t W[16];
  register uint32_t A;
  uint32_t B, C, D, E;

  A = ctx->MD[0];
  B = ctx->MD[1];
  C = ctx->MD[2];
  D = ctx->MD[3];
  E = ctx->MD[4];

  /*
   * Optimization:
   * 1. Use one for loop in the place of 2 seperate for loops
   * 2. While loop unrolled completely
   */

  //1-4
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (0<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (1<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (2<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (3<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;


  //4-8
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (4<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (5<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (6<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (7<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;


  //8-12
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (8<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (9<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (10<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (11<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;


  //12-16
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (12<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (13<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (14<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;
  temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + (__builtin_bswap32(*((uint32_t *)(ctx->MBlock + (15<<2))))) ) & 0xFFFFFFFF;
  E = D;
  D = C;
  C = ISHACircularShift(30,B);
  B = A;
  A = temp;

  ctx->MD[0] = (ctx->MD[0] + A) & 0xFFFFFFFF;
  ctx->MD[1] = (ctx->MD[1] + B) & 0xFFFFFFFF;
  ctx->MD[2] = (ctx->MD[2] + C) & 0xFFFFFFFF;
  ctx->MD[3] = (ctx->MD[3] + D) & 0xFFFFFFFF;
  ctx->MD[4] = (ctx->MD[4] + E) & 0xFFFFFFFF;
  ctx->MB_Idx = 0;
}


/*  
 * The message must be padded to an even 512 bits.  The first padding
 * bit must be a '1'.  The last 64 bits represent the length of the
 * original message.  All bits in between should be 0. This function
 * will pad the message according to those rules by filling the MBlock
 * array accordingly. It will also call ISHAProcessMessageBlock()
 * appropriately. When it returns, it can be assumed that the message
 * digest has been computed.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAPadMessage(ISHAContext *ctx)
{
  /*
   *  Check to see if the current message block is too small to hold
   *  the initial padding bits and length.  If so, we will pad the
   *  block, process it, and then continue padding into a second
   *  block.
   */
  if (ctx->MB_Idx > 55)
  {
	ctx->MBlock[ctx->MB_Idx++] = 0x80;

    memset(ctx->MBlock + ctx->MB_Idx, 0, ISHA_BLOCKLEN - ctx->MB_Idx);
    ISHAProcessMessageBlock(ctx);
    memset(ctx->MBlock, 0, ISHA_BLOCKLEN - 6);
  }
  else
  {
	ctx->MBlock[ctx->MB_Idx++] = 0x80;
	memset(ctx->MBlock + ctx->MB_Idx,0, 59 - ctx->MB_Idx); // 59, so padding later
  }

  /*
   *  Optimization:
   *  1. Store the message length as last 5 bytes
   *     Note: everything shifted over by 2 bits, so
   *           using 29, 21, etc since it accounts
   *           for the 2 bit shift when converting from
   *           bytes to bits:
   *
   *           1 -> 100
   *           10 -> 1000
   *           100 -> 10000
   *  Big endian
   */
  ctx->MBlock[59] = (ctx->byte_length >> 29) & 0xFF;
  ctx->MBlock[60] = (ctx->byte_length >> 21) & 0xFF;
  ctx->MBlock[61] = (ctx->byte_length >> 13) & 0xFF;
  ctx->MBlock[62] = (ctx->byte_length >> 5) & 0xFF;
  ctx->MBlock[63] = (ctx->byte_length << 3) & 0xFF;

  ISHAProcessMessageBlock(ctx);
}


void ISHAReset(ISHAContext *ctx)
{
  ctx->byte_length = 0; // new Message length
  ctx->MB_Idx      = 0;

  ctx->MD[0]       = 0x67452301;
  ctx->MD[1]       = 0xEFCDAB89;
  ctx->MD[2]       = 0x98BADCFE;
  ctx->MD[3]       = 0x10325476;
  ctx->MD[4]       = 0xC3D2E1F0;

  ctx->Computed    = 0;
  ctx->Corrupted   = 0;
}


void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)
{
	// Corrupt was redundant
//  if (ctx->Corrupted)
//  {
//    return;
//  }

  if (!ctx->Computed)
  {
    ISHAPadMessage(ctx);
    ctx->Computed = 1;
  }

  /*
   * Optimization:
   * 1. Using bswap32 to perform endianess
   * 2. unroll the loop
   */
  *((uint32_t *)(digest_out)) = __builtin_bswap32(ctx->MD[0]);
  *((uint32_t *)(digest_out + 4)) = __builtin_bswap32(ctx->MD[1]);
  *((uint32_t *)(digest_out + 8)) = __builtin_bswap32(ctx->MD[2]);
  *((uint32_t *)(digest_out + 12)) = __builtin_bswap32(ctx->MD[3]);
  *((uint32_t *)(digest_out + 16)) = __builtin_bswap32(ctx->MD[4]);

  return;
}


void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)
{
	  int length_to_store = 0;
	  if (!length)
	  {
	    return;
	  }

	  ctx->byte_length += length;

	  while(length)
	  {
		/*
		 * i.e. if message to big for capacity
		 *          - store as much as possible
		 *      else
		 *          - store entire message
		 */
	    length_to_store = length;
		if ( (ISHA_BLOCKLEN - ctx->MB_Idx) < length) {
			length_to_store = ISHA_BLOCKLEN - ctx->MB_Idx;
		}

		/*
		 * Store message using memcpy at location ctx->MBlock[ctx->MB_Idx]
		 */
		memcpy(ctx->MBlock + ctx->MB_Idx, message_array, length_to_store);

		// updates
		length -= length_to_store; // update the length needed to store still
		ctx->MB_Idx += length_to_store; // update index by len stored
		message_array += length_to_store; // update ptr to msg

		// process maxed out message block
	    if (ctx->MB_Idx == ISHA_BLOCKLEN)
	    {
	      ISHAProcessMessageBlock(ctx);
	    }
	  }

}


