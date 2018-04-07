// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <string.h>
#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "crypto_verify_32.h"
#include "ge.h"
#include "sc.h"

int crypto_sign_open(
  const unsigned char* sig,
  const unsigned char* m, size_t mlen,
  const unsigned char* pk
)
{
  unsigned char pkcopy[32];
  unsigned char rcopy[32];
  unsigned char scopy[32];
  unsigned char h[64];
  unsigned char rcheck[32];
  ge_p3 A;
  ge_p2 R;

  if (sig[63] & 224) goto badsig;
  if (ge_frombytes_negate_vartime(&A,pk) != 0) goto badsig;

  memmove(pkcopy,pk,32);
  memmove(rcopy, sig, 32);
  memmove(scopy, sig + 32,32);

  crypto_hash_sha512_3(h, rcopy, 32, pkcopy, 32, m, mlen);
  sc_reduce(h);

  ge_double_scalarmult_vartime(&R,h,&A,scopy);
  ge_tobytes(rcheck,&R);
  if (crypto_verify_32(rcheck,rcopy) == 0)
    return 0;

badsig:
  return -1;
}
