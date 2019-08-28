// --------------------------------------------------------------------------------
//   Copyright (c) 2015, cose-wg
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright notice, this
//     list of conditions and the following disclaimer.
//   
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   
//   * Neither the name of COSE-C nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//   
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// --------------------------------------------------------------------------------

#ifndef __COSE_CONFIGURE_H__
#define __COSE_CONFIGURE_H__


//
//  Determine which cryptographic library we are goig to be usig
//

#if defined(USE_MBED_TLS)
#if defined(USE_OPEN_SSL) || defined(USE_BCRYPT)
#error Only Define One Crypto Package
#endif
#elif defined(USE_BCRYPT)
#if defined(USE_OPENSSL)
#error Only Define One Crypto Package
#endif
#elif !defined(USE_OPEN_SSL)
#define USE_OPEN_SSL
#endif

//
//  Define which AES GCM algorithms are being used
//

#if !defined(USE_MBED_TLS)
#define USE_AES_GCM_128
#define USE_AES_GCM_192
#define USE_AES_GCM_256

#if defined(USE_AES_GCM_128) || defined(USE_AES_GCM_192) || defined(USE_AES_GCM_256)
#define USE_AES_GCM
#endif
#endif // !defined(USE_MBED_TLS)

//
//  Define which AES CCM algorithms are being used
//

#define USE_AES_CCM_16_64_128
#define USE_AES_CCM_16_64_256
#define USE_AES_CCM_64_64_128
#define USE_AES_CCM_64_64_256
#define USE_AES_CCM_16_128_128
#define USE_AES_CCM_16_128_256
#define USE_AES_CCM_64_128_128
#define USE_AES_CCM_64_128_256

#define INCLUDE_AES_CCM

//
//  Define which HMAC-SHA algorithms are being used
//

#define USE_HMAC_256_64
#define USE_HMAC_256_256
#define USE_HMAC_384_384
#define USE_HMAC_512_512
#if defined(USE_HMAC_256_64) || defined(USE_HMAC_256_256) || defined(USE_HMAC_384_384) || defined(USE_HMAC_512_512)
#define USE_HMAC
#endif

//
//  Define which AES CBC-MAC algorithms are to be used
//

#if !defined(USE_MBED_TLS)

#define USE_AES_CBC_MAC_128_64
#define USE_AES_CBC_MAC_128_128
#define USE_AES_CBC_MAC_256_64
#define USE_AES_CBC_MAC_256_128

#endif // !defined(USE_MBED_TLS)

//
//  Define which ECDH algorithms are to be used
//

#if !defined(USE_MBED_TLS)
#define USE_ECDH_ES_HKDF_256
#define USE_ECDH_ES_HKDF_512
#define USE_ECDH_SS_HKDF_256
#define USE_ECDH_SS_HKDF_512
#if defined(USE_ECDH_ES_HKDF_256) || defined(USE_ECDH_ES_HKDF_512) || defined(USE_ECDH_SS_HKDF_256) || defined(USE_ECDH_SS_HKDF_512)
#define USE_ECDH 1
#define USE_HKDF_SHA2 1
#endif
#endif // !defined(USE_MBED_TLS)

#if !defined(USE_MBED_TLS)
#define USE_ECDH_ES_A128KW
#define USE_ECDH_ES_A192KW
#define USE_ECDH_ES_A256KW
#define USE_ECDH_SS_A128KW
#define USE_ECDH_SS_A192KW
#define USE_ECDH_SS_A256KW
#if defined(USE_ECDH_ES_A128KW) || defined(USE_ECDH_ES_A192KW) || defined(USE_ECDH_ES_A256KW) || defined(USE_ECDH_SS_A128KW) || defined(USE_ECDH_SS_A192KW) || defined(USE_ECDH_SS_A256KW)
#define USE_ECDH 1
#define USE_HKDF_AES 1
#endif
#endif // !defined(USE_MBED_TLS)

//
//  Define which Key Wrap functions are to be used
//

#if !defined(USE_MBED_TLS)
#define USE_AES_KW_128
#define USE_AES_KW_192
#define USE_AES_KW_256
#endif // !defined(USE_MBED_TLS)

//
//  Define which of the DIRECT + KDF algorithms are to be used
//

#if !defined(USE_MBED_TLS)
#define USE_Direct_HKDF_HMAC_SHA_256
#define USE_Direct_HKDF_HMAC_SHA_512
#define USE_Direct_HKDF_AES_128
#define USE_Direct_HKDF_AES_256
#if defined(USE_Direct_HKDF_HMAC_SHA_256) || defined(USE_Direct_HKDF_HMAC_SHA_512)
#define USE_HKDF_SHA2 1
#endif
#if defined(USE_Direct_HKDF_AES_128) || defined(USE_Direct_KDF_AES_256)
#define USE_HKDF_AES 1
#endif
#endif // !defined(USE_MBED_TLS)


//
//  Define which of the signature algorithms are to be used
//

#if !defined(USE_MBED_TLS)
#define USE_ECDSA_SHA_256
#define USE_ECDSA_SHA_384
#define USE_ECDSA_SHA_512
#endif // !defined(USE_MBED_TLS)



//#define USE_COUNTER_SIGNATURES

#endif
