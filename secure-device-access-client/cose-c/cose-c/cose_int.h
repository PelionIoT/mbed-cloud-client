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

#include <assert.h>

// These definitions are here because they aren't required for the public
// interface, and they were quite confusing in cn-cbor.h

#ifndef __COSE_INT_H__
#define __COSE_INT_H__

#include "mbed_trace.h"

#ifdef USE_CN_CBOR
#ifdef USE_COUNTER_SIGNATURES
struct _COSE_COUNTER_SIGN;
typedef struct _COSE_COUNTER_SIGN COSE_CounterSign;
#endif
#endif

#define UNUSED(x) ((void) (x))

typedef struct message_buffers_ {
    const uint8_t  *buffer;
    size_t  buffer_size;
    bool is_map_initialized;
}message_buffers_s;

typedef struct _COSE {
	COSE_INIT_FLAGS m_flags;		//  Not sure what goes here yet
	int m_ownMsg;		//  Do I own the pointer @ m_cbor?
	int m_ownUnprotectedMap; //  Do I own the pointer @ m_unportectedMap?
	int m_msgType;		//  What message type is this?
	int m_refCount;			//  Allocator Reference Counting.
#ifdef USE_CN_CBOR
	cn_cbor * m_cbor;
	cn_cbor * m_cborRoot;
	cn_cbor * m_protectedMap;
	cn_cbor * m_unprotectMap;
	cn_cbor * m_dontSendMap;
#else
    message_buffers_s message_cbor; //m_cbor
    message_buffers_s message_root_cbor; //m_cborRoot
    message_buffers_s message_protected_map_cbor; //m_protectedMap
    message_buffers_s message_unprotected_map_cbor; //m_unprotectMap
    message_buffers_s message_dont_send_map_cbor; //m_dontSendMap
#endif
	const byte * m_pbExternal;
	size_t m_cbExternal;

#ifdef USE_CN_CBOR
    //FIXME: Should be USE_COSE_CONTEXT? used by COSE_CALLOC which does not allocate a cn_cbor
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context m_allocContext;
#endif
#endif
	struct _COSE * m_handleList;

#ifdef USE_CN_CBOR
#ifdef USE_COUNTER_SIGNATURES
	COSE_CounterSign * m_counterSigners;
#endif
#endif
} COSE;

struct _SignerInfo;
typedef struct _SignerInfo COSE_SignerInfo;

typedef struct {
	COSE m_message;	    // The message object
	COSE_SignerInfo * m_signerFirst;
} COSE_SignMessage;

typedef struct {
	COSE m_message;	    // The message object
} COSE_Sign0Message;
#ifdef USE_CN_CBOR
struct _SignerInfo {
	COSE m_message;
	const cn_cbor * m_pkey;
	COSE_SignerInfo * m_signerNext;
};

struct _RecipientInfo;
typedef struct _RecipientInfo COSE_RecipientInfo;

#if 0
typedef struct {
	COSE m_message;		// The message object
	const byte * pbContent;
	size_t cbContent;
} COSE_Encrypt;
#endif 

typedef struct {
	COSE m_message;		// The message object
	const byte * pbContent;
	size_t cbContent;
	COSE_RecipientInfo * m_recipientFirst;
} COSE_Enveloped;

typedef COSE_Enveloped COSE_Encrypt;

struct _RecipientInfo {
	COSE_Enveloped m_encrypt;
	COSE_RecipientInfo * m_recipientNext;
	const cn_cbor * m_pkey;
	const cn_cbor * m_pkeyStatic;
};

typedef struct {
	COSE m_message;			// The message object
	COSE_RecipientInfo * m_recipientFirst;
} COSE_MacMessage;

#if 0
typedef struct {
	COSE m_message;			// The message object
} COSE_Mac0Message;
#endif
typedef COSE_MacMessage COSE_Mac0Message;

#ifdef USE_COUNTER_SIGNATURES
typedef struct _COSE_COUNTER_SIGN {
	COSE_SignerInfo m_signer;
	COSE_CounterSign * m_next;
} COSE_CounterSign;
#endif
#endif


#ifdef USE_CN_CBOR
#ifdef USE_COSE_CONTEXT

/**
*  Allocate space required
*
* @param[in]	ctx  The allocation context, or NULL for normal calloc.
* @param[in]	count	Number of items to allocate
* @param[in]	size	Size of item to allocate
* @return				A pointer to the object needed
*/
#define COSE_CALLOC(count, size, ctx) ((((ctx)) && ((ctx)->calloc_func)) ? \
	((ctx)->calloc_func(count, size, (ctx)->context)) : \
	calloc(count, size))

/**
* Free a
* @param  free_func [description]
* @return           [description]
*/

#define COSE_FREE_CONTEXT(ptr, ctx) (((ctx) && (ctx)->free_func)) ? \
    ((ctx)->free_func((ptr), (ctx)->context)) : \
    free((ptr))

#define COSE_FREE(ptr) COSE_FREE_CONTEXT(ptr, cose_allocation_context)

#else
#define COSE_CALLOC(count, size, ctx) calloc(count, size)
#define COSE_FREE(ptr) free(ptr)
#endif

#define CN_CBOR_FREE(p) cn_cbor_free(p CBOR_CONTEXT_PARAM)

#ifdef USE_CBOR_CONTEXT
/**
* Allocate enough space for 1 `cn_cbor` structure.
*
* @param[in]  ctx  The allocation context, or NULL for calloc.
* @return          A pointer to a `cn_cbor` or NULL on failure
*/
/*
#define CN_CALLOC(ctx) ((ctx) && (ctx)->calloc_func) ? \
    (ctx)->calloc_func(1, sizeof(cn_cbor), (ctx)->context) : \
    calloc(1, sizeof(cn_cbor));

*/


//#define CBOR_CONTEXT_PARAM , context
//#define CBOR_CONTEXT_PARAM_COMMA context ,
//#define CN_CALLOC_CONTEXT() CN_CALLOC(context)




#else

//#define CBOR_CONTEXT_PARAM
//#define CBOR_CONTEXT_PARAM_COMMA
//#define CN_CALLOC_CONTEXT() CN_CALLOC



#endif // USE_CBOR_CONTEXT
#endif //USE_CN_CBOR





#define COSE_CALLOC(count, size, ctx) calloc(count, size)
#define COSE_FREE(ptr) free(ptr)


#ifndef UNUSED_PARAM
#define UNUSED_PARAM(p) ((void)&(p))
#endif


#ifdef USE_CN_CBOR
extern cose_error _MapFromCBOR(cn_cbor_errback err);
#else
extern cose_error _MapFromCBOR(CborError err);
#endif

/*
 *  Set of routines for handle checking
 */

extern bool _COSE_SetExternal(COSE * pcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr);
extern void _COSE_InsertInList(COSE ** rootNode, COSE * newMsg);
extern bool _COSE_IsInList(COSE * rootNode, COSE * thisMsg);
extern void _COSE_RemoveFromList(COSE ** rootNode, COSE * thisMsg);

#ifdef USE_CN_CBOR
extern bool IsValidEncryptHandle(HCOSE_ENCRYPT h);
extern bool IsValidEnvelopedHandle(HCOSE_ENVELOPED h);
extern bool IsValidRecipientHandle(HCOSE_RECIPIENT h);
extern bool IsValidSignerHandle(HCOSE_SIGNER h);
extern bool IsValidCounterSignHandle(HCOSE_COUNTERSIGN h);


extern bool _COSE_Init(COSE_INIT_FLAGS flags, COSE * pcose, int msgType, CBOR_CONTEXT_COMMA cose_errback * errp);
extern bool _COSE_Init_From_Object(COSE* pobj, cn_cbor * pcbor, CBOR_CONTEXT_COMMA cose_errback * perror);

extern void _COSE_Release(COSE * pcose CBOR_CONTEXT);

extern cn_cbor * _COSE_map_get_string(COSE * cose, const char * key, int flags, cose_errback * errp);
extern cn_cbor * _COSE_map_get_int(COSE * cose, int key, int flags, cose_errback * errp);
extern bool _COSE_map_put(COSE * cose, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * errp);


extern HCOSE_ENVELOPED _COSE_Enveloped_Init_From_Object(cn_cbor *, COSE_Enveloped * pIn, CBOR_CONTEXT_COMMA cose_errback * errp);
extern void _COSE_Enveloped_Release(COSE_Enveloped * p CBOR_CONTEXT);
extern bool _COSE_Enveloped_decrypt(COSE_Enveloped * pcose, COSE_RecipientInfo * pRecip, const byte *pbKeyIn, size_t cbKeyIn, const char * szContext, cose_errback * perr);
extern bool _COSE_Enveloped_encrypt(COSE_Enveloped * pcose, const byte * pbKeyIn, size_t cbKeyIn, const char * szContext, CBOR_CONTEXT_COMMA cose_errback * perr);
extern bool _COSE_Enveloped_SetContent(COSE_Enveloped * cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);

extern HCOSE_ENCRYPT _COSE_Encrypt_Init_From_Object(cn_cbor *, COSE_Encrypt * pIn, CBOR_CONTEXT_COMMA cose_errback * errp);
extern void _COSE_Encrypt_Release(COSE_Encrypt * p CBOR_CONTEXT);
extern bool _COSE_Encrypt_SetContent(COSE_Encrypt * cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
extern bool _COSE_Encrypt_Build_AAD(COSE * pMessage, byte ** ppbAAD, size_t * pcbAAD, const char * szContext, cose_errback * perr);


extern COSE_RecipientInfo * _COSE_Recipient_Init_From_Object(cn_cbor *, CBOR_CONTEXT_COMMA cose_errback * errp);
extern void _COSE_Recipient_Free(COSE_RecipientInfo *p CBOR_CONTEXT);
extern bool _COSE_Recipient_decrypt(COSE_RecipientInfo * pRecip, COSE_RecipientInfo * pRecipUse, int algIn, size_t cbitKey, byte * pbKey, cose_errback * errp);
extern bool _COSE_Recipient_encrypt(COSE_RecipientInfo * pRecipient, const byte * pbContent, size_t cbContent, cose_errback * perr);
extern byte * _COSE_RecipientInfo_generateKey(COSE_RecipientInfo * pRecipient, int algIn, size_t cbitKeySize, CBOR_CONTEXT_COMMA cose_errback * perr);


//  Signed items
extern HCOSE_SIGN _COSE_Sign_Init_From_Object(cn_cbor *, COSE_SignMessage * pIn, CBOR_CONTEXT_COMMA cose_errback * errp);
extern void _COSE_Sign_Release(COSE_SignMessage * p CBOR_CONTEXT);

//  Signer items

extern bool _COSE_SignerInfo_Init(COSE_INIT_FLAGS flags, COSE_SignerInfo * pcose, int msgType, CBOR_CONTEXT_COMMA cose_errback * errp);
extern bool _COSE_Signer_sign(COSE_SignerInfo * pSigner, const cn_cbor * pcborBody, const cn_cbor * pcborProtected, cose_errback * perr);
extern COSE_SignerInfo * _COSE_SignerInfo_Init_From_Object(cn_cbor * cbor, COSE_SignerInfo * pIn, CBOR_CONTEXT_COMMA cose_errback * perr);
extern bool _COSE_SignerInfo_Free(COSE_SignerInfo * pSigner CBOR_CONTEXT);
extern bool _COSE_Signer_validate(COSE_SignMessage * pSign, COSE_SignerInfo * pSigner, const cn_cbor * pbContent, const cn_cbor * pbProtected, cose_errback * perr);


// Sign0 items
extern HCOSE_SIGN0 _COSE_Sign0_Init_From_Object(cn_cbor * cbor, COSE_Sign0Message * pIn, CBOR_CONTEXT_COMMA cose_errback * perr);
extern void _COSE_Sign0_Release(COSE_Sign0Message * p CBOR_CONTEXT);

//  Mac-ed items
extern HCOSE_MAC _COSE_Mac_Init_From_Object(cn_cbor *, COSE_MacMessage * pIn, CBOR_CONTEXT_COMMA cose_errback * errp);
extern bool _COSE_Mac_Release(COSE_MacMessage * p CBOR_CONTEXT);
extern bool _COSE_Mac_Build_AAD(COSE * pCose, const char * szContext, byte ** ppbAuthData, size_t * pcbAuthData, CBOR_CONTEXT_COMMA cose_errback * perr);
extern bool _COSE_Mac_compute(COSE_MacMessage * pcose, const byte * pbKeyIn, size_t cbKeyIn, const char * szContext, CBOR_CONTEXT_COMMA cose_errback * perr);
extern bool _COSE_Mac_validate(COSE_MacMessage * pcose, COSE_RecipientInfo * pRecip, const byte * pbKeyIn, size_t cbKeyIn, const char * szContext, cose_errback * perr);

//  MAC0 Items
extern HCOSE_MAC0 _COSE_Mac0_Init_From_Object(cn_cbor *, COSE_Mac0Message * pIn, CBOR_CONTEXT_COMMA cose_errback * errp);
extern bool _COSE_Mac0_Release(COSE_Mac0Message * p CBOR_CONTEXT);

//  Counter Sign Items
extern HCOSE_COUNTERSIGN _COSE_CounterSign_get(COSE * pMessage, int iSigner, cose_errback * perr);
extern bool _COSE_CounterSign_add(COSE * pMessage, HCOSE_COUNTERSIGN hSigner, cose_errback * perr);
extern bool _COSE_CountSign_create(COSE * pMessage, cn_cbor * pcnBody, CBOR_CONTEXT_COMMA cose_errback * perr);
#else
HCOSE_SIGN0 _COSE_Sign0_Init_From_Object_tiny(const uint8_t *coseBuffer, size_t coseBufferSize, COSE_Sign0Message * pIn, cose_errback * perr);
//This function currently not in use
bool _COSE_map_put_tiny(COSE * pCose, int key, /*cn_cbor * value,*/ int flags, cose_errback * perr);
bool  _COSE_map_get_int_tiny(COSE * pcose, int key, int flags, uint8_t **out_map_value, size_t *out_map_value_size, cose_errback * perror);
bool _COSE_Init_From_Object_tiny(COSE* pobj, const uint8_t *coseBuffer, size_t coseBufferSize, cose_errback * perr);

#endif
//
//  Debugging Items

//#define DO_ASSERT assert(false);
#define DO_ASSERT
#define CHECK_CONDITION(condition, error) { if (!(condition)) { DO_ASSERT; if (perr != NULL) {perr->err = error;} goto errorReturn;}}
#define FAIL_CONDITION(error) { DO_ASSERT; if (perr != NULL) {perr->err = error;} goto errorReturn;}
#define CHECK_CONDITION_CBOR(condition, error) { if (!(condition)) { DO_ASSERT; if (perr != NULL) {perr->err = _MapFromCBOR(error);} goto errorReturn;}}
#define CHECK_CONDITION_AND_PRINT_MESSAGE(condition, error, format, ...) {\
	if (!(condition)) {\
		DO_ASSERT; \
		if (perr != NULL) {\
			perr->err = error;\
		}\
		mbed_tracef(TRACE_LEVEL_ERROR, "cose", format, ##__VA_ARGS__);\
		goto errorReturn;\
	}\
}
#ifdef USE_CN_CBOR
extern cn_cbor * _COSE_encode_protected(COSE * pMessage, CBOR_CONTEXT_COMMA cose_errback * perr);
#endif

//// Defines on positions

#define INDEX_PROTECTED 0
#define INDEX_UNPROTECTED 1
#define INDEX_BODY 2
#define INDEX_SIGNERS 3
#define INDEX_RECIPIENTS 3
#define INDEX_MAC_TAG 3
#define INDEX_MAC_RECIPIENTS 4
#define INDEX_SIGNATURE 2

//// Defines on message types

#define COSE_Header_Protected 99
#define COSE_Header_Unprotected 98
#define COSE_Header_Type 97
#define COSE_Header_Ciphertext 96
#define COSE_Header_Recipients 95
#define COSE_Header_Signature 94
#define COSE_Header_Signers 93

#ifdef USE_CN_CBOR
bool _COSE_array_replace(COSE * pMessage, cn_cbor * cb_value, int index, CBOR_CONTEXT_COMMA cn_cbor_errback * errp);
cn_cbor * _COSE_arrayget_int(COSE * pMessage, int index);

///  NEW CBOR FUNCTIONS

bool cn_cbor_array_replace(cn_cbor * cb_array, cn_cbor * cb_value, int index, CBOR_CONTEXT_COMMA cn_cbor_errback *errp);
cn_cbor * cn_cbor_bool_create(int boolValue, CBOR_CONTEXT_COMMA cn_cbor_errback * errp);

extern size_t cn_cbor_encode_size(cn_cbor * object);
#endif
enum {
	COSE_Int_Alg_AES_CBC_MAC_256_64 = -22
};


#define COSE_CounterSign_object 1000

#endif

