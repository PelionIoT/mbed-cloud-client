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

/** \file Sign.c
* Contains implementation of the functions related to HCOSE_SIGN handle objects.
*/

#include <stdlib.h>

#include "cose.h"
#include "cose_int.h"


#ifdef USE_CN_CBOR
COSE * SignRoot = NULL;

/*! \private
* @brief Test if a HCOSE_SIGN handle is valid
*
*  Internal function to test if a sign handle is valid.
*  This will start returning invalid results and cause the code to
*  crash if handles are not released before the memory that underlies them
*  is deallocated.  This is an issue of a block allocator is used since
*  in that case it is common to allocate memory but never to de-allocate it
*  and just do that in a single big block.
*
*  @param h handle to be validated
*  @returns result of check
*/

bool IsValidSignHandle(HCOSE_SIGN h)
{
	COSE_SignMessage * p = (COSE_SignMessage *)h;

	if (p == NULL) return false;
	return _COSE_IsInList(SignRoot, (COSE *) p);
}


/** Allocate a SIGN message structure.
*
* Allocate a new SIGN message structure for creation of a COSE_Sign object.
* @param context is a cn_cbor context object
* @param perr is a cose_errback return variable
* @return HCOSE_SIGN a handle for the newly allocated object
*/
HCOSE_SIGN COSE_Sign_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	CHECK_CONDITION(flags == COSE_INIT_FLAGS_NONE, COSE_ERR_INVALID_PARAMETER);
	COSE_SignMessage * pobj = (COSE_SignMessage *)COSE_CALLOC(1, sizeof(COSE_SignMessage), context);
	CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init(flags, &pobj->m_message, COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_Sign_Release(pobj CBOR_CONTEXT_PARAM);
		COSE_FREE(pobj);
		return NULL;
	}

	_COSE_InsertInList(&SignRoot, &pobj->m_message);

	return (HCOSE_SIGN)pobj;

errorReturn:
	return NULL;
}

HCOSE_SIGN _COSE_Sign_Init_From_Object(cn_cbor * cbor, COSE_SignMessage * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_SignMessage * pobj = pIn;
	cn_cbor * pSigners = NULL;
	// cn_cbor * tmp;
	cose_errback error = { 0 };
	if (perr == NULL) perr = &error;

	if (pobj == NULL) pobj = (COSE_SignMessage *)COSE_CALLOC(1, sizeof(COSE_SignMessage), context);
	CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	pSigners = _COSE_arrayget_int(&pobj->m_message, INDEX_SIGNERS);
	CHECK_CONDITION(pSigners != NULL, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(pSigners->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);
	CHECK_CONDITION(pSigners->length > 0, COSE_ERR_INVALID_PARAMETER); // Must be at least one signer

	pSigners = pSigners->first_child;
	do {
		COSE_SignerInfo * pInfo = _COSE_SignerInfo_Init_From_Object(pSigners, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
		if (pInfo == NULL) goto errorReturn;

		pInfo->m_signerNext = pobj->m_signerFirst;
		pobj->m_signerFirst = pInfo;
		pSigners = pSigners->next;
	} while (pSigners != NULL);

	if (pIn == NULL) _COSE_InsertInList(&SignRoot, &pobj->m_message);

	return(HCOSE_SIGN)pobj;

errorReturn:
	if (pobj != NULL) {
		_COSE_Sign_Release(pobj CBOR_CONTEXT_PARAM);
		if (pIn == NULL) COSE_FREE(pobj);
	}
	return NULL;
}

bool COSE_Sign_Free(HCOSE_SIGN h CBOR_CONTEXT)
{
	COSE_SignMessage * pMessage = (COSE_SignMessage *)h;

	if (!IsValidSignHandle(h)) return false;

	//  Check reference counting
	if (pMessage->m_message.m_refCount > 1) {
		pMessage->m_message.m_refCount--;
		return true;
	}

	_COSE_RemoveFromList(&SignRoot, &pMessage->m_message);

	_COSE_Sign_Release(pMessage CBOR_CONTEXT_PARAM);

	COSE_FREE(pMessage);

	return true;
}

void _COSE_Sign_Release(COSE_SignMessage * p CBOR_CONTEXT)
{
	COSE_SignerInfo * pSigner;
	COSE_SignerInfo * pSigner2;

	for (pSigner = p->m_signerFirst; pSigner != NULL; pSigner = pSigner2)
	{
		pSigner2 = pSigner->m_signerNext;
		_COSE_SignerInfo_Free(pSigner CBOR_CONTEXT_PARAM);
	}

	_COSE_Release(&p->m_message CBOR_CONTEXT_PARAM);
}

bool COSE_Sign_SetContent(HCOSE_SIGN h, const byte * rgb, size_t cb, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	cn_cbor * p = NULL;
	COSE_SignMessage * pMessage = (COSE_SignMessage *)h;
	bool f = false;

	CHECK_CONDITION(IsValidSignHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(rgb != NULL, COSE_ERR_INVALID_PARAMETER);

	p = cn_cbor_data_create(rgb, (int) cb, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(p != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(_COSE_array_replace(&pMessage->m_message, p, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_OUT_OF_MEMORY);
	p = NULL;

	f = true;
errorReturn:
	if (p != NULL) CN_CBOR_FREE(p);

	return f;
}

HCOSE_SIGNER COSE_Sign_add_signer(HCOSE_SIGN hSign, const cn_cbor * pkey, int algId, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	const cn_cbor * cbor;
	cn_cbor * cbor2 = NULL;
	HCOSE_SIGNER hSigner = NULL;
	cn_cbor_errback cbor_error;

	CHECK_CONDITION(IsValidSignHandle(hSign), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pkey != NULL, COSE_ERR_INVALID_PARAMETER);

	hSigner = COSE_Signer_Init(CBOR_CONTEXT_PARAM_COMMA perr);
	if (hSigner == NULL) goto errorReturn;


	cbor2 = cn_cbor_int_create(algId, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cbor2 != NULL, cbor_error);
	if (!COSE_Signer_map_put_int(hSigner, COSE_Header_Algorithm, cbor2, COSE_PROTECT_ONLY, CBOR_CONTEXT_PARAM_COMMA perr)) goto errorReturn;
	cbor2 = NULL;

	cbor = cn_cbor_mapget_int(pkey, COSE_Key_ID);
	if (cbor != NULL) {
		CHECK_CONDITION(cbor->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);
		cbor2 = cn_cbor_data_create(cbor->v.bytes, (int) cbor->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(cbor2 != NULL, cbor_error);
		if (!COSE_Signer_map_put_int(hSigner, COSE_Header_KID, cbor2, COSE_UNPROTECT_ONLY, CBOR_CONTEXT_PARAM_COMMA perr)) goto errorReturn;
		cbor2 = NULL;
	}

	if (!COSE_Signer_SetKey(hSigner, pkey, perr)) goto errorReturn;

	if (!COSE_Sign_AddSigner(hSign, hSigner, CBOR_CONTEXT_PARAM_COMMA perr)) goto errorReturn;

	return hSigner;

errorReturn:
	if (cbor2 != NULL) CN_CBOR_FREE((void *)cbor2);
	if (hSigner != NULL) COSE_Signer_Free(hSigner CBOR_CONTEXT_PARAM);
	return NULL;
}

bool COSE_Sign_Sign(HCOSE_SIGN h, cose_errback * perr)
{
	COSE_SignMessage * pMessage = (COSE_SignMessage *)h;
	COSE_SignerInfo * pSigner;
	const cn_cbor * pcborBody;
	const cn_cbor * pcborProtected;

	if (!IsValidSignHandle(h)) {
		CHECK_CONDITION(false, COSE_ERR_INVALID_HANDLE);
	errorReturn:
		return false;
	}

	pcborBody = _COSE_arrayget_int(&pMessage->m_message, INDEX_BODY);
	CHECK_CONDITION((pcborBody != NULL) && (pcborBody->type == CN_CBOR_BYTES), COSE_ERR_INVALID_PARAMETER);

	pcborProtected = _COSE_encode_protected(&pMessage->m_message, CBOR_CONTEXT_PARAM_COMMA perr);
	if (pcborProtected == NULL) goto errorReturn;

	for (pSigner = pMessage->m_signerFirst; pSigner != NULL; pSigner = pSigner->m_signerNext) {
		if (!_COSE_Signer_sign(pSigner, pcborBody, pcborProtected, perr)) goto errorReturn;
	}

	return true;
}

bool COSE_Sign_validate(HCOSE_SIGN hSign, HCOSE_SIGNER hSigner, cose_errback * perr)
{
	bool f;
	COSE_SignMessage * pSign;
	COSE_SignerInfo * pSigner;
	const cn_cbor * cnContent;
	const cn_cbor * cnProtected;

	CHECK_CONDITION(IsValidSignHandle(hSign), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);

	pSign = (COSE_SignMessage *)hSign;
	pSigner = (COSE_SignerInfo *)hSigner;

	cnContent = _COSE_arrayget_int(&pSign->m_message, INDEX_BODY);
	CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	cnProtected = _COSE_arrayget_int(&pSign->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

	f = _COSE_Signer_validate(pSign, pSigner, cnContent, cnProtected, perr);

	return f;

errorReturn:
	return false;
}


bool COSE_Sign_AddSigner(HCOSE_SIGN hSign, HCOSE_SIGNER hSigner, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_SignerInfo * pSigner;
	COSE_SignMessage * pSign;
	cn_cbor * pSigners = NULL;
	cn_cbor * pSignersT = NULL;
	cn_cbor_errback cbor_error;

	CHECK_CONDITION(IsValidSignHandle(hSign), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(IsValidSignerHandle(hSigner), COSE_ERR_INVALID_HANDLE);

	pSign = (COSE_SignMessage *)hSign;
	pSigner = (COSE_SignerInfo *)hSigner;

	pSigner->m_signerNext = pSign->m_signerFirst;
	pSign->m_signerFirst = pSigner;

	pSigners = _COSE_arrayget_int(&pSign->m_message, INDEX_SIGNERS);
	if (pSigners == NULL) {
		pSignersT = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
		CHECK_CONDITION_CBOR(pSignersT != NULL, cbor_error);

		CHECK_CONDITION_CBOR(_COSE_array_replace(&pSign->m_message, pSignersT, INDEX_SIGNERS, CBOR_CONTEXT_PARAM_COMMA &cbor_error), cbor_error);
		pSigners = pSignersT;
		pSignersT = NULL;
	}

	CHECK_CONDITION_CBOR(cn_cbor_array_append(pSigners, pSigner->m_message.m_cbor, &cbor_error), cbor_error);
	pSigner->m_message.m_refCount++;

	return true;

errorReturn:
	if (pSignersT == NULL) CN_CBOR_FREE(pSignersT);
	return false;
}

cn_cbor * COSE_Sign_map_get_int(HCOSE_SIGN h, int key, int flags, cose_errback * perror)
{
	if (!IsValidSignHandle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_HANDLE;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_SignMessage *)h)->m_message, key, flags, perror);
}

bool COSE_Sign_map_put_int(HCOSE_SIGN h, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * perror)
{
	if (!IsValidSignHandle(h)){
		if (perror != NULL) perror->err = COSE_ERR_INVALID_HANDLE;
		return false;
	}

	return _COSE_map_put(&((COSE_SignMessage *)h)->m_message, key, value, flags, CBOR_CONTEXT_PARAM_COMMA perror);
}

HCOSE_SIGNER COSE_Sign_GetSigner(HCOSE_SIGN cose, int iSigner, cose_errback * perr)
{
	int i;
	COSE_SignerInfo * p;

	if (!IsValidSignHandle(cose)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_HANDLE;
		return NULL;
	}

	p = ((COSE_SignMessage *)cose)->m_signerFirst;
	for (i = 0; i < iSigner; i++) {
		if (p == NULL) {
			if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
			return NULL;
		}
		p = p->m_signerNext;
	}
	p->m_message.m_refCount++;

	return (HCOSE_SIGNER)p;
}
#endif

