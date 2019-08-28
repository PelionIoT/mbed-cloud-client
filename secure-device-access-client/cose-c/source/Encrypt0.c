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

/** \file Encrypt0.c
* Contains implementation of the functions related to HCOSE_ENCRYPT handle objects.
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto_cose.h"

#ifdef USE_CN_CBOR
void _COSE_Encrypt_Release(COSE_Encrypt * p  CBOR_CONTEXT);

COSE * EncryptRoot = NULL;

/*! \private
* @brief Test if a HCOSE_ENCRYPT handle is valid
*
*  Internal function to test if an encrypt message handle is valid.
*  This will start returning invalid results and cause the code to
*  crash if handles are not released before the memory that underlies them
*  is deallocated.  This is an issue of a block allocator is used since
*  in that case it is common to allocate memory but never to de-allocate it
*  and just do that in a single big block.
*
*  @param h handle to be validated
*  @returns result of check
*/

bool IsValidEncryptHandle(HCOSE_ENCRYPT h)
{
	COSE_Encrypt * p = (COSE_Encrypt *)h;
	return _COSE_IsInList(EncryptRoot, (COSE *)p);
}


HCOSE_ENCRYPT COSE_Encrypt_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	CHECK_CONDITION(flags == COSE_INIT_FLAGS_NONE, COSE_ERR_INVALID_PARAMETER);
	COSE_Encrypt * pobj = (COSE_Encrypt *)COSE_CALLOC(1, sizeof(COSE_Encrypt), context);
	CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init(flags, &pobj->m_message, COSE_enveloped_object, CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_Encrypt_Release(pobj CBOR_CONTEXT_PARAM);
		COSE_FREE(pobj);
		return NULL;
	}

	_COSE_InsertInList(&EncryptRoot, &pobj->m_message);

	return (HCOSE_ENCRYPT) pobj;

errorReturn:
	return NULL;
}

HCOSE_ENCRYPT _COSE_Encrypt_Init_From_Object(cn_cbor * cbor, COSE_Encrypt * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_Encrypt * pobj = pIn;
	cn_cbor * pRecipients = NULL;
	cose_errback error = { 0 };
	if (perr == NULL) perr = &error;

	if (pobj == NULL) pobj = (COSE_Encrypt *)COSE_CALLOC(1, sizeof(COSE_Encrypt), context);
	if (pobj == NULL) {
		perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (pobj != NULL) {
			_COSE_Encrypt_Release(pobj CBOR_CONTEXT_PARAM);
			if (pIn == NULL)  COSE_FREE(pobj);
		}
		return NULL;
	}

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	pRecipients = _COSE_arrayget_int(&pobj->m_message, INDEX_RECIPIENTS);
	CHECK_CONDITION(pRecipients == NULL, COSE_ERR_INVALID_PARAMETER);

	_COSE_InsertInList(&EncryptRoot, &pobj->m_message);

	return(HCOSE_ENCRYPT) pobj;
}

bool COSE_Encrypt_Free(HCOSE_ENCRYPT h CBOR_CONTEXT)
{
	COSE_Encrypt * pEncrypt = (COSE_Encrypt *)h;

	if (!IsValidEncryptHandle(h)) return false;

	_COSE_Encrypt_Release(pEncrypt CBOR_CONTEXT_PARAM);

	_COSE_RemoveFromList(&EncryptRoot, &pEncrypt->m_message);
	
	COSE_FREE((COSE_Encrypt *)h);

	return true;
}

void _COSE_Encrypt_Release(COSE_Encrypt * p CBOR_CONTEXT)
{
	if (p->pbContent != NULL) COSE_FREE((void *) p->pbContent);

	_COSE_Release(&p->m_message CBOR_CONTEXT_PARAM);
}

bool COSE_Encrypt_decrypt(HCOSE_ENCRYPT h, const byte * pbKey, size_t cbKey, cose_errback * perr)
{
	COSE_Encrypt * pcose = (COSE_Encrypt *)h;
	bool f;

	if (!IsValidEncryptHandle(h)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	f = _COSE_Enveloped_decrypt(pcose, NULL, pbKey, cbKey, "Encrypt1", perr);
	return f;
}

bool COSE_Encrypt_encrypt(HCOSE_ENCRYPT h, const byte * pbKey, size_t cbKey, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	CHECK_CONDITION(IsValidEncryptHandle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(pbKey != NULL, COSE_ERR_INVALID_PARAMETER);

	return _COSE_Enveloped_encrypt((COSE_Encrypt *)h, pbKey, cbKey, "Encrypt1", CBOR_CONTEXT_PARAM_COMMA perr);

errorReturn:
	return false;
}

bool COSE_Encrypt_SetContent(HCOSE_ENCRYPT h, const byte * rgb, size_t cb, cose_errback * perror)
{
	if (!IsValidEncryptHandle(h) || (rgb == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_Encrypt_SetContent((COSE_Encrypt *)h, rgb, cb, perror);
}

bool _COSE_Encrypt_SetContent(COSE_Encrypt * cose, const byte * rgb, size_t cb, cose_errback * perror)
{
	byte * pb;
	cose->pbContent = pb = (byte *)COSE_CALLOC(cb, 1, &cose->m_message.m_allocContext);
	if (cose->pbContent == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}
	memcpy(pb, rgb, cb);
	cose->cbContent = cb;

	return true;
}

/*!
* @brief Set the application external data for authentication
*
* Enveloped data objects support the authentication of external application
* supplied data.  This function is provided to supply that data to the library.
*
* The external data is not copied, nor will be it freed when the handle is released.
*
* @param hcose  Handle for the COSE Enveloped data object
* @param pbEternalData  point to the external data
* @param cbExternalData size of the external data
* @param perr  location to return errors
* @return result of the operation.
*/

bool COSE_Encrypt_SetExternal(HCOSE_ENCRYPT hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr)
{
	if (!IsValidEncryptHandle(hcose)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_SetExternal(&((COSE_Encrypt *)hcose)->m_message, pbExternalData, cbExternalData, perr);
}

cn_cbor * COSE_Encrypt_map_get_int(HCOSE_ENCRYPT h, int key, int flags, cose_errback * perror)
{
	if (!IsValidEncryptHandle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_Encrypt *)h)->m_message, key, flags, perror);
}


bool COSE_Encrypt_map_put_int(HCOSE_ENCRYPT h, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * perror)
{
	if (!IsValidEncryptHandle(h) || (value == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_PARAMETER;
		return false;
	}

	return _COSE_map_put(&((COSE_Encrypt *)h)->m_message, key, value, flags, CBOR_CONTEXT_PARAM_COMMA perror);
}
#endif
