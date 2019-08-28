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

#include <stdlib.h>
#include <string.h>
#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto_cose.h"

#ifdef USE_CN_CBOR
#include "cn-cbor.h"

bool IsValidCOSEHandle(HCOSE h)
{
    COSE_Encrypt * p = (COSE_Encrypt *)h;
    if (p == NULL) return false;
    return true;
}


bool _COSE_Init(COSE_INIT_FLAGS flags, COSE* pobj, int msgType, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    cn_cbor_errback errState;

#ifdef USE_CBOR_CONTEXT
    //if (cbor_context != NULL) pobj->m_allocContext = *cbor_context;
#endif

    CHECK_CONDITION((flags & ~(COSE_INIT_FLAGS_DETACHED_CONTENT | COSE_INIT_FLAGS_NO_CBOR_TAG)) == 0, COSE_ERR_INVALID_PARAMETER);

    pobj->m_flags = flags;

    pobj->m_protectedMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
    CHECK_CONDITION_CBOR(pobj->m_protectedMap != NULL, errState);

    pobj->m_dontSendMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
    CHECK_CONDITION_CBOR(pobj->m_dontSendMap != NULL, errState);

    pobj->m_cborRoot = pobj->m_cbor = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &errState);
    CHECK_CONDITION_CBOR(pobj->m_cbor != NULL, errState);
    pobj->m_ownMsg = 1;

    pobj->m_msgType = msgType;

    pobj->m_unprotectMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &errState);
    CHECK_CONDITION_CBOR(pobj->m_unprotectMap != NULL, errState);
    CHECK_CONDITION_CBOR(_COSE_array_replace(pobj, pobj->m_unprotectMap, INDEX_UNPROTECTED, CBOR_CONTEXT_PARAM_COMMA &errState), errState);
    pobj->m_ownUnprotectedMap = false;


    if (!(flags & COSE_INIT_FLAGS_NO_CBOR_TAG)) {
        cn_cbor_errback cbor_error;
        cn_cbor * cn = cn_cbor_tag_create(msgType, pobj->m_cborRoot, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
        CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
        pobj->m_cborRoot = cn;
    }

    pobj->m_refCount = 1;

    return true;

errorReturn:
    return false;
}

bool _COSE_Init_From_Object(COSE* pobj, cn_cbor * pcbor, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    const cn_cbor * pmap = NULL;
    cn_cbor_errback errState; // = { 0 };
    cn_cbor_errback cbor_error;

#ifdef USE_CBOR_CONTEXT
    //if (cbor_context != NULL) pobj->m_allocContext = *cbor_context;
#endif
    pobj->m_cborRoot = pcbor;
    pobj->m_cbor = pcbor;

    //  Check if we have a tag
    //Skip all tags of current CBOR object, and get the last one. The last one should be Cose object tag
    while (pcbor->type == CN_CBOR_TAG) {
        pcbor = pobj->m_cbor = pcbor->first_child;
    }

    pmap = _COSE_arrayget_int(pobj, INDEX_PROTECTED);

    CHECK_CONDITION(pmap != NULL, COSE_ERR_INVALID_PARAMETER);
    if (pmap != NULL) {
        CHECK_CONDITION(pmap->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

        if (pmap->length == 0) {
            pobj->m_protectedMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA NULL);
            CHECK_CONDITION(pobj->m_protectedMap, COSE_ERR_OUT_OF_MEMORY);
        } else {
            pobj->m_protectedMap = cn_cbor_decode((const byte *)pmap->v.str, pmap->length, CBOR_CONTEXT_PARAM_COMMA &errState);
            CHECK_CONDITION(pobj->m_protectedMap != NULL, COSE_ERR_INVALID_PARAMETER);
        }
    }

    pobj->m_unprotectMap = _COSE_arrayget_int(pobj, INDEX_UNPROTECTED);
    CHECK_CONDITION((pobj->m_unprotectMap != NULL) && (pobj->m_unprotectMap->type == CN_CBOR_MAP), COSE_ERR_INVALID_PARAMETER);
    pobj->m_ownUnprotectedMap = false;

    pobj->m_dontSendMap = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
    CHECK_CONDITION_CBOR(pobj->m_dontSendMap != NULL, cbor_error);

    pobj->m_ownMsg = true;
    pobj->m_refCount = 1;

    return true;

errorReturn:
    return false;
}

bool _COSE_array_replace(COSE * pMessage, cn_cbor * cb_value, int index, CBOR_CONTEXT_COMMA cn_cbor_errback * errp)
{
    return cn_cbor_array_replace(pMessage->m_cbor, cb_value, index, CBOR_CONTEXT_PARAM_COMMA errp);
}

cn_cbor * _COSE_arrayget_int(COSE * pMessage, int index)
{
    return cn_cbor_index(pMessage->m_cbor, index);
}

static HCOSE _COSE_Create_HCOSE(const cn_cbor *coseObj, int * ptype, COSE_object_type struct_type, bool isOwner, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    cn_cbor * cbor = NULL;
    cn_cbor * cborRoot = NULL;
    cn_cbor_errback cbor_err;
    HCOSE h;

    cbor = cborRoot = (cn_cbor*)coseObj;
    CHECK_CONDITION_CBOR(cbor != NULL, cbor_err);


    while (cbor->type == CN_CBOR_TAG) {
        struct_type = cbor->v.uint;
        cbor = cbor->first_child;
    }

    *ptype = struct_type;

    CHECK_CONDITION(cbor->type == CN_CBOR_ARRAY, COSE_ERR_INVALID_PARAMETER);

    switch (*ptype) {
    case COSE_enveloped_object:
        h = (HCOSE)_COSE_Enveloped_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
        if (h == NULL) {
            goto errorReturn;
        }
        break;

    case COSE_sign_object:
        h = (HCOSE)_COSE_Sign_Init_From_Object(cborRoot, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
        if (h == NULL) {
            goto errorReturn;
        }
        break;

    case COSE_sign0_object:
        h = (HCOSE)_COSE_Sign0_Init_From_Object(cborRoot, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
        if (h == NULL) {
            goto errorReturn;
        }

        // By default _COSE_Sign0_Init_From_Object sets pSign0->m_message.m_ownMsg to 1
        COSE_Sign0Message *pSign0 = (COSE_Sign0Message *)(h);
        if (!isOwner) {
            pSign0->m_message.m_ownMsg = 0;
        }
        break;

    case COSE_mac_object:
        h = (HCOSE)_COSE_Mac_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
        if (h == NULL) {
            goto errorReturn;
        }
        break;

    case COSE_mac0_object:
        h = (HCOSE)_COSE_Mac0_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
        if (h == NULL) {
            goto errorReturn;
        }
        break;

    case COSE_encrypt_object:
        h = (HCOSE)_COSE_Encrypt_Init_From_Object(cbor, NULL, CBOR_CONTEXT_PARAM_COMMA perr);
        if (h == NULL) {
            goto errorReturn;
        }
        break;

    default:
        FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
    }

    return h;

errorReturn:
    return NULL;

}

HCOSE COSE_Init(const cn_cbor *coseObj, int * ptype, COSE_object_type struct_type, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    return _COSE_Create_HCOSE(coseObj, ptype, struct_type, false CBOR_CONTEXT_PARAM, perr);
}

// This decodes and calls COSE_Init
HCOSE COSE_Decode(const byte * rgbData, size_t cbData, int * ptype, COSE_object_type struct_type, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    cn_cbor * cose = NULL;
    cn_cbor_errback cbor_err;
    HCOSE h;

    CHECK_CONDITION((rgbData != NULL) && (ptype != NULL), COSE_ERR_INVALID_PARAMETER);

    // FIXME: should do proper cbor and cose error conversions
    cose = cn_cbor_decode(rgbData, cbData, CBOR_CONTEXT_PARAM_COMMA &cbor_err);

    h = _COSE_Create_HCOSE(cose, ptype, struct_type, true, CBOR_CONTEXT_PARAM_COMMA perr);
    CHECK_CONDITION((h != NULL), COSE_ERR_CBOR);

    return h;

errorReturn:
    cn_cbor_free(cose CBOR_CONTEXT_PARAM);
    return NULL;
}

size_t COSE_Encode(HCOSE msg, byte * rgb, size_t ib, size_t cb)
{
    cn_cbor_errback errp;
    size_t encodedSize = 0;

    if (rgb == NULL) return cn_cbor_encode_size(((COSE *)msg)->m_cbor) + ib;
    encodedSize = cn_cbor_encoder_write(((COSE*)msg)->m_cbor, rgb, cb, &errp);

    if (errp.err != CN_CBOR_NO_ERROR) {
        return 0;  // failure
    }

    return encodedSize; // success
}


cn_cbor * COSE_get_cbor(HCOSE h)
{
    COSE * msg = (COSE *)h;
    if (!IsValidCOSEHandle(h)) return NULL;

    return msg->m_cbor;
}
cn_cbor * _COSE_map_get_int(COSE * pcose, int key, int flags, cose_errback * perror)
{
    cn_cbor * p = NULL;

    if (perror != NULL) perror->err = COSE_ERR_NONE;

    if ((pcose->m_protectedMap != NULL) && ((flags & COSE_PROTECT_ONLY) != 0)) {
        p = cn_cbor_mapget_int(pcose->m_protectedMap, key);
        if (p != NULL) return p;
    }

    if ((pcose->m_unprotectMap != NULL) && ((flags & COSE_UNPROTECT_ONLY) != 0)) {
        p = cn_cbor_mapget_int(pcose->m_unprotectMap, key);
        if (p != NULL) return p;
    }

    if ((pcose->m_dontSendMap != NULL) && ((flags & COSE_DONT_SEND) != 0)) {
        p = cn_cbor_mapget_int(pcose->m_dontSendMap, key);
    }

    if ((p == NULL) && (perror != NULL)) perror->err = COSE_ERR_INVALID_PARAMETER;

    return p;
}



cn_cbor * _COSE_map_get_str(COSE * pcose, const char * key, int flags, cose_errback * perror)
{
    cn_cbor * p = NULL;

    if (perror != NULL) perror->err = COSE_ERR_NONE;

    if ((pcose->m_protectedMap != NULL) && ((flags & COSE_PROTECT_ONLY) != 0)) {
        p = cn_cbor_mapget_string(pcose->m_protectedMap, key);
        if (p != NULL) return p;
    }

    if ((pcose->m_unprotectMap != NULL) && ((flags & COSE_UNPROTECT_ONLY) != 0)) {
        p = cn_cbor_mapget_string(pcose->m_unprotectMap, key);
    }

    if ((pcose->m_dontSendMap != NULL) && ((flags & COSE_DONT_SEND) != 0)) {
        p = cn_cbor_mapget_string(pcose->m_dontSendMap, key);
    }

    return p;
}

bool _COSE_map_put(COSE * pCose, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    cn_cbor_errback error;
    bool f = false;
    CHECK_CONDITION(value != NULL, COSE_ERR_INVALID_PARAMETER);

    CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_protectedMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);
    CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_unprotectMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);
    CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_dontSendMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);

    switch (flags) {
    case COSE_PROTECT_ONLY:
        f = cn_cbor_mapput_int(pCose->m_protectedMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
        break;

    case COSE_UNPROTECT_ONLY:
        f = cn_cbor_mapput_int(pCose->m_unprotectMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
        break;

    case COSE_DONT_SEND:
        f = cn_cbor_mapput_int(pCose->m_dontSendMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
        break;

    default:
        FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
        break;
    }

    CHECK_CONDITION(f, _MapFromCBOR(error));

errorReturn:
    return f;
}
cn_cbor * _COSE_encode_protected(COSE * pMessage, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    cn_cbor * pProtected;
    int cbProtected;
    byte * pbProtected = NULL;
    cn_cbor_errback cbor_error;
    int bytesWritten = 0;


    pProtected = cn_cbor_index(pMessage->m_cbor, INDEX_PROTECTED);
    if ((pProtected != NULL) && (pProtected->type != CN_CBOR_INVALID)) {
    errorReturn:
        if (pbProtected != NULL) COSE_FREE(pbProtected);
        return pProtected;
    }

    if (pMessage->m_protectedMap->length > 0) {
        cbProtected = cn_cbor_encode_size(pMessage->m_protectedMap);
        pbProtected = (byte *)COSE_CALLOC(cbProtected, 1, context);
        CHECK_CONDITION(pbProtected != NULL, COSE_ERR_OUT_OF_MEMORY);

        bytesWritten = cn_cbor_encoder_write(pMessage->m_protectedMap, pbProtected, cbProtected, &cbor_error);
        CHECK_CONDITION(bytesWritten == cbProtected, COSE_ERR_CBOR);
    }
    else {
        cbProtected = 0;
    }

    pProtected = cn_cbor_data_create(pbProtected, cbProtected, CBOR_CONTEXT_PARAM_COMMA NULL);
    CHECK_CONDITION(pProtected != NULL, COSE_ERR_OUT_OF_MEMORY);
    pbProtected = NULL;

    CHECK_CONDITION(_COSE_array_replace(pMessage, pProtected, INDEX_PROTECTED, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_CBOR);

    return pProtected;
}

#ifdef USE_COUNTER_SIGNATURES
bool _COSE_CounterSign_add(COSE * pMessage, HCOSE_COUNTERSIGN hSigner, cose_errback * perr)
{
    COSE_CounterSign * pSigner = (COSE_CounterSign *)hSigner;

    CHECK_CONDITION(IsValidCounterSignHandle(hSigner), COSE_ERR_INVALID_HANDLE);
    CHECK_CONDITION(pSigner->m_signer.m_signerNext == NULL, COSE_ERR_INVALID_PARAMETER);

    pSigner = pMessage->m_counterSigners;
    pMessage->m_counterSigners = pSigner;
    return true;

errorReturn:
    return false;
}

HCOSE_COUNTERSIGN _COSE_CounterSign_get(COSE * pMessage, int iSigner, cose_errback * perr)
{
    COSE_CounterSign * pSigner = pMessage->m_counterSigners;
    int i;

    for (i = 0; i < iSigner; i++, pSigner = pSigner->m_next) {
        CHECK_CONDITION(pSigner != NULL, COSE_ERR_INVALID_PARAMETER);
    }

    return (HCOSE_COUNTERSIGN)pSigner;

errorReturn:
    return false;
}

bool _COSE_CountSign_create(COSE * pMessage, cn_cbor * pcnBody, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    cn_cbor * pArray = NULL;
    cn_cbor_errback cbor_err;
    COSE_CounterSign * pSigner = NULL;
    cn_cbor * pcnProtected = NULL;
    cn_cbor * pcn = NULL;
    cn_cbor * pcn2 = NULL;

    if (pMessage->m_counterSigners == NULL) return true;

    //  One or more than one?
    if (pMessage->m_counterSigners->m_signer.m_signerNext != NULL) {
        pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_err);
        CHECK_CONDITION_CBOR(pArray != NULL, cbor_err);
    }

    pcnProtected = _COSE_arrayget_int(pMessage, INDEX_PROTECTED);
    CHECK_CONDITION(pcnProtected != NULL, COSE_ERR_INTERNAL);

    for (pSigner = pMessage->m_counterSigners; pSigner != NULL; pSigner = pSigner->m_next) {
        CHECK_CONDITION(pSigner->m_signer.m_signerNext == NULL, COSE_ERR_INTERNAL);

        pcn = cn_cbor_data_create(pcnProtected->v.bytes, pcnProtected->v.count, CBOR_CONTEXT_PARAM_COMMA &cbor_err);
        CHECK_CONDITION_CBOR(pcnProtected != NULL, cbor_err);

        pcn2 = cn_cbor_clone(pcnBody, CBOR_CONTEXT_PARAM_COMMA &cbor_err);
        CHECK_CONDITION_CBOR(pcnBody != NULL, cbor_err);

        if (!_COSE_Signer_sign(&pSigner->m_signer, pcnBody, pcn2, perr)) goto errorReturn;
        pcn = NULL;
        pcn2 = NULL;

        if (pArray != NULL) {
            bool f = cn_cbor_array_append(pArray, pSigner->m_signer.m_message.m_cborRoot, &cbor_err);
            CHECK_CONDITION_CBOR(f, cbor_err);
        }
        else {
            pArray = pSigner->m_signer.m_message.m_cborRoot;
        }
    }

    if (!_COSE_map_put(pMessage, COSE_Header_CounterSign, pArray, COSE_UNPROTECT_ONLY, CBOR_CONTEXT_PARAM_COMMA perr)) goto errorReturn;

    return true;

errorReturn:
    if (pArray != NULL) CN_CBOR_FREE(pArray);
    if ((pcn != NULL) && (pcn->parent != NULL)) CN_CBOR_FREE(pcn);
    if ((pcn2 != NULL) && (pcn2->parent != NULL)) CN_CBOR_FREE(pcn2);
    return false;
}

#endif

#else

// This function is currently not used by core or by tests, in case we will need to use this function we need to change all cn - cbor functionality to tincbor.
bool _COSE_map_put_tiny(COSE * pCose, int key, /*cn_cbor * value,*/ int flags,  cose_errback * perr)
{
    //cn_cbor_errback error;
    bool f = false;
    //CHECK_CONDITION(value != NULL, COSE_ERR_INVALID_PARAMETER);

#if 0
    CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_protectedMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);
    CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_unprotectMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);
    CHECK_CONDITION(cn_cbor_mapget_int(pCose->m_dontSendMap, key) == NULL, COSE_ERR_INVALID_PARAMETER);

    switch (flags) {
    case COSE_PROTECT_ONLY:
        f = cn_cbor_mapput_int(pCose->m_protectedMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
        break;

    case COSE_UNPROTECT_ONLY:
        f = cn_cbor_mapput_int(pCose->m_unprotectMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
        break;

    case COSE_DONT_SEND:
        f = cn_cbor_mapput_int(pCose->m_dontSendMap, key, value, CBOR_CONTEXT_PARAM_COMMA &error);
        break;

    default:
        FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
        break;
    }
errorReturn:
#endif


    return f;
}


static bool get_map_value_from_buffer(uint8_t *map_buffer, size_t map_buffer_size, int key, uint8_t **map_value_buffer, size_t *map_value_buffer_size) {

    CborValue map;
    CborParser parser;
    CborValue map_value;
    CborError  cbor_err = CborNoError;

    //Parse coseBuffer
    cbor_err = cbor_parser_init(map_buffer, map_buffer_size, CborIteratorFlag_NegativeInteger, &parser, &map);
    if (cbor_err != CborNoError) {
        return false;
    }

    cbor_err = cbor_get_map_element_by_int_key(&map, key, &map_value);
    if (cbor_err != CborNoError) {
        return false;
    }

    cbor_err = cbor_get_cbor_payload_buffer_in_container(&map_value, map_value_buffer, map_value_buffer_size);
    if (cbor_err != CborNoError) {
        return false;
    }

    return true;

}
bool _COSE_Init_From_Object_tiny(COSE* pobj, const uint8_t *coseBuffer, size_t coseBufferSize, cose_errback * perr)
{

    size_t map_buffer_size = 0;
    CborValue value;
    CborValue value_container;
    CborValue array_element;
    CborParser parser;
    CborError cbor_error = CborNoError;

    //Set message cbor and root cbor
    pobj->message_root_cbor.buffer = coseBuffer;
    pobj->message_root_cbor.buffer_size = coseBufferSize;
    pobj->message_cbor.buffer = coseBuffer;
    pobj->message_cbor.buffer_size = coseBufferSize;

    //Parse coseBuffer
    cbor_error = cbor_parser_init(coseBuffer, coseBufferSize, CborIteratorFlag_NegativeInteger, &parser, &value);
    CHECK_CONDITION_CBOR(cbor_error == CborNoError, cbor_error);

    if (value.type == CborTagType) {
        //Init container of parsed value
        cbor_error = cbor_init_container(&value, &value_container);
        CHECK_CONDITION_CBOR(cbor_error == CborNoError, cbor_error);
    }
    else {
        value_container = value;
    }

    //Iterate the container until type is tag
    while (value_container.type == CborTagType) {
        //Get next value object
        cbor_error = cbor_get_next_container_element(&value_container);
        CHECK_CONDITION(cbor_error == CborNoError, COSE_ERR_CBOR);
    }
    //Update message cbor
    cbor_error = cbor_get_cbor_payload_buffer_in_container(&value_container, (uint8_t**)&pobj->message_cbor.buffer, &pobj->message_cbor.buffer_size);
    CHECK_CONDITION(cbor_error == CborNoError, COSE_ERR_CBOR);


    //Try to get protected map from cose buffer
    cbor_error = cbor_get_array_element(&value_container, INDEX_PROTECTED, &array_element);
    CHECK_CONDITION(cbor_error == CborNoError, COSE_ERR_INVALID_PARAMETER);
    CHECK_CONDITION(cbor_value_is_byte_string(&array_element) == true, COSE_ERR_INVALID_PARAMETER);

    cbor_error = cbor_value_get_string_length(&array_element, &map_buffer_size);
    CHECK_CONDITION(cbor_error == CborNoError, COSE_ERR_INVALID_PARAMETER);

    if (map_buffer_size == 0) {
        pobj->message_protected_map_cbor.buffer = NULL;
        pobj->message_protected_map_cbor.buffer_size = 0;
        pobj->message_protected_map_cbor.is_map_initialized = true;
    }
    else {
        //Update message protected map
        cbor_error = cbor_value_get_byte_string_chunk(&array_element, (const uint8_t **)&(pobj->message_protected_map_cbor.buffer), &pobj->message_protected_map_cbor.buffer_size, NULL);
        CHECK_CONDITION(cbor_error == CborNoError, COSE_ERR_INVALID_PARAMETER);
        pobj->message_protected_map_cbor.is_map_initialized = true;
    }

    //Try to get unprotected map from cose buffer
    cbor_error = cbor_get_array_element(&value_container, INDEX_UNPROTECTED, &array_element);
    CHECK_CONDITION(cbor_error == CborNoError, COSE_ERR_INVALID_PARAMETER);
    CHECK_CONDITION(cbor_value_is_map(&array_element) == true, COSE_ERR_INVALID_PARAMETER);

    cbor_error = cbor_get_cbor_payload_buffer_in_container(&array_element, (uint8_t**)&pobj->message_unprotected_map_cbor.buffer, &pobj->message_unprotected_map_cbor.buffer_size);
    CHECK_CONDITION(cbor_error == CborNoError, COSE_ERR_INVALID_PARAMETER);
    pobj->message_unprotected_map_cbor.is_map_initialized = true;

    pobj->m_ownUnprotectedMap = false;

    pobj->message_dont_send_map_cbor.buffer = NULL;
    pobj->message_dont_send_map_cbor.buffer_size = 0;
    pobj->message_dont_send_map_cbor.is_map_initialized = true;

    pobj->m_ownMsg = true;
    pobj->m_refCount = 1;

    return true;

errorReturn:
    return false;
}

bool  _COSE_map_get_int_tiny(COSE * pcose, int key, int flags, uint8_t **out_map_value, size_t *out_map_value_size, cose_errback * perror)
{
    bool status = false;

    if (perror != NULL) perror->err = COSE_ERR_NONE;

    if ((pcose->message_protected_map_cbor.buffer != NULL && pcose->message_protected_map_cbor.is_map_initialized == true) && ((flags & COSE_PROTECT_ONLY) != 0)) {

        status = get_map_value_from_buffer((uint8_t*)pcose->message_protected_map_cbor.buffer, pcose->message_protected_map_cbor.buffer_size, key, out_map_value, out_map_value_size);
        if (status == true)
            return status;
    }

    if ((pcose->message_unprotected_map_cbor.buffer != NULL && pcose->message_unprotected_map_cbor.is_map_initialized == true) && ((flags & COSE_UNPROTECT_ONLY) != 0)) {
        status = get_map_value_from_buffer((uint8_t*)pcose->message_unprotected_map_cbor.buffer, pcose->message_unprotected_map_cbor.buffer_size, key, out_map_value, out_map_value_size);
        if (status == true)
            return status;
    }

    if ((pcose->message_dont_send_map_cbor.buffer != NULL && pcose->message_dont_send_map_cbor.is_map_initialized == true) && ((flags & COSE_DONT_SEND) != 0)) {
        status = get_map_value_from_buffer((uint8_t*)pcose->message_dont_send_map_cbor.buffer, pcose->message_dont_send_map_cbor.buffer_size, key, out_map_value, out_map_value_size);
        if (status == true)
            return status;
    }

    return false;
}

/**
* Create an HCOSE. This function does all the COSE initializations.
* The function allocates memory dynamically, and must be freed by COSE_<type>_Free() function. Depending on struct_type.
*
* @param[in]  coseObj       Pointer to a decoded CBOR object containing the COSE.
* @param[out] pType         Pointer to the location where the COSE_object_type will be output to the caller.
*                           Should be the same as the provided struct_type.
* @param[in]  struct_type   Enum representing the type of COSE.
* @param[in]  isOwner       If this is true - COSE_<type>_Free() will free coseObj. If false - coseObj must be freed by user who allocated coseObj.
* @param[in]  CBOR_CONTEXT  CBOR allocation context (only if USE_CBOR_CONTEXT is defined).
* @param[out] cose_errback  Pointer to COSE error object. Can be NULL.
*
* @return
*       HCOSE handle which points to the specific COSE object based on the struct_type.
*       NULL if error has occurred.
*/

static HCOSE _COSE_Create_HCOSE_tiny(const uint8_t *coseBuffer, size_t coseBufferSize, int *ptype, COSE_object_type struct_type, bool isOwner, cose_errback * perr)
{
    CborValue value;
    CborValue value_container;
    CborParser parser;
    CborError cbor_err = CborNoError;
    CborTag tag_value;

    HCOSE h;
    CHECK_CONDITION((coseBuffer != NULL || coseBufferSize == 0), COSE_ERR_INVALID_PARAMETER);

    //Parse coseBuffer
    cbor_err = cbor_parser_init(coseBuffer, coseBufferSize, CborIteratorFlag_NegativeInteger, &parser, &value);
    CHECK_CONDITION_CBOR(cbor_err == CborNoError, cbor_err);


    if (value.type == CborTagType) {
        //Init container of parsed value
        cbor_err = cbor_init_container(&value, &value_container);
        CHECK_CONDITION_CBOR(cbor_err == CborNoError, cbor_err);
    }
    else {
        *ptype = struct_type;
        value_container = value;
    }

    //Iterate the container until type is tag
    while (value_container.type == CborTagType) {
        //Get value of the tag
        cbor_err = cbor_value_get_tag(&value_container, &tag_value);
        CHECK_CONDITION_CBOR(cbor_err == CborNoError, cbor_err);

        //Set tag value to ptype
        *ptype = tag_value;

        //Get next value object
        cbor_err = cbor_get_next_container_element(&value_container);
        CHECK_CONDITION_CBOR(cbor_err == CborNoError, cbor_err);
    }


    CHECK_CONDITION(value_container.type == CborArrayType, COSE_ERR_INVALID_PARAMETER);

    //Init HCOSE
    switch ((COSE_object_type)*ptype) {

    case COSE_sign0_object:
        h = (HCOSE)_COSE_Sign0_Init_From_Object_tiny(coseBuffer, coseBufferSize, NULL, perr);
        if (h == NULL) {
            goto errorReturn;
        }

        // By default _COSE_Sign0_Init_From_Object sets pSign0->m_message.m_ownMsg to 1
        COSE_Sign0Message *pSign0 = (COSE_Sign0Message *)(h);
        if (!isOwner) {
            pSign0->m_message.m_ownMsg = 0;
        }
        break;

    default:
        FAIL_CONDITION(COSE_ERR_INVALID_PARAMETER);
    }

    return h;

errorReturn:
    return NULL;
}

HCOSE COSE_Init_tiny(const uint8_t *coseBuffer, size_t coseBufferSize, int * ptype, COSE_object_type struct_type, cose_errback * perr)
{
    return _COSE_Create_HCOSE_tiny(coseBuffer, coseBufferSize, ptype, struct_type, false, perr);
}

HCOSE COSE_Decode_tiny(const byte * rgbData, size_t cbData, int * ptype, COSE_object_type struct_type, cose_errback * perr)
{

    HCOSE h;

    CHECK_CONDITION((rgbData != NULL) && (ptype != NULL), COSE_ERR_INVALID_PARAMETER);

    h = _COSE_Create_HCOSE_tiny(rgbData, cbData, ptype, struct_type, true, perr);
    CHECK_CONDITION((h != NULL), COSE_ERR_CBOR);

    return h;

errorReturn:
    return NULL;
}

#endif

#ifdef USE_CN_CBOR
//pr
void _COSE_Release(COSE * pobj CBOR_CONTEXT)
{
#ifdef USE_CBOR_CONTEXT
    //cbor_context *cbor_context = &pobj->m_allocContext;
#endif


    if (pobj->m_protectedMap != NULL) CN_CBOR_FREE(pobj->m_protectedMap);
    if (pobj->m_ownUnprotectedMap && (pobj->m_unprotectMap != NULL)) CN_CBOR_FREE(pobj->m_unprotectMap);
    if (pobj->m_dontSendMap != NULL) CN_CBOR_FREE(pobj->m_dontSendMap);
    if (pobj->m_ownMsg && (pobj->m_cborRoot != NULL) && (pobj->m_cborRoot->parent == NULL)) CN_CBOR_FREE(pobj->m_cborRoot);

}
#endif

//common
bool _COSE_SetExternal(COSE * pcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr)
{
    (void)perr;
    pcose->m_pbExternal = pbExternalData;
    pcose->m_cbExternal = cbExternalData;

    return true;
}

void _COSE_InsertInList(COSE ** root, COSE * newMsg)
{
    if (*root == NULL) {
        *root = newMsg;
        return;
    }

    newMsg->m_handleList = *root;
    *root = newMsg;
    return;
}

bool _COSE_IsInList(COSE * root, COSE * thisMsg)
{
    COSE * walk;

    if (root == NULL) return false;
    if (thisMsg == NULL) return false;

    for (walk = root; walk != NULL; walk = walk->m_handleList) {
        if (walk == thisMsg) return true;
    }
    return false;
}

void _COSE_RemoveFromList(COSE ** root, COSE * thisMsg)
{
    COSE * walk;

    if (*root == thisMsg) {
        *root = thisMsg->m_handleList;
        thisMsg->m_handleList = NULL;
        return;
    }

    for (walk = *root; walk->m_handleList != NULL; walk = walk->m_handleList) {
        if (walk->m_handleList == thisMsg) {
            walk->m_handleList = thisMsg->m_handleList;
            thisMsg->m_handleList = NULL;
            return;
        }
    }
    return;
}

#ifdef USE_CN_CBOR
cose_error _MapFromCBOR(cn_cbor_errback err)
{
    switch (err.err) {
    case CN_CBOR_ERR_INVALID_PARAMETER:
        return COSE_ERR_INVALID_PARAMETER;

    case CN_CBOR_ERR_OUT_OF_MEMORY:
        return COSE_ERR_OUT_OF_MEMORY;

    default:
        return COSE_ERR_CBOR;
    }
}

#else

cose_error _MapFromCBOR(CborError err)
{
    switch (err) {

    case CborErrorIO:
        return COSE_ERR_INVALID_PARAMETER;

    case CborErrorOutOfMemory:
        return COSE_ERR_OUT_OF_MEMORY;

    default:
        return COSE_ERR_CBOR;
    }
}
#endif
