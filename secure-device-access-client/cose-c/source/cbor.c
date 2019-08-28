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
#ifdef USE_CN_CBOR
#include "cn-cbor.h"
#include <stdlib.h>
#include <string.h>

#define INIT_CB(v) \
  if (errp) {errp->err = CN_CBOR_NO_ERROR;} \
  (v) = CN_CALLOC_CONTEXT(); \
  if (!(v)) { if (errp) {errp->err = CN_CBOR_ERR_OUT_OF_MEMORY;} return false; }

#ifdef USE_CBOR_CONTEXT

#define CN_CALLOC(ctx) ((ctx) && (ctx)->calloc_func) ? \
    (ctx)->calloc_func(1, sizeof(cn_cbor), (ctx)->context) : \
    calloc(1, sizeof(cn_cbor));

#define CN_CALLOC_CONTEXT() CN_CALLOC(cbor_context)

#else
#define CN_CALLOC(ctx) calloc(1, sizeof(cn_cbor));
#define CN_CALLOC_CONTEXT() CN_CALLOC(cbor_context)
#endif


/***
* Replace the i-th element in the array.
* Extend the array if necessary so it has enough elements.
*
* @param[in]    cn_cbor *		Array to use
* @param[in]	const cn_cbor *	New item to be placed in the array
* @param[in]	int				Zero based index to be used
* @param[in]	context	*		Context based allocation structure
* @param[in,out] cn_cbor_errback * CBOR error return on failure
* returns	    bool			Did we succeed?
*/

bool cn_cbor_array_replace(cn_cbor * cb_array, cn_cbor * cb_value, int index, CBOR_CONTEXT_COMMA cn_cbor_errback *errp)
{
	int i;
	cn_cbor * cb_temp;
	cn_cbor * cb_temp2;

	if (!cb_array || !cb_value || cb_array->type != CN_CBOR_ARRAY) {
		if (errp != NULL) errp->err = CN_CBOR_ERR_INVALID_PARAMETER;
		return false;
	}

	if (index == 0) {
		if (cb_array->length > 0) {
			cb_temp = cb_array->first_child;

			cb_value->parent = cb_array;
			cb_value->next = cb_temp->next;
			if (cb_array->last_child == cb_temp) {
				cb_array->last_child = cb_value;
			}
			cb_array->first_child = cb_value;
			cb_temp->parent = NULL;
			cb_temp->next = NULL;
			cn_cbor_free(cb_temp CBOR_CONTEXT_PARAM);
			return true;
		}
		return cn_cbor_array_append(cb_array, cb_value, errp);
	}

	if (cb_array->first_child == NULL) {
		INIT_CB(cb_temp2);
		cb_array->first_child = cb_array->last_child = cb_temp2;
		cb_temp2->parent = cb_array;
		cb_array->length = 1;
		cb_temp2->type = CN_CBOR_INVALID;
	}

	cb_temp = cb_array->first_child;
	for (i = 1; i < index; i++) {
		if (cb_temp->next == NULL) {
			INIT_CB(cb_temp2);
			cb_temp2->type = CN_CBOR_INVALID;
			cb_temp->next = cb_temp2;
			cb_temp2->parent = cb_array;
			cb_array->last_child = cb_temp2;
			cb_array->length += 1;
		}

		cb_temp = cb_temp->next;
	}

	if (cb_temp->next == NULL) {
		cb_temp->next = cb_value;
		cb_value->parent = cb_array;
		cb_array->last_child = cb_value;
		cb_array->length += 1;
		return true;
	}

	cb_temp2 = cb_temp->next;
	cb_value->next = cb_temp2->next;
	cb_temp->next = cb_value;
	cb_value->parent = cb_array;
	if (cb_array->last_child == cb_temp2) {
		cb_array->last_child = cb_value;
	}

	cb_temp2->next = NULL;
	cb_temp2->parent = NULL;
	cn_cbor_free(cb_temp2 CBOR_CONTEXT_PARAM);

	return true;
}

cn_cbor * cn_cbor_clone(const cn_cbor * pIn, CBOR_CONTEXT_COMMA cn_cbor_errback * pcn_cbor_error)
{
	cn_cbor * pOut = NULL;
	char * sz;
	unsigned char * pb;

	switch (pIn->type) {
	case CN_CBOR_TEXT:
        // Use regular calloc for string allocation. 
        // FIXME: this could cause a memory leak if pOut does not know that he is the owner of the string and free it.
		sz = calloc(pIn->length + 1, 1);
		if (sz == NULL) return NULL;
		memcpy(sz, pIn->v.str, pIn->length);
		sz[pIn->length] = 0;
		pOut = cn_cbor_string_create(sz CBOR_CONTEXT_PARAM, pcn_cbor_error);
		break;

	case CN_CBOR_UINT:
		pOut = cn_cbor_int_create(pIn->v.sint CBOR_CONTEXT_PARAM, pcn_cbor_error);
		break;

	case CN_CBOR_BYTES:
        // Use regular calloc for string allocation. 
        // FIXME: this could cause a memory leak if pOut does not know that he is the owner of the string and free it.
		pb = calloc((int) pIn->length, 1);
		if (pb == NULL) return NULL;
		memcpy(pb, pIn->v.bytes, pIn->length);
		pOut = cn_cbor_data_create(pb, (int) pIn->length CBOR_CONTEXT_PARAM, pcn_cbor_error);
		break;

	default:
		break;
	}

	return pOut;
}

cn_cbor * cn_cbor_tag_create(int tag, cn_cbor * child, CBOR_CONTEXT_COMMA cn_cbor_errback * perr)
{
	cn_cbor * pcnTag = CN_CALLOC(cbor_context);
	if (pcnTag == NULL) {
		if (perr != NULL) perr->err = CN_CBOR_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	pcnTag->type = CN_CBOR_TAG;
	pcnTag->v.sint = tag;
	pcnTag->first_child = child;
	child->parent = pcnTag;

	return pcnTag;
}

cn_cbor * cn_cbor_bool_create(int boolValue, CBOR_CONTEXT_COMMA cn_cbor_errback * errp)
{
	cn_cbor * pcn = CN_CALLOC(cbor_context);
	if (pcn == NULL) {
		if (errp != NULL) errp->err = CN_CBOR_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	pcn->type = CN_CBOR_FALSE + (boolValue != 0);
	return pcn;
}

cn_cbor * cn_cbor_null_create(CBOR_CONTEXT_COMMA cn_cbor_errback * errp)
{
	cn_cbor * pcn = CN_CALLOC(cbor_context);
	if (pcn == NULL) {
		if (errp != NULL) errp->err = CN_CBOR_ERR_OUT_OF_MEMORY;
		return NULL;
	}
	pcn->type = CN_CBOR_NULL;
	return pcn;
}

unsigned char RgbDontUse4[5 * 1024];

size_t cn_cbor_encode_size(cn_cbor * object)
{
    cn_cbor_errback errp;
    size_t encodedSize = cn_cbor_encoder_write(object, RgbDontUse4, sizeof(RgbDontUse4), &errp);
    
    if (errp.err != CN_CBOR_NO_ERROR) {
        return 0;  // failure
    }

    return encodedSize; // success
}
#endif
