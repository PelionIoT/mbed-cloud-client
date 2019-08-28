// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//  
//     http://www.apache.org/licenses/LICENSE-2.0
//  
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef __FCC_BUNDLE_FIELDS_H__
#define __FCC_BUNDLE_FIELDS_H__


#ifdef __cplusplus
extern "C" {
#endif

/**
* @file fcc_bundle_handler.h
*  \brief Defines for the bundles sent between the FCU and FCC 
* This layer handles a device configuration bundle created by factory configurator utility (FCU).
*/


/**
* Names of key parameters
*/
#define FCC_BUNDLE_DATA_PARAMETER_NAME                  "Name"
#define FCC_BUNDLE_DATA_PARAMETER_TYPE                  "Type"
#define FCC_BUNDLE_DATA_PARAMETER_FORMAT                "Format"
#define FCC_BUNDLE_DATA_PARAMETER_DATA                  "Data"
#define FCC_BUNDLE_DATA_PARAMETER_ACL                   "ACL"
#define FCC_BUNDLE_DATA_PARAMETER_ARRAY                 "DataArray"
#define FCC_BUNDLE_DATA_PARAMETER_PRIVATE_KEY_NAME      "PrKN"

/**
* Names of key types
*/
#define FCC_ECC_PRIVATE_KEY_TYPE_NAME  "ECCPrivate"
#define FCC_ECC_PUBLIC_KEY_TYPE_NAME   "ECCPublic"
#define FCC_RSA_PRIVATE_KEY_TYPE_NAME  "RSAPrivate"
#define FCC_RSA_PUBLIC_KEY_TYPE_NAME   "RSAPublic"
#define FCC_SYMMETRIC_KEY_TYPE_NAME    "Symmetric"

/**
* Names of data formats
*/
#define FCC_BUNDLE_DER_DATA_FORMAT_NAME  "der"
#define FCC_BUNDLE_PEM_DATA_FORMAT_NAME   "pem"


/****************************************/
/* Inbound Message Main CBOR Map Groups */
/****************************************/

/**
* Name of keys group.
*/
#define FCC_KEY_GROUP_NAME                   "Keys"
/**
* Name of certificates group
*/
#define FCC_CERTIFICATE_GROUP_NAME           "Certificates"
/**
* Name of configuration parameters group.
*/
#define FCC_CONFIG_PARAM_GROUP_NAME           "ConfigParams"
/**
* Name of certificate chain group.
*/
#define FCC_CERTIFICATE_CHAIN_GROUP_NAME       "CertificateChains"
/**
* Name of scheme version group.
*/
#define FCC_BUNDLE_SCHEME_GROUP_NAME          "SchemeVersion"
/**
* Name of keep alive session group.
*/
#define FCC_KEEP_ALIVE_SESSION_GROUP_NAME          "KpAlvSess"
/**
* Name of Entropy group.
*/
#define FCC_ENTROPY_NAME       "Entropy"
/**
* Name of RoT group.
*/
#define FCC_ROT_NAME          "ROT"
/**
* Name of device verify readiness group.
*/
#define FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME          "Verify"
/**
* Name of device verify readiness group.
*/
#define FCC_FACTORY_DISABLE_GROUP_NAME          "Disable"

/**
* Name of FCU session ID group (optional).
*/
#define FCC_FCU_SESSION_ID_GROUP_TYPE_NAME          "SID"

/** Name of CSR requests group.
*/
#define FCC_CSR_REQUESTS_GROUP_NAME            "CsrReqs"

/************************************************/
/* Inbound Message: fields within CsrReqs Group */
/************************************************/

/**
* Name of private key name field, within CSR Requests group
*/
#define FCC_CSRREQ_INBOUND_PRIVATE_KEY_NAME "PrKN"

/**
* Name of public key name field, within CSR Requests group
*/
#define FCC_CSRREQ_INBOUND_PUBLIC_KEY_NAME "PbKN"

/**
* Name of Extensions field, within CSR Requests group
*/
#define FCC_CSRREQ_INBOUND_EXTENSIONS_NAME "Ext"

/**
* Name of Subject field, within CSR Requests group
*/
#define FCC_CSRREQ_INBOUND_SUBJECT_NAME "Subj"

/**
* Name of Message digest field, within CSR Requests group
*/
#define FCC_CSRREQ_INBOUND_MESSAGEDIGEST_NAME "MD"


/**********************************************************************/
/* Inbound Message: fields within Extensions map within CsrReqs Group */
/**********************************************************************/

/**
* Name of Trust field within Extensions
*/
#define FCC_CSRREQ_INBOUND_EXTENSION_TRUSTLEVEL_NAME "Trust"

/**
* Name of Key Usage field within Extensions
*/
#define FCC_CSRREQ_INBOUND_EXTENSION_KEYUSAGE_NAME "KU"

/**
* Name of Extended Key Usage field within Extensions
*/
#define FCC_CSRREQ_INBOUND_EXTENSION_EXTENDEDKEYUSAGE_NAME "EKU"

/****************************************/
/* Outbound Message Main CBOR Map Groups */
/****************************************/

/**
* Name of error info group.
*/
//Fixme : rename "infoMessage" to ErrorInfo" when Factory tool will be ready for the change
#define FCC_ERROR_INFO_GROUP_NAME              "InfoMessage"

/**
* Name of return status group.
*/
#define FCC_RETURN_STATUS_GROUP_NAME          "ReturnStatus"

/**
* Name of warning info group.
*/
#define FCC_WARNING_INFO_GROUP_NAME            "WarningInfo"

/**
* Name of CSRs group.
*/
#define FCC_CSR_OUTBOUND_GROUP_NAME                "Csrs"


/***********************************************************/
/* Outbound Message: fields the CSR maps within Csrs array */
/***********************************************************/

/**
* Name of the private key corresponding to the CSR within the CSR map.
*/
#define FCC_CSR_OUTBOUND_MAP_PRIVATE_KEY_NAME FCC_CSRREQ_INBOUND_PRIVATE_KEY_NAME

/**
* Name of the data of the CSR within the CSR map.
*/
#define FCC_CSR_OUTBOUND_MAP_DATA FCC_BUNDLE_DATA_PARAMETER_DATA


#ifdef __cplusplus
}
#endif

#endif //__FCC_BUNDLE_FIELDS_H__
