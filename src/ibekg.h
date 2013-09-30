/*************************************************************************
  Ibekg/nodejs_ibekg.h

  Copyright (c) 2011-2013, Igor Zboran

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*************************************************************************/

//#pragma once

#include <node.h>

#ifdef OPENSSL_FIPS_BUILD
#include <openssl/fipssyms.h>
#include <openssl/fips_rand.h>
#else
#include <openssl/rand.h> 
#include <openssl/hmac.h> 
#endif

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

#include <jansson.h>

//#include <vld.h>

#include <string.h>

#define PRODUCT_VERSION						"0.3.2"
#define API_VERSION							"0.3.2"

#ifdef _WIN32
#define REGISTRY_SUBKEY_IBEKG				"Software\\LEADict.com\\Ibekg"
#define REGISTRY_MASTERKEY					"MasterKey"
#else
#define REGISTRY_SUBKEY_IBEKG				"ibekg"
#define REGISTRY_MASTERKEY					"masterkey"
#endif

#define JSON_LENGTH_MAX						1024

#define IBEKG_URI_LEN_MAX					255
#define IBEKG_URI_LEN_MIN					4

#define MASTERKEY_STORAGE_ENTROPY_LEN_MAX	255
#define MASTERKEY_STORAGE_ENTROPY_LEN_MIN	16

#define MASTERKEY_BUF_SIZE					32
#define RND_ENTROPY_BUF_SIZE				384 // 4 * 48 (* 2 - reservation)
#define RND_NONCE_BUF_SIZE					16

#define NONCE_SIZE							32
#define DIGEST_SIZE							48
#define KEY_SIZE							32
#define IV_SIZE								16
#define TAG_SIZE							16

#define DATA_RANDOM_BUF_SIZE				(KEY_SIZE + IV_SIZE)
#define IDENTITY_RANDOM_BUF_SIZE			(NONCE_SIZE + IV_SIZE)

#define DATACIPHER_ARR_MAX					100
#define IDENTITYCIPHER_ARR_MAX				100

#define UUID_LEN							36

#define ERR_MSG_BUF_SIZE					512

// Property Names
#define PN_DATA_KEY							"dataKey"
#define PN_DATA_IV							"dataIV"
#define PN_IDENTITY_CIPHER_ARR				"identityCipherArr"
#define PN_DATA_CIKEY						"dataCiKey"
#define PN_IDENTITY_IV						"identityIV"
#define PN_IDENTITY_TAG						"identityTag"
#define PN_IDENTITY_AAD_OBJ					"identityAadObj"
#define PN_IDENTITY_NONCE					"identityNonce"
#define PN_SENDER_ID						"senderId"
#define PN_IBEKG_URI						"ibekgURI"
#define PN_RECEIVER_ID						"receiverId"
#define PN_ISO_TIMESTAMP					"isoTimestamp"
#define PN_DATA_HASH						"dataHash"
#define PN_PRODUCT_VERSION					"productVersion"
#define PN_API_VERSION						"apiVersion"

#define PN_CURRENT_DATE						"currentDate"
#define PN_ANONYMITY_LEVEL					"anonymityLevel"
#define	PN_MASTERKEY_STORAGE_ENTROPY		"masterKeyStorageEntropy"
