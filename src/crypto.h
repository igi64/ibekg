/*************************************************************************
  Ibekg/crypto.h

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
#include "ibekg.h"

int Random(
#ifdef OPENSSL_FIPS_BUILD
	DRBG_CTX *drbg_ctx,
#endif
	char *err_msg,
	unsigned char *random_buf,
	size_t random_buf_len);
int IdentityDigest(HMAC_CTX *hmac_ctx,
	char *err_msg,
	unsigned char *masterkey_buf,
	unsigned char *identity_nonce,
	const char *receiver_id,
	unsigned char *identity_digest);
int Encrypt(EVP_CIPHER_CTX *cipher_ctx,
	char *err_msg,
	unsigned char *identity_digest,
	unsigned char *identity_iv,
	const char *identitycipher_aad,
	unsigned char *data_key,
	unsigned char *data_cikey,
	unsigned char *identity_tag);
int Decrypt(EVP_CIPHER_CTX *cipher_ctx,
	char *err_msg,
	unsigned char *identity_digest,
	unsigned char *identity_iv,
	unsigned char *identity_tag,
	const char *identitycipher_aad,
	unsigned char *data_cikey,
	unsigned char *data_key,
	unsigned char *identity_nonce,
	char *identity_nonce_str,
	char *identity_key_str,
	json_t *json_arr_identitykey);
