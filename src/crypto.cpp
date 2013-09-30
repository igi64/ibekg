/*************************************************************************
  Ibekg/crypto.cpp

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

#include "crypto.h"
#include "utils.h"

//Disable unsafe code Visual Studio warning.
#pragma warning(push)
#pragma warning(disable: 4996) 

#define DONE 0
#define ERR	1

int Random(
#ifdef OPENSSL_FIPS_BUILD
	DRBG_CTX *drbg_ctx,
#endif
	char *err_msg,
	unsigned char *random_buf,
	size_t random_buf_len)
{
#ifdef OPENSSL_FIPS_BUILD
	if (!FIPS_drbg_generate(drbg_ctx, random_buf, random_buf_len, 0, NULL, 0)) {
		sprintf(&err_msg[strlen(err_msg)], "Random generator error\n");
		return ERR;
	}
#else
	if (!RAND_bytes(random_buf, random_buf_len)) {
		sprintf(&err_msg[strlen(err_msg)], "Random generator error\n");
		return ERR;
	}
#endif

	return DONE;
}

int IdentityDigest(HMAC_CTX *hmac_ctx,
	char *err_msg,
	unsigned char *masterkey_buf,
	unsigned char *identity_nonce,
	const char *receiver_id,
	unsigned char *identity_digest)
{
#ifdef OPENSSL_FIPS_BUILD
	if (FIPS_hmac_init_ex(hmac_ctx, masterkey_buf, MASTERKEY_BUF_SIZE, EVP_sha384(), NULL) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot init HMAC\n");
		return ERR;
	}
#else
	if (HMAC_Init_ex(hmac_ctx, masterkey_buf, MASTERKEY_BUF_SIZE, EVP_sha384(), NULL) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot init HMAC\n");
		return ERR;
	}
#endif
	if (HMAC_Update(hmac_ctx, identity_nonce, NONCE_SIZE) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot update HMAC\n");
		return ERR;
	}

	if (HMAC_Update(hmac_ctx, (unsigned char*)receiver_id, strlen(receiver_id)) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot update HMAC\n");
		return ERR;
	}

	unsigned int identity_digest_size = DIGEST_SIZE;

	if (HMAC_Final(hmac_ctx, identity_digest, &identity_digest_size) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot final HMAC\n");
		return ERR;
	}

	return DONE;
}

int Encrypt(EVP_CIPHER_CTX *cipher_ctx,
	char *err_msg,
	unsigned char *identity_digest,
	unsigned char *identity_iv,
	const char *identitycipher_aad,
	unsigned char *data_key,
	unsigned char *data_cikey,
	unsigned char *identity_tag)
{
#ifdef OPENSSL_FIPS_BUILD
	if (FIPS_cipherinit(cipher_ctx, EVP_aes_256_gcm(), identity_digest, identity_iv, 1) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot init AES\n");
		return ERR;
	}

	FIPS_cipher(cipher_ctx, NULL, (unsigned char*)identitycipher_aad, strlen(identitycipher_aad));

	FIPS_cipher(cipher_ctx, data_cikey, data_key, KEY_SIZE);

	FIPS_cipher(cipher_ctx, NULL, NULL, 0);

	if (!FIPS_cipher_ctx_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, identity_tag)) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot get Tag AES\n");
		return ERR;
	}
#else
	// init/cleanup for every round due to memory leaks
	EVP_CIPHER_CTX_init(cipher_ctx);

	if (EVP_CipherInit(cipher_ctx, EVP_aes_256_gcm(), identity_digest, identity_iv, 1) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot init AES\n");
		return ERR;
	}
	EVP_Cipher(cipher_ctx, NULL, (unsigned char*)identitycipher_aad, strlen(identitycipher_aad));

	EVP_Cipher(cipher_ctx, data_cikey, data_key, KEY_SIZE);

	EVP_Cipher(cipher_ctx, NULL, NULL, 0);

	if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, identity_tag)) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot get Tag AES\n");
		return ERR;
	}

	EVP_CIPHER_CTX_cleanup(cipher_ctx);
#endif

	return DONE;
}

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
	char *data_key_str,
	json_t *json_arr_identitykey)
{
	json_t *json_obj_identitykey;

#ifdef OPENSSL_FIPS_BUILD
	if (FIPS_cipherinit(cipher_ctx, EVP_aes_256_gcm(), identity_digest, identity_iv, 0) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot init AES\n");
		return ERR;
	}

	if (!FIPS_cipher_ctx_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, identity_tag)) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot get Tag AES\n");
		return ERR;
	}

	FIPS_cipher(cipher_ctx, NULL, (unsigned char*)identitycipher_aad, strlen(identitycipher_aad));

	FIPS_cipher(cipher_ctx, data_key, data_cikey, KEY_SIZE);

	if (FIPS_cipher(cipher_ctx, NULL, NULL, 0) >= 0) {
		// Generate JSON
		json_obj_identitykey = json_object();

		charToHex(identity_nonce_str, (const char*)identity_nonce, NONCE_SIZE);
		charToHex(data_key_str, (const char*)data_key, KEY_SIZE);

		json_object_set_new(json_obj_identitykey, "identityNonce", json_string(identity_nonce_str));
		json_object_set_new(json_obj_identitykey, "dataKey", json_string(data_key_str));

		json_array_append(json_arr_identitykey, json_obj_identitykey);

		json_decref(json_obj_identitykey);
	} else {
		// nothing to do
	}
#else
	// init/cleanup for every round due to memory leaks
	EVP_CIPHER_CTX_init(cipher_ctx);

	if (EVP_CipherInit(cipher_ctx, EVP_aes_256_gcm(), identity_digest, identity_iv, 0) <= 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot init AES\n");
		return ERR;
	}

	if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, identity_tag)) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot get Tag AES\n");
		return ERR;
	}

	EVP_Cipher(cipher_ctx, NULL, (unsigned char*)identitycipher_aad, strlen(identitycipher_aad));

	EVP_Cipher(cipher_ctx, data_key, data_cikey, KEY_SIZE);

	if (EVP_Cipher(cipher_ctx, NULL, NULL, 0) >= 0) {
		// Generate JSON
		json_obj_identitykey = json_object();

		charToHex(identity_nonce_str, (const char*)identity_nonce, NONCE_SIZE);
		charToHex(data_key_str, (const char*)data_key, KEY_SIZE);

		json_object_set_new(json_obj_identitykey, "identityNonce", json_string(identity_nonce_str));
		json_object_set_new(json_obj_identitykey, "dataKey", json_string(data_key_str));

		json_array_append(json_arr_identitykey, json_obj_identitykey);

		json_decref(json_obj_identitykey);
	} else {
		// nothing to do
	}

	EVP_CIPHER_CTX_cleanup(cipher_ctx);
#endif

	return DONE;
}

#pragma warning(pop)
