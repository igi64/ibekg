/*************************************************************************
  Ibekg/secure_storage.cpp

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

#include "secure_storage.h"

#define OPTIONAL_ENTROPY "5ae440a9a4c20c4f8d2bd7557d4af67d731ffa2039fb5893d7d0eb0312a23d0c"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

long StoreBufSecure(char *subKey, char *valueName, unsigned char *value, unsigned long valueLen, const char *staticEntropy, unsigned char *iv)
{
    if (!subKey || !valueName)
        return ERROR_INVALID_DATA;

    LONG result = 0;
    DWORD keyCreationResult = 0;
    HKEY newKey;

    // Create a new key or open existing key.
    result = RegCreateKeyEx(
        HKEY_CURRENT_USER, 
        subKey, 
        0,
        NULL,
        0,
        KEY_ALL_ACCESS,
        NULL,
        &newKey,
        &keyCreationResult);

    if (ERROR_SUCCESS != result)
    {
        return result;
    }

    DATA_BLOB unencryptedData, encryptedData, optionalEntropy;

	unencryptedData.pbData = value;
	unencryptedData.cbData = valueLen;

	if (staticEntropy) {
		optionalEntropy.pbData = (unsigned char *)staticEntropy;
		optionalEntropy.cbData = strlen(staticEntropy) + 1;
	} else {
		optionalEntropy.pbData = (unsigned char *)OPTIONAL_ENTROPY;
		optionalEntropy.cbData = strlen(OPTIONAL_ENTROPY) + 1;
	}

    if (!CryptProtectData(
        &unencryptedData,
        NULL,
        &optionalEntropy,
        NULL,
        NULL,
        0,
        &encryptedData))
    {
		LocalFree(unencryptedData.pbData);
        RegCloseKey(newKey);
        return GetLastError();
    }

    // OK, so now we can save the data to the registry.
    result = RegSetValueEx(
        newKey,
        valueName,
        0,
        REG_BINARY,
        encryptedData.pbData,
        encryptedData.cbData);

    // Free the encrypted data buffer
    LocalFree(encryptedData.pbData);
    RegCloseKey(newKey);
    
    return result;
}

long LoadBufSecure(char *subKey, char *valueName, unsigned char *value, unsigned long valueLen, const char* staticEntropy)
{
    if (!subKey || !valueName)
        return NULL;

    LONG result = ERROR_SUCCESS;

    HKEY key;
    // Open the requested key
    result = RegOpenKeyEx(
        HKEY_CURRENT_USER, 
        subKey, 
        0, 
        KEY_READ, 
        &key);
    
    if (ERROR_SUCCESS != result)
        return NULL;

    // Read the encrypted data from the registry
    // First we will determine the required buffer size for the data.
    DWORD valueType = REG_BINARY;
    DWORD requiredLen = 0;
    result = RegQueryValueEx(
        key,
        valueName,
        NULL,
        &valueType,
        NULL,
        &requiredLen);

    if (ERROR_SUCCESS != result)
    {
        RegCloseKey(key);
        return NULL;
    }

    DATA_BLOB encryptedData, unencryptedData, optionalEntropy;
    
    unsigned char *encryptedRegistryEntry = (unsigned char *)malloc(requiredLen);
    result = RegQueryValueEx(
        key,
        valueName,
        NULL,
        &valueType,
        encryptedRegistryEntry,
        &requiredLen);
    
    // We're done with the registry entry now.
    RegCloseKey(key);

    if (ERROR_SUCCESS != result)
    {
        free(encryptedRegistryEntry);
        return NULL;
    }

    // OK, so we got the encrypted data, so let's decrypt it.
    encryptedData.pbData = encryptedRegistryEntry;
    encryptedData.cbData = requiredLen;

	if (staticEntropy) {
		optionalEntropy.pbData = (unsigned char *)staticEntropy;
		optionalEntropy.cbData = strlen(staticEntropy) + 1;
	} else {
		optionalEntropy.pbData = (unsigned char *)OPTIONAL_ENTROPY;
		optionalEntropy.cbData = strlen(OPTIONAL_ENTROPY) + 1;
	}

    LPWSTR dataDescription; // Receives the description saved with data
    if (!CryptUnprotectData(
        &encryptedData,
        &dataDescription,
		&optionalEntropy,
        NULL,
        NULL,
        0,
        &unencryptedData))
    {
        free(encryptedRegistryEntry);
		LocalFree(encryptedData.pbData);
        return NULL;
    }

    // We can free the encrypted registry entry now.
    free (encryptedRegistryEntry);

    // And the data description string as well.
    LocalFree(dataDescription);

	LONG rslt = NULL;

	if (unencryptedData.cbData == valueLen) {
		memcpy(value, unencryptedData.pbData, unencryptedData.cbData);
		rslt = unencryptedData.cbData;
	} else {
		rslt = NULL;
	}

    // Cleanup
    LocalFree(unencryptedData.pbData);

    return rslt;
}

long QueryBufSecure(char *subKey, char *valueName)
{
	if (!subKey || !valueName)
		return NULL;

	LONG result = ERROR_SUCCESS;

	HKEY key;
	// Open the requested key
	result = RegOpenKeyEx(
		HKEY_CURRENT_USER, 
		subKey, 
		0, 
		KEY_READ, 
		&key);

	if (ERROR_SUCCESS != result)
		return NULL;

	return 1;
}
#else
#include <glib.h>
#include <gnome-keyring.h>
#include <string.h>
#include <cstdlib>

#ifdef OPENSSL_FIPS_BUILD
#include <openssl/fipssyms.h>
#include <openssl/fips_rand.h>
#else
#include <openssl/hmac.h>
#endif

#include <openssl/sha.h>

#include "utils.h";

int CryptBuf(unsigned char *value,
	int valueLen,
	const char *keyStr,
	unsigned char *iv,
	int encrypt);

long StoreBufSecure(char *subKey, char *valueName, unsigned char *value, unsigned long valueLen, const char* staticEntropy, unsigned char *iv)
{
	guint32 itemid;
	char *value_iv_str;

	int rslt = 1;

	//unsigned char iv[EVP_MAX_IV_LENGTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	CryptBuf(value, valueLen, staticEntropy, iv, 1);

	value_iv_str = (char*)malloc((2 * valueLen) + (2 * EVP_MAX_IV_LENGTH) + 1);
	charToHex(value_iv_str, (const char*)value, valueLen);
	charToHex(&value_iv_str[2 * valueLen], (const char*)iv, EVP_MAX_IV_LENGTH);

	if (gnome_keyring_set_network_password_sync(GNOME_KEYRING_DEFAULT,
			g_get_user_name(), NULL, subKey, valueName, NULL, NULL, 0,
			value_iv_str, &itemid) != GNOME_KEYRING_RESULT_OK)
	{
		rslt = 0;
	}

	free(value_iv_str);

	return rslt;
}

long LoadBufSecure(char *subKey, char *valueName, unsigned char *value, unsigned long valueLen, const char* staticEntropy)
{
	GList *list;
	GList *iter;
	char *pass = NULL;

	if (gnome_keyring_find_network_password_sync(g_get_user_name(), NULL, subKey,
			NULL, NULL, NULL, 0, &list) != GNOME_KEYRING_RESULT_OK)
	{
		return 0;
	}

	for (iter = list; iter; iter = iter->next)
	{
		GnomeKeyringNetworkPasswordData *data = (GnomeKeyringNetworkPasswordData *)iter->data;

		if (strcmp(data->object, valueName) == 0 && data->password)
		{
			pass = g_strdup(data->password);
			break;
		}
	}
	gnome_keyring_network_password_list_free(list);

	if (pass) {
		int passLen = strlen(pass);

		if ((passLen - (2 * EVP_MAX_IV_LENGTH)) / 2 == valueLen) {
			hexToChar(value, pass, 2 * valueLen);

			unsigned char iv[EVP_MAX_IV_LENGTH];
			hexToChar(iv, &pass[2 * valueLen], 2 * EVP_MAX_IV_LENGTH);

			CryptBuf(value, valueLen, staticEntropy, iv, 0);

			g_free(pass);

			return valueLen;
		}
		g_free(pass);
	}

	return 0;
}

long QueryBufSecure(char *subKey, char *valueName)
{
	GList *list;
	GList *iter;
	char *pass = NULL;

	if (gnome_keyring_find_network_password_sync(g_get_user_name(), NULL, subKey,
			NULL, NULL, NULL, 0, &list) != GNOME_KEYRING_RESULT_OK)
	{
		return 0;
	}

	for (iter = list; iter; iter = iter->next)
	{
		GnomeKeyringNetworkPasswordData *data = (GnomeKeyringNetworkPasswordData *)iter->data;

		if (strcmp(data->object, valueName) == 0 && data->password)
		{
			pass = g_strdup(data->password);
			break;
		}
	}
	gnome_keyring_network_password_list_free(list);

	if (pass) {
		g_free(pass);
		return 1;
	} else {
		return 0;
	}
}

int CryptBuf(unsigned char *value,
	int valueLen,
	const char *keyStr,
	unsigned char *iv,
	int encrypt)
{
	unsigned char hash[SHA512_DIGEST_LENGTH];
	int keyStrLen = strlen(keyStr);

	if (keyStrLen > 0) {
		SHA512_CTX sha512_ctx;
		SHA512_Init(&sha512_ctx);
		SHA512_Update(&sha512_ctx, keyStr, keyStrLen);
		SHA512_Final(hash, &sha512_ctx);

		EVP_CIPHER_CTX cipher_ctx;
#ifdef OPENSSL_FIPS_BUILD
		FIPS_cipher_ctx_init(&cipher_ctx);
		if (FIPS_cipherinit(&cipher_ctx, EVP_aes_256_cbc(), hash, iv, encrypt) <= 0) {
			return 0;
		}
		FIPS_cipher(&cipher_ctx, value, value, valueLen);
		FIPS_cipher_ctx_cleanup(&cipher_ctx);
#else
		EVP_CIPHER_CTX_init(&cipher_ctx);
		if (EVP_CipherInit(&cipher_ctx, EVP_aes_256_cbc(), hash, iv, encrypt) <= 0) {
			return 0;
		}
		EVP_Cipher(&cipher_ctx, value, value, valueLen);
		EVP_CIPHER_CTX_cleanup(&cipher_ctx);
#endif
	}

	return 0;
}

#endif
