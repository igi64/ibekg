/*************************************************************************
  Ibekg/nodejs_ibekg.cpp

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

//TODO BackupMasterKey ???
//TODO ibekg.createMasterKey() with safety param (e.g. date/time)
//TODO Better input data parsing/error handling

#include "nodejs_ibekg.h"

#include "../crypto.h"
#include "../secure_storage.h"
#include "../uuid_gen.h"
#include "../utils.h"

//Disable unsafe code Visual Studio warning.
#pragma warning(push)
#pragma warning(disable: 4996) 

#ifdef OPENSSL_FIPS_BUILD
size_t Ibekg::drbg_get_entropy(DRBG_CTX *dctx, unsigned char **pout, int entropy, size_t min_len, size_t max_len) {
	DRBG_ENT *t = (DRBG_ENT*)FIPS_drbg_get_app_data(dctx);

	if ((min_len * (t->entcnt + 1)) <= t->entlen) {
		*pout = (unsigned char *)&t->ent[min_len * t->entcnt];	
		t->entcnt++;
		return min_len;
	} else {
		return 0;
	}
}

size_t Ibekg::drbg_get_nonce(DRBG_CTX *dctx, unsigned char **pout, int entropy, size_t min_len, size_t max_len) {
	DRBG_ENT *t = (DRBG_ENT*)FIPS_drbg_get_app_data(dctx);

	time_t rawtime;
	time(&rawtime);
	// Only for testing!
	//rawtime = 987654321;

	memcpy((unsigned char *)t->nonce, &rawtime, sizeof(rawtime));

	*pout = (unsigned char *)t->nonce;

	t->noncecnt++;
	return t->noncelen;
}
#endif

v8::Local<v8::Object> Ibekg::JSON;
v8::Persistent<v8::Function> Ibekg::stringify;
v8::Persistent<v8::Function> Ibekg::parse;

v8::Handle<v8::Value> Ibekg::New(const v8::Arguments& args) {
	v8::HandleScope scope;

	Ibekg* ibekg = new Ibekg();

	ibekg->engine_setup = 0;

	ibekg->ibekg_uri[0] = 0;
	ibekg->masterkey_storage_entropy[0] = 0;

	int mode = FIPS_mode();

	if (mode != 1) {
		int ret = FIPS_mode_set(1 /*on*/);

		if (ret != 1) {
			FIPS_mode_set(0 /*off*/);
		}
	}

	// Get the global object, same as using 'global' in Node
	v8::Local<v8::Object> global = v8::Context::GetCurrent()->Global();

	// Get JSON, same as using 'global.JSON'
	//v8::Local<v8::Object> JSON = v8::Local<v8::Object>::Cast(global->Get(v8::String::New("JSON")));
	ibekg->JSON = v8::Local<v8::Object>::Cast(global->Get(v8::String::New("JSON")));

	// Get stringify, same as using 'global.JSON.stringify'
	v8::Local<v8::Function> stringify = v8::Local<v8::Function>::Cast(ibekg->JSON->Get(v8::String::New("stringify")));
	ibekg->stringify = v8::Persistent<v8::Function>::New(stringify);

	// Get parse, same as using 'global.JSON.parse'
	v8::Local<v8::Function> parse = v8::Local<v8::Function>::Cast(ibekg->JSON->Get(v8::String::New("parse")));
	ibekg->parse = v8::Persistent<v8::Function>::New(parse);

	ibekg->Wrap(args.This());
	return args.This();
}

v8::Handle<v8::Value> Ibekg::GetCryptoInfo(const v8::Arguments& args) {
	v8::HandleScope scope;
	Ibekg* ibekg = ObjectWrap::Unwrap<Ibekg>(args.This());

	char json_data[JSON_LENGTH_MAX] = ""; 

	json_t *json_obj;
	char *json_buff;

	json_set_alloc_funcs(secure_malloc, secure_free);

	json_obj = json_object();
	
	json_object_set_new(json_obj, "product_version", json_string(PRODUCT_VERSION));
	json_object_set_new(json_obj, "api_version", json_string(API_VERSION));

#ifdef OPENSSL_FIPS_BUILD
	json_object_set_new(json_obj, "fips_build", json_string("true"));
#else
	json_object_set_new(json_obj, "fips_build", json_string("false"));
#endif

	int mode = FIPS_mode();
		
	if (mode == 1) {
		json_object_set_new(json_obj, "fips_enabled", json_string("true"));
	} else {
		json_object_set_new(json_obj, "fips_enabled", json_string("false"));
	}

	if (QueryBufSecure(REGISTRY_SUBKEY_IBEKG, REGISTRY_MASTERKEY) == 1) {
		json_object_set_new(json_obj, "masterkey_stored", json_string("true"));
	} else {
		json_object_set_new(json_obj, "masterkey_stored", json_string("false"));
	}

	json_object_set_new(json_obj, "entropy_bufs_size", json_integer(RND_ENTROPY_BUF_SIZE));
	
	json_object_set_new(json_obj, "datacipher_arr_max", json_integer(DATACIPHER_ARR_MAX));
	json_object_set_new(json_obj, "identitycipher_arr_max", json_integer(IDENTITYCIPHER_ARR_MAX));

	json_buff = json_dumps(json_obj, 0);

	BUF_strlcpy(json_data, json_buff, JSON_LENGTH_MAX); //strlcpy, strcpy_s
	
	secure_free(json_buff);
	json_decref(json_obj);

	return v8::String::New(json_data);
}

v8::Handle<v8::Value> Ibekg::SetupEngine(const v8::Arguments& args) {
	v8::HandleScope scope;
	Ibekg* ibekg = ObjectWrap::Unwrap<Ibekg>(args.This());
	char err_msg[ERR_MSG_BUF_SIZE + 1];

	ibekg->engine_setup++;

	strcpy(err_msg, "SetupEngine error\n");

	if (ibekg->engine_setup > 1) {
		sprintf(&err_msg[strlen(err_msg)], "setupEngine function can be called only once in a session!\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

#ifdef OPENSSL_FIPS_BUILD
	strcpy(&err_msg[strlen(err_msg)], "Random generator initialization error\n");

	if (args.Length() == 2) {
		if (!args[0]->IsObject()) {
			sprintf(&err_msg[strlen(err_msg)], "The first argument must be an object\n");
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}
		if (!args[1]->IsFunction()) {
			sprintf(&err_msg[strlen(err_msg)], "The second argument must be a callback function\n");
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}
	} else {
		sprintf(&err_msg[strlen(err_msg)], "use: setupEngine(setupEngineOptions, function (entlen) {...})\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	//// Callback

	{
		v8::Local<v8::Function> cb = v8::Local<v8::Function>::Cast(args[1]);

		const unsigned argc = 1;
		v8::Local<v8::Value> argv[argc] = {
			v8::Local<v8::Value>::New(v8::Integer::New(RND_ENTROPY_BUF_SIZE))
		};

		v8::Handle<v8::Value> js_result = cb->Call(v8::Context::GetCurrent()->Global(), argc, argv);

		if (js_result->IsArray()) {

			v8::Local<v8::Array> rslt = v8::Array::Cast(*js_result);

			if (rslt->Length() < RND_ENTROPY_BUF_SIZE) {
				sprintf(&err_msg[strlen(err_msg)], "An array must be of %1u length\n", RND_ENTROPY_BUF_SIZE);
				return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
			}

			for (int i = 0; i < RND_ENTROPY_BUF_SIZE; i++) 
			{
				v8::Local<v8::Value> element = rslt->Get(i);
				nonce_entropy_buf[i] = element->Int32Value();
			} 
		} else {
			if (js_result->IsString()) {
				v8::String::Utf8Value errorMsg(js_result);
				sprintf(&err_msg[strlen(err_msg)], *errorMsg);
				return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
			} else {
				sprintf(&err_msg[strlen(err_msg)], "Callback function must return an array\n");
				return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
			}
		}
	}
	////

	char uuid[UUID_LEN + 1] = "00000000-0000-0000-0000-000000000000";

	if (GetUUID(uuid) != 0) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot get UUID\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	// Only for testing!
	//char uuid[UUID_LEN + 1] = "5D810F42-B740-4DD8-BD80-E286432DA179";
	//printf(uuid);

	ibekg->nonce_drbg_ctx = FIPS_drbg_new(NID_aes_256_ctr, DRBG_FLAG_CTR_USE_DF);

	if (!ibekg->nonce_drbg_ctx) {
		// probably fips mode is not enabled correctly
		sprintf(&err_msg[strlen(err_msg)], "Cannot create FIPS-DRGB\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!FIPS_drbg_set_callbacks(ibekg->nonce_drbg_ctx, ibekg->drbg_get_entropy, 0, 0x10, ibekg->drbg_get_nonce, 0)) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot set callback for iv FIPS-DRGB\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}
	FIPS_drbg_set_app_data(ibekg->nonce_drbg_ctx, &ibekg->nonce_drbg_ent);

	//Should be true random data e.g. from random.org
	ibekg->nonce_drbg_ent.ent = nonce_entropy_buf;
	ibekg->nonce_drbg_ent.entlen = RND_ENTROPY_BUF_SIZE;
	ibekg->nonce_drbg_ent.nonce = iv_nonce_buf;
	ibekg->nonce_drbg_ent.noncelen = sizeof(iv_nonce_buf);
	ibekg->nonce_drbg_ent.entcnt = 0;
	ibekg->nonce_drbg_ent.noncecnt = 0;

	if (!FIPS_drbg_instantiate(ibekg->nonce_drbg_ctx, (unsigned char*)uuid, strlen(uuid))) {
		sprintf(&err_msg[strlen(err_msg)], "Cannot instantiate iv FIPS-DRGB\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}
#else
	if (args.Length() == 1) {
		if (!args[0]->IsObject()) {
			sprintf(&err_msg[strlen(err_msg)], "The first argument must be an object\n");
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}
	} else {
		sprintf(&err_msg[strlen(err_msg)], "use: setupEngine(setupEngineOptions)\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

#endif

	{
		const char *ibekg_uri = 0;
		const char *master_key_storage_entropy = 0;

		v8::Handle<v8::Value> options_obj[1];
		options_obj[0] = args[0]->ToObject();

		v8::Local<v8::String> options_obj_str = v8::Local<v8::String>::Cast(stringify->Call(JSON, 1, options_obj));

		json_t *json_obj_options;
		json_error_t error;

		json_obj_options = json_loads(*(v8::String::Utf8Value)options_obj_str, 0, &error);
		if (json_obj_options) {
			ibekg_uri = json_string_value(json_object_get(json_obj_options, PN_IBEKG_URI));
			master_key_storage_entropy = json_string_value(json_object_get(json_obj_options, PN_MASTERKEY_STORAGE_ENTROPY));
		} else {
			sprintf(&err_msg[strlen(err_msg)], "JSON error: %s", error.text);
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}

		if (strlen(ibekg_uri) >= IBEKG_URI_LEN_MIN && strlen(ibekg_uri) <= IBEKG_URI_LEN_MAX) {
			memcpy(ibekg->ibekg_uri, ibekg_uri, strlen(ibekg_uri) + 1);
		} else {
			sprintf(&err_msg[strlen(err_msg)], "The length of ibekg uri must be between %i and %i \n", IBEKG_URI_LEN_MIN, IBEKG_URI_LEN_MAX);
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}

		if (strlen(master_key_storage_entropy) >= MASTERKEY_STORAGE_ENTROPY_LEN_MIN && strlen(master_key_storage_entropy) <= MASTERKEY_STORAGE_ENTROPY_LEN_MAX) {
			memcpy(ibekg->masterkey_storage_entropy, master_key_storage_entropy, strlen(master_key_storage_entropy) + 1);
		} else {
			sprintf(&err_msg[strlen(err_msg)], "The length of Master Key Storage Entropy must be between %i and %i \n", MASTERKEY_STORAGE_ENTROPY_LEN_MIN, MASTERKEY_STORAGE_ENTROPY_LEN_MAX);
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}

		json_decref(json_obj_options);
	}

	err_msg[0] = 0;

	return v8::Undefined();
}

v8::Handle<v8::Value> Ibekg::CreateMasterKey(const v8::Arguments& args) {
	v8::HandleScope scope;
	Ibekg* ibekg = ObjectWrap::Unwrap<Ibekg>(args.This());
	char err_msg[ERR_MSG_BUF_SIZE + 1];

	strcpy(err_msg, "CreateMasterKey error\n");

	if (!ibekg->engine_setup) {
		sprintf(&err_msg[strlen(err_msg)], "You must call setupEngine at first\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (args.Length() != 1) {
		sprintf(&err_msg[strlen(err_msg)], "use: createMasterKey(createMasterKeyOptions)\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!args[0]->IsObject()) {
		sprintf(&err_msg[strlen(err_msg)], "The first argument must be an object\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	{
		v8::Handle<v8::Value> options_obj[1];
		options_obj[0] = args[0]->ToObject();

		v8::Local<v8::String> options_obj_str = v8::Local<v8::String>::Cast(stringify->Call(JSON, 1, options_obj));

		json_t *json_obj_options;
		json_error_t error;

		json_obj_options = json_loads(*(v8::String::Utf8Value)options_obj_str, 0, &error);
		if (json_obj_options) {
			const char *current_date = json_string_value(json_object_get(json_obj_options, PN_CURRENT_DATE));
			if (current_date) {
				time_t now;
				time(&now);
				char iso_timestamp[sizeof("2012-12-31")];
				strftime(iso_timestamp, sizeof(iso_timestamp), "%Y-%m-%d", gmtime(&now));

				if (strcmp(current_date, iso_timestamp) != 0)
				{
					sprintf(&err_msg[strlen(err_msg)], "Current date error");
					return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
				}
			} else {
				sprintf(&err_msg[strlen(err_msg)], "JSON error: %s", error.text);
				return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
			}
		} else {
			sprintf(&err_msg[strlen(err_msg)], "JSON error: %s", error.text);
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}

		unsigned char * masterkey_buf = (unsigned char *)malloc(MASTERKEY_BUF_SIZE);

		if (Random(
#ifdef OPENSSL_FIPS_BUILD
			ibekg->nonce_drbg_ctx,
#endif
			err_msg, masterkey_buf,
			MASTERKEY_BUF_SIZE) != 0)
		{
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}

		unsigned char masterkey_iv[EVP_MAX_IV_LENGTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

		if (Random(
#ifdef OPENSSL_FIPS_BUILD
			ibekg->nonce_drbg_ctx,
#endif
			err_msg, masterkey_iv,
			EVP_MAX_IV_LENGTH) != 0)
		{
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}

		StoreBufSecure(REGISTRY_SUBKEY_IBEKG, REGISTRY_MASTERKEY, masterkey_buf, MASTERKEY_BUF_SIZE, ibekg->masterkey_storage_entropy, masterkey_iv);

		json_decref(json_obj_options);
		
		memset(masterkey_buf, 0, MASTERKEY_BUF_SIZE);

		free(masterkey_buf);
	}

	err_msg[0] = 0;

	return v8::Undefined();
}

v8::Handle<v8::Value> Ibekg::EncryptDataKey(const v8::Arguments& args) {
	v8::HandleScope scope;
	Ibekg* ibekg = ObjectWrap::Unwrap<Ibekg>(args.This());
	char err_msg[ERR_MSG_BUF_SIZE + 1];

	strcpy(err_msg, "EncryptDataKey error\n");

	if (!ibekg->engine_setup) {
		sprintf(&err_msg[strlen(err_msg)], "You must call setupEngine at first\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if ((args.Length() < 4) || (args.Length() > 5)) {
		sprintf(&err_msg[strlen(err_msg)], "use: encryptDataKey(encryptDataKeyOptions, dataHashArr, senderId, [receiverIdArr], function (err, result) {...})\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!args[0]->IsObject()) {
		sprintf(&err_msg[strlen(err_msg)], "The first argument must be an object\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!args[1]->IsArray()) {
		sprintf(&err_msg[strlen(err_msg)], "The second argument must be an array\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!args[2]->IsString()) {
		sprintf(&err_msg[strlen(err_msg)], "The third argument must be a string\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (args.Length() > 4) {
		if (!args[3]->IsArray()) {
			sprintf(&err_msg[strlen(err_msg)], "The fourth argument must be an array\n");
			return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
		}
	}

	if (!args[args.Length()-1]->IsFunction()) {
		sprintf(&err_msg[strlen(err_msg)], "The last argument must be a callback function\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	{
		// There's no ToFunction(), use a Cast instead.
		v8::Local<v8::Function> callback = v8::Local<v8::Function>::Cast(args[args.Length()-1]);

		// This creates our work request, including the libuv struct.
		Baton* baton = new Baton();
		baton->err_code = 1;
		strcpy(baton->err_msg, "EncryptDataKey error\n");
		baton->data_random_buf_len = 0;
		baton->data_random_buf = 0;
		baton->identity_random_buf_len = 0;
		baton->identity_random_buf = 0;
		baton->jsn_options = 0;
		baton->jsn_data_in = 0;
		baton->jsn_data_out = 0;
		baton->request.data = baton;
		baton->callback = v8::Persistent<v8::Function>::New(callback);

		baton->ibekg_uri = 0;

		if (strlen(ibekg->ibekg_uri) > 0) {
			int ibekg_uri_len = strlen(ibekg->ibekg_uri);
			baton->ibekg_uri = (char*)malloc(ibekg_uri_len + 1);
			memcpy(baton->ibekg_uri, ibekg->ibekg_uri, ibekg_uri_len + 1);
		}

		baton->identity_id = 0;

		// utf-8 support
		if (args[2]->ToString()->Length() > 0) {
			int sender_id_len = strlen(*(v8::String::Utf8Value)args[2]);
			baton->identity_id = (char*)malloc(sender_id_len + 1);
			memcpy(baton->identity_id, *(v8::String::Utf8Value)args[2], sender_id_len + 1);
		} else {
			sprintf(&baton->err_msg[strlen(baton->err_msg)], "senderId cannot be empty");
			goto err_baton;
		}

		{
			{
				v8::Handle<v8::Value> options_obj[1];
				options_obj[0] = args[0]->ToObject();

				v8::Local<v8::String> options_obj_str = v8::Local<v8::String>::Cast(stringify->Call(JSON, 1, options_obj));

				json_t *json_obj_options;
				json_error_t error;

				json_obj_options = json_loads(*(v8::String::Utf8Value)options_obj_str, 0, &error);
				if (json_obj_options) {
					baton->jsn_options = json_obj_options;
					json_object_set_new(json_obj_options, PN_MASTERKEY_STORAGE_ENTROPY, json_string(ibekg->masterkey_storage_entropy));
				} else {
					sprintf(&baton->err_msg[strlen(baton->err_msg)], "JSON error: %s", error.text);
					goto err_baton;
				}

				v8::Local<v8::Value> datahash_arr[] = { v8::Array::Cast(*args[1]) };
			
				v8::Local<v8::String> datahash_arr_str = v8::Local<v8::String>::Cast(stringify->Call(JSON, 1, datahash_arr));

				v8::Local<v8::String> arr_str = datahash_arr_str->Concat(v8::String::New("{\"dataHashArr\":"), datahash_arr_str);

				if (args.Length() > 4) {
					v8::Local<v8::Value> identity_arr[] = { v8::Array::Cast(*args[3]) };

					v8::Local<v8::String> identity_arr_str = v8::Local<v8::String>::Cast(stringify->Call(JSON, 1, identity_arr));
					identity_arr_str = identity_arr_str->Concat(v8::String::New("\"identityArr\":"), identity_arr_str);

					arr_str = arr_str->Concat(arr_str, v8::String::New(","));
					arr_str = arr_str->Concat(arr_str, identity_arr_str);
				} else {
					v8::Local<v8::String> identity_arr_str = v8::String::New(baton->identity_id);
					identity_arr_str = identity_arr_str->Concat(v8::String::New("[\""), identity_arr_str);
					identity_arr_str = identity_arr_str->Concat(identity_arr_str, v8::String::New("\"]"));
					identity_arr_str = identity_arr_str->Concat(v8::String::New("\"identityArr\":"), identity_arr_str);

					arr_str = arr_str->Concat(arr_str, v8::String::New(","));
					arr_str = arr_str->Concat(arr_str, identity_arr_str);
				}

				arr_str = arr_str->Concat(arr_str, v8::String::New("}"));

				json_t *json_obj;

				json_obj = json_loads(*(v8::String::Utf8Value)arr_str, 0, &error);
				if (json_obj) {
					baton->jsn_data_in = json_obj;
				} else {
					sprintf(&baton->err_msg[strlen(baton->err_msg)], "JSON error: %s", error.text);
					goto err_baton;
				}

				// We must add sender_id to identity_arr (if it is not there)
				char *identity_id = baton->identity_id;
				json_t *json_arr_datahash;
				json_t *json_arr_identity;
				int identity_id_found = 0;

				json_arr_datahash = json_object_get(json_obj, "dataHashArr");
				json_arr_identity = json_object_get(json_obj, "identityArr");

				if (!json_arr_datahash)
				{
					sprintf(&baton->err_msg[strlen(baton->err_msg)], "Cannot load dataHash array\n");
					goto err_baton;
				}

				if (!json_arr_identity)
				{
					sprintf(&baton->err_msg[strlen(baton->err_msg)], "Cannot load dataIdentity array\n");
					goto err_baton;
				}

				for (size_t i = 0; i < json_array_size(json_arr_identity); i++)
				{
					const char *identity_id_tmp = json_string_value(json_array_get(json_arr_identity, i));

					if (strcmp(identity_id, identity_id_tmp) == 0) {
						identity_id_found = 1;
						break;
					}
				}

				if (!identity_id_found) {
					json_array_insert_new(json_arr_identity, 0, json_string(identity_id));
				}

				// We must generate random numbers here - to avoid race conditions due to threaded EncryptDataKeyWork
				baton->data_random_buf_len = json_array_size(json_arr_datahash) * DATA_RANDOM_BUF_SIZE;
				baton->data_random_buf = (unsigned char*)malloc(baton->data_random_buf_len);

				baton->identity_random_buf_len = json_array_size(json_arr_datahash) * json_array_size(json_arr_identity) * IDENTITY_RANDOM_BUF_SIZE;
				baton->identity_random_buf = (unsigned char*)malloc(baton->identity_random_buf_len);

				if (Random(
#ifdef OPENSSL_FIPS_BUILD
					ibekg->nonce_drbg_ctx,
#endif
					baton->err_msg,
					baton->data_random_buf,
					baton->data_random_buf_len) != 0) {
						goto err_baton;
				}

				if (Random(
#ifdef OPENSSL_FIPS_BUILD
					ibekg->nonce_drbg_ctx,
#endif
					baton->err_msg,
					baton->identity_random_buf,
					baton->identity_random_buf_len) != 0) {
						goto err_baton;
				}
			}
		}

		err_msg[0] = 0;

		baton->err_code = 0;

err_baton:
		// Schedule our work request with libuv. Here you can specify the functions
		// that should be executed in the threadpool and back in the main thread
		// after the threadpool function completed.
		int status = uv_queue_work(uv_default_loop(), &baton->request, EncryptDataKeyWork, (uv_after_work_cb)DataKeyAfter);
		assert(status == 0);
	}

	return v8::Undefined();
}

void Ibekg::EncryptDataKeyWork(uv_work_t* req) {
	Baton* baton = static_cast<Baton*>(req->data);

	if (baton->err_code) {
		return;
	}

	baton->err_code = 1;
	strcpy(baton->err_msg, "EncryptDataKeyWork error\n");

	// Timestamp
	time_t now;
	time(&now); // timestamp
	char iso_timestamp[sizeof("2012-12-31T12:00:00Z")];
	// Only for testing!
	//now = 987654321;
	strftime(iso_timestamp, sizeof(iso_timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

	// Load Masterkey
	const char *masterkey_storage_entropy = json_string_value(json_object_get(baton->jsn_options, PN_MASTERKEY_STORAGE_ENTROPY));

	unsigned char* masterkey_buf = (unsigned char*)malloc(MASTERKEY_BUF_SIZE);
	long masterkey_buf_len = LoadBufSecure(REGISTRY_SUBKEY_IBEKG, REGISTRY_MASTERKEY, masterkey_buf, MASTERKEY_BUF_SIZE, masterkey_storage_entropy);
	//printf("masterkey_buf_len = %i \n", masterkey_buf_len);
	if (masterkey_buf && masterkey_buf_len == MASTERKEY_BUF_SIZE) {
		HMAC_CTX hmac_ctx;
		HMAC_CTX_init(&hmac_ctx);

		EVP_CIPHER_CTX cipher_ctx;
#ifdef OPENSSL_FIPS_BUILD
		FIPS_cipher_ctx_init(&cipher_ctx);
#else
		//EVP_CIPHER_CTX_init(&cipher_ctx);
#endif

		char *ibekg_uri = baton->ibekg_uri;
		char *sender_id = baton->identity_id;
		// out
		unsigned char* data_key = (unsigned char*)malloc(KEY_SIZE);	
		unsigned char* data_iv = (unsigned char*)malloc(IV_SIZE);	

		unsigned char* identity_digest = (unsigned char*)malloc(DIGEST_SIZE);	
		unsigned char* data_cikey = (unsigned char*)malloc(KEY_SIZE);	
		unsigned char* identity_tag = (unsigned char*)malloc(TAG_SIZE);	

		char* data_key_str = (char*)malloc(2 * KEY_SIZE + 1);	
		char* data_iv_str = (char*)malloc(2 * IV_SIZE + 1);	

		char* identity_nonce_str = (char*)malloc(2 * NONCE_SIZE + 1);	
		char* data_cikey_str = (char*)malloc(2 * KEY_SIZE + 1);	
		char* identity_iv_str = (char*)malloc(2 * IV_SIZE + 1);	
		char* identity_tag_str = (char*)malloc(2 * TAG_SIZE + 1);	

		json_set_alloc_funcs(secure_malloc, secure_free);
		// in
		json_t *json_obj;
		json_t *json_arr_datahash;
		json_t *json_arr_identity;
		json_t *json_obj_identityaad;
		// out
		json_t *json_arr_cipher;
		json_t *json_obj_datacipher;
		json_t *json_arr_identitycipher;
		json_t *json_obj_identitycipher;

		json_obj = baton->jsn_data_in;

		baton->jsn_data_out = json_array();
		json_arr_cipher = baton->jsn_data_out;

		json_arr_datahash = json_object_get(json_obj, "dataHashArr");
		json_arr_identity = json_object_get(json_obj, "identityArr");

		int datahash_arr_len = json_array_size(json_arr_datahash);
		int identity_arr_len = json_array_size(json_arr_identity);

		for (int i = 0; i < datahash_arr_len; i++)
		{
			json_arr_identitycipher = json_array();

			int data_idx = ((i + 1) * DATA_RANDOM_BUF_SIZE) - DATA_RANDOM_BUF_SIZE;
			// data random values
			unsigned char* data_key = &baton->data_random_buf[data_idx];	
			unsigned char* data_iv = &baton->data_random_buf[data_idx + KEY_SIZE];

			for (int j = 0; j < identity_arr_len; j++)
			{
				baton->err_code = 1;

				int identity_idx = ((i + 1) * (j + 1) * IDENTITY_RANDOM_BUF_SIZE) - IDENTITY_RANDOM_BUF_SIZE;
				// identity random values
				unsigned char* identity_nonce = &baton->identity_random_buf[identity_idx];	
				unsigned char* identity_iv = &baton->identity_random_buf[identity_idx + NONCE_SIZE];

				const char *datahash = json_string_value(json_array_get(json_arr_datahash, i));
				const char *receiver_id = json_string_value(json_array_get(json_arr_identity, j));

				charToHex(identity_nonce_str, (const char*)identity_nonce, NONCE_SIZE);

				// Build AAD to preserve AAD properties order
				json_obj_identityaad = json_object();

				int anonymity_level = (int)json_integer_value(json_object_get(baton->jsn_options, PN_ANONYMITY_LEVEL));

				if (anonymity_level == 0) {
					json_object_set_new(json_obj_identityaad, PN_SENDER_ID, json_string(sender_id));
					json_object_set_new(json_obj_identityaad, PN_RECEIVER_ID, json_string(receiver_id));
				}
				json_object_set_new(json_obj_identityaad, PN_IDENTITY_NONCE, json_string(identity_nonce_str));
				json_object_set_new(json_obj_identityaad, PN_DATA_HASH, json_string(datahash));
				if (anonymity_level < 2) {
					json_object_set_new(json_obj_identityaad, PN_IBEKG_URI, json_string(ibekg_uri));
				}
				json_object_set_new(json_obj_identityaad, PN_ISO_TIMESTAMP, json_string(iso_timestamp));
				json_object_set_new(json_obj_identityaad, PN_PRODUCT_VERSION, json_string(PRODUCT_VERSION));
				json_object_set_new(json_obj_identityaad, PN_API_VERSION, json_string(API_VERSION));

				const char *identitycipher_aad = json_dumps(json_obj_identityaad, 0);

				// Identity digest
				if (IdentityDigest(&hmac_ctx,
					baton->err_msg, masterkey_buf,
					identity_nonce,
					receiver_id,
					identity_digest) == 0)
				{
					// Encrypt
					if (Encrypt(&cipher_ctx,
						baton->err_msg, identity_digest,
						identity_iv,
						identitycipher_aad,
						data_key,
						data_cikey,
						identity_tag) == 0)
					{
						baton->err_code = 0;
					}

				}

				// Generate JSON
				json_obj_identitycipher = json_object();

				charToHex(data_cikey_str, (const char*)data_cikey, KEY_SIZE);
				charToHex(identity_iv_str, (const char*)identity_iv, IV_SIZE);
				charToHex(identity_tag_str, (const char*)identity_tag, TAG_SIZE);

				json_object_set_new(json_obj_identitycipher, PN_DATA_CIKEY, json_string(data_cikey_str));
				json_object_set_new(json_obj_identitycipher, PN_IDENTITY_IV, json_string(identity_iv_str));
				json_object_set_new(json_obj_identitycipher, PN_IDENTITY_TAG, json_string(identity_tag_str));
				json_object_set(json_obj_identitycipher, PN_IDENTITY_AAD_OBJ, json_obj_identityaad);

				json_decref(json_obj_identityaad);

				json_array_append(json_arr_identitycipher, json_obj_identitycipher);

				json_decref(json_obj_identitycipher);

				secure_free((char*)identitycipher_aad);

				if (baton->err_code) {
					break;
				}
			}

			// Generate JSON
			json_obj_datacipher = json_object();

			charToHex(data_key_str, (const char*)data_key, KEY_SIZE);
			charToHex(data_iv_str, (const char*)data_iv, IV_SIZE);

			json_object_set_new(json_obj_datacipher, PN_DATA_KEY, json_string(data_key_str));
			json_object_set_new(json_obj_datacipher, PN_DATA_IV, json_string(data_iv_str));
			json_object_set(json_obj_datacipher, PN_IDENTITY_CIPHER_ARR, json_arr_identitycipher);

			json_decref(json_arr_identitycipher);

			json_array_append(json_arr_cipher, json_obj_datacipher);

			json_decref(json_obj_datacipher);

			if (baton->err_code) {
				break;
			}
		}

#ifdef OPENSSL_FIPS_BUILD
		FIPS_cipher_ctx_cleanup(&cipher_ctx);
#else
		// init/cleanup for every round due to memory leaks
		//EVP_CIPHER_CTX_cleanup(&cipher_ctx);
#endif

#ifdef OPENSSL_FIPS_BUILD
		FIPS_hmac_ctx_cleanup(&hmac_ctx);
#else
		HMAC_CTX_cleanup(&hmac_ctx);
#endif

		memset(data_key_str, 0, 2 * KEY_SIZE);
		free(data_key_str);
		memset(data_iv_str, 0, 2 * IV_SIZE);
		free(data_iv_str);

		memset(identity_nonce_str, 0, 2 * NONCE_SIZE);
		free(identity_nonce_str);
		memset(data_cikey_str, 0, 2 * KEY_SIZE);
		free(data_cikey_str);
		memset(identity_iv_str, 0, 2 * IV_SIZE);
		free(identity_iv_str);
		memset(identity_tag_str, 0, 2 * TAG_SIZE);
		free(identity_tag_str);

		memset(data_key, 0, KEY_SIZE);
		free(data_key);
		memset(data_iv, 0, IV_SIZE);
		free(data_iv);

		memset(identity_digest, 0, DIGEST_SIZE);
		free(identity_digest);
		memset(data_cikey, 0, KEY_SIZE);
		free(data_cikey);
		memset(identity_tag, 0, TAG_SIZE);
		free(identity_tag);
	} else {
		sprintf(&baton->err_msg[strlen(baton->err_msg)], "Cannot load Masterkey\n");
	}

	memset(masterkey_buf, 0, MASTERKEY_BUF_SIZE);
	free(masterkey_buf);
}

v8::Handle<v8::Value> Ibekg::DecryptDataKey(const v8::Arguments& args) {
	v8::HandleScope scope;
	Ibekg* ibekg = ObjectWrap::Unwrap<Ibekg>(args.This());
	char err_msg[ERR_MSG_BUF_SIZE + 1];

	strcpy(err_msg, "DecryptDataKey error\n");

	if (!ibekg->engine_setup) {
		sprintf(&err_msg[strlen(err_msg)], "You must call setupEngine at first\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (args.Length() != 4) {
		sprintf(&err_msg[strlen(err_msg)], "use: decryptDataKey(decryptDataKeyOptions, receiverId, identityCipherArr, function (err, result) {...})\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!args[0]->IsObject()) {
		sprintf(&err_msg[strlen(err_msg)], "The first argument must be an object\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!args[1]->IsString()) {
		sprintf(&err_msg[strlen(err_msg)], "The second argument must be a string\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!args[2]->IsArray()) {
		sprintf(&err_msg[strlen(err_msg)], "The third argument must be an array\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	if (!args[args.Length()-1]->IsFunction()) {
		sprintf(&err_msg[strlen(err_msg)], "The last argument must be a callback function\n");
		return v8::ThrowException(v8::Exception::Error(v8::String::New(err_msg)));
	}

	{
		// There's no ToFunction(), use a Cast instead.
		v8::Local<v8::Function> callback = v8::Local<v8::Function>::Cast(args[args.Length()-1]);

		// This creates our work request, including the libuv struct.
		Baton* baton = new Baton();
		baton->err_code = 1;
		strcpy(baton->err_msg, "DecryptDataKey error\n");
		baton->data_random_buf_len = 0;
		baton->data_random_buf = 0;
		baton->identity_random_buf_len = 0;
		baton->identity_random_buf = 0;
		baton->jsn_options = 0;
		baton->jsn_data_in = 0;
		baton->jsn_data_out = 0;
		baton->request.data = baton;
		baton->callback = v8::Persistent<v8::Function>::New(callback);

		baton->ibekg_uri = 0;

		if (strlen(ibekg->ibekg_uri) > 0) {
			int ibekg_uri_len = strlen(ibekg->ibekg_uri);
			baton->ibekg_uri = (char*)malloc(ibekg_uri_len + 1);
			memcpy(baton->ibekg_uri, ibekg->ibekg_uri, ibekg_uri_len + 1);
		}

		baton->identity_id = 0;

		// utf-8 support
		if (args[1]->ToString()->Length() > 0) {
			int receiver_id_len = strlen(*(v8::String::Utf8Value)args[1]);
			baton->identity_id = (char*)malloc(receiver_id_len + 1);
			memcpy(baton->identity_id, *(v8::String::Utf8Value)args[1], receiver_id_len + 1);
		} else {
			sprintf(&baton->err_msg[strlen(baton->err_msg)], "receiverId cannot be empty");
			goto err_baton;
		}

		{
			v8::Handle<v8::Value> options_obj[1];
			options_obj[0] = args[0]->ToObject();

			v8::Local<v8::String> options_obj_str = v8::Local<v8::String>::Cast(stringify->Call(JSON, 1, options_obj));

			json_t *json_obj_options;
			json_error_t error;

			json_obj_options = json_loads(*(v8::String::Utf8Value)options_obj_str, 0, &error);
			if (json_obj_options) {
				baton->jsn_options = json_obj_options;
				json_object_set_new(json_obj_options, PN_MASTERKEY_STORAGE_ENTROPY, json_string(ibekg->masterkey_storage_entropy));
			} else {
				sprintf(&baton->err_msg[strlen(baton->err_msg)], "JSON error: %s", error.text);
				goto err_baton;
			}

			v8::Local<v8::Value> identitycipher_arr[] = { v8::Array::Cast(*args[2]) };

			v8::Local<v8::String> identitycipher_arr_str = v8::Local<v8::String>::Cast(stringify->Call(JSON, 1, identitycipher_arr));

			json_t *json_arr_identitycipher;

			json_arr_identitycipher = json_loads(*(v8::String::Utf8Value)identitycipher_arr_str, 0, &error);
			if (json_arr_identitycipher) {
				baton->jsn_data_in = json_arr_identitycipher;
			} else {
				sprintf(&baton->err_msg[strlen(baton->err_msg)], "JSON error: %s", error.text);
				goto err_baton;
			}

			err_msg[0] = 0;

			baton->err_code = 0;
		}

err_baton:
		// Schedule our work request with libuv. Here you can specify the functions
		// that should be executed in the threadpool and back in the main thread
		// after the threadpool function completed.
		int status = uv_queue_work(uv_default_loop(), &baton->request, DecryptDataKeyWork, (uv_after_work_cb)DataKeyAfter);
		assert(status == 0);
	}

	return v8::Undefined();
}

void Ibekg::DecryptDataKeyWork(uv_work_t* req) {
	Baton* baton = static_cast<Baton*>(req->data);

	if (baton->err_code) {
		return;
	}

	baton->err_code = 1;
	strcpy(baton->err_msg, "DecryptDataKeyWork error\n");

	// Load Masterkey
	const char *masterkey_storage_entropy = json_string_value(json_object_get(baton->jsn_options, PN_MASTERKEY_STORAGE_ENTROPY));

	unsigned char* masterkey_buf = (unsigned char*)malloc(MASTERKEY_BUF_SIZE);	
	long masterkey_buf_len = LoadBufSecure(REGISTRY_SUBKEY_IBEKG, REGISTRY_MASTERKEY, masterkey_buf, MASTERKEY_BUF_SIZE, masterkey_storage_entropy);
	if (masterkey_buf && masterkey_buf_len == MASTERKEY_BUF_SIZE) {
		HMAC_CTX hmac_ctx;
		HMAC_CTX_init(&hmac_ctx);

		EVP_CIPHER_CTX cipher_ctx;
#ifdef OPENSSL_FIPS_BUILD
		FIPS_cipher_ctx_init(&cipher_ctx);
#else
		//EVP_CIPHER_CTX_init(&cipher_ctx);
#endif

		unsigned char* identity_nonce = (unsigned char*)malloc(NONCE_SIZE);	
		unsigned char* identity_digest = (unsigned char*)malloc(DIGEST_SIZE);	
		unsigned char* identity_iv = (unsigned char*)malloc(IV_SIZE);	
		unsigned char* data_cikey = (unsigned char*)malloc(KEY_SIZE);	
		unsigned char* data_key = (unsigned char*)malloc(KEY_SIZE);	
		unsigned char* identity_tag = (unsigned char*)malloc(TAG_SIZE);	

		char* identity_nonce_str = (char*)malloc(2 * NONCE_SIZE + 1);	
		char* data_key_str = (char*)malloc(2 * KEY_SIZE + 1);	

		char *ibekg_uri = baton->ibekg_uri;
		char *receiver_id = baton->identity_id;

		json_set_alloc_funcs(secure_malloc, secure_free);
		// in
		json_t *json_arr_identitycipher;
		json_t *json_obj_identitycipher;
		json_t *json_obj_identityaad;
		json_t *json_obj_identityaad_rec;
		// out
		json_t *json_arr_identitykey;
		//json_t *json_obj_identitykey;

		json_arr_identitycipher = baton->jsn_data_in;

		baton->jsn_data_out = json_array();
		json_arr_identitykey = baton->jsn_data_out;

		int identitycipher_arr_len = json_array_size(json_arr_identitycipher);

		for (int i = 0; i < identitycipher_arr_len; i++)
		{
			baton->err_code = 1;

			json_obj_identitycipher = json_array_get(json_arr_identitycipher, i);

			const char *identitycipher_datacikey = json_string_value(json_object_get(json_obj_identitycipher, PN_DATA_CIKEY));
			const char *identitycipher_iv = json_string_value(json_object_get(json_obj_identitycipher, PN_IDENTITY_IV));
			const char *identitycipher_tag = json_string_value(json_object_get(json_obj_identitycipher, PN_IDENTITY_TAG));

			json_obj_identityaad = json_object_get(json_obj_identitycipher, PN_IDENTITY_AAD_OBJ);

			const char *identitycipher_aad = json_dumps(json_obj_identityaad, 0);

			int aad_prop_num = json_object_size(json_obj_identityaad);

			const char *identitycipher_nonce = json_string_value(json_object_get(json_obj_identityaad, PN_IDENTITY_NONCE));
			const char *identitycipher_datahash = json_string_value(json_object_get(json_obj_identityaad, PN_DATA_HASH));
			const char *identitycipher_senderid = json_string_value(json_object_get(json_obj_identityaad, PN_SENDER_ID));
			const char *identitycipher_receiverid = json_string_value(json_object_get(json_obj_identityaad, PN_RECEIVER_ID));
			const char *identitycipher_ibekguri = json_string_value(json_object_get(json_obj_identityaad, PN_IBEKG_URI));
			const char *identitycipher_isotimestamp = json_string_value(json_object_get(json_obj_identityaad, PN_ISO_TIMESTAMP));
			const char *identitycipher_productversion = json_string_value(json_object_get(json_obj_identityaad, PN_PRODUCT_VERSION));
			const char *identitycipher_apiversion = json_string_value(json_object_get(json_obj_identityaad, PN_API_VERSION));

			// Check required props
			if (!(strlen((char*)identitycipher_datacikey) == 2 * KEY_SIZE && isHex((char*)identitycipher_datacikey, KEY_SIZE) &&
				strlen((char*)identitycipher_iv) == 2 * IV_SIZE && isHex((char*)identitycipher_iv, IV_SIZE) &&
				strlen((char*)identitycipher_tag) == 2 * TAG_SIZE && isHex((char*)identitycipher_tag, TAG_SIZE) &&
				strlen((char*)identitycipher_nonce) == 2 * NONCE_SIZE && isHex((char*)identitycipher_nonce, NONCE_SIZE))) {
					secure_free((char*)identitycipher_aad);
					continue;
			}

			// Check props count
			int aad_rec_prop_num = 0;

			if (identitycipher_nonce) ++aad_rec_prop_num;
			if (identitycipher_datahash) ++aad_rec_prop_num;
			if (identitycipher_senderid) ++aad_rec_prop_num;
			if (identitycipher_receiverid) ++aad_rec_prop_num;
			if (identitycipher_ibekguri) ++aad_rec_prop_num;
			if (identitycipher_apiversion) ++aad_rec_prop_num;
			if (identitycipher_productversion) ++aad_rec_prop_num;
			if (identitycipher_isotimestamp) ++aad_rec_prop_num;

			if ((aad_prop_num != aad_rec_prop_num) || !identitycipher_nonce || !identitycipher_datahash) {
				secure_free((char*)identitycipher_aad);
				continue;
			}

			// Reconstruct AAD, to preserve AAD properties order
			json_obj_identityaad_rec = json_object();
			if (identitycipher_senderid && identitycipher_receiverid) {
				json_object_set_new(json_obj_identityaad_rec, PN_SENDER_ID, json_string(identitycipher_senderid));
				json_object_set_new(json_obj_identityaad_rec, PN_RECEIVER_ID, json_string(identitycipher_receiverid));
			}
			json_object_set_new(json_obj_identityaad_rec, PN_IDENTITY_NONCE, json_string(identitycipher_nonce));
			json_object_set_new(json_obj_identityaad_rec, PN_DATA_HASH, json_string(identitycipher_datahash));
			if (identitycipher_ibekguri) {
				json_object_set_new(json_obj_identityaad_rec, PN_IBEKG_URI, json_string(identitycipher_ibekguri));
			}
			json_object_set_new(json_obj_identityaad_rec, PN_ISO_TIMESTAMP, json_string(identitycipher_isotimestamp));
			json_object_set_new(json_obj_identityaad_rec, PN_PRODUCT_VERSION, json_string(identitycipher_productversion));
			json_object_set_new(json_obj_identityaad_rec, PN_API_VERSION, json_string(identitycipher_apiversion));

			const char *identitycipher_aad_rec = json_dumps(json_obj_identityaad_rec, 0);

			json_decref(json_obj_identityaad_rec);
			/////

			if ((!identitycipher_receiverid || strcmp(identitycipher_receiverid, receiver_id) == 0) &&
				(!identitycipher_ibekguri || strcmp(identitycipher_ibekguri, ibekg_uri) == 0)) {

					hexToChar(identity_nonce, identitycipher_nonce, 2 * NONCE_SIZE);

					// Identity digest
					if (IdentityDigest(&hmac_ctx,
						baton->err_msg, masterkey_buf,
						identity_nonce,
						receiver_id,
						identity_digest) == 0)
					{
						hexToChar(identity_iv, identitycipher_iv, 2 * IV_SIZE);
						hexToChar(data_cikey, identitycipher_datacikey, 2 * KEY_SIZE);
						hexToChar(identity_tag, identitycipher_tag, 2 * TAG_SIZE);

						// Decrypt
						if (Decrypt(&cipher_ctx, baton->err_msg,
							identity_digest,
							identity_iv,
							identity_tag,
							identitycipher_aad_rec,
							data_cikey,
							data_key,
							identity_nonce,
							identity_nonce_str,
							data_key_str,
							json_arr_identitykey) == 0)
						{
							baton->err_code = 0;
						}
					}
			} else {
				baton->err_code = 0;
			}

			secure_free((char*)identitycipher_aad);
			secure_free((char*)identitycipher_aad_rec);

			if (baton->err_code) {
				break;
			}
		}

#ifdef OPENSSL_FIPS_BUILD
		FIPS_cipher_ctx_cleanup(&cipher_ctx);
#else
		// init/cleanup for every round due to memory leaks
		//EVP_CIPHER_CTX_cleanup(&cipher_ctx);
#endif

#ifdef OPENSSL_FIPS_BUILD
		FIPS_hmac_ctx_cleanup(&hmac_ctx);
#else
		HMAC_CTX_cleanup(&hmac_ctx);
#endif

		memset(identity_nonce_str, 0, 2 * NONCE_SIZE);
		free(identity_nonce_str);
		memset(data_key_str, 0, 2 * KEY_SIZE);
		free(data_key_str);

		memset(identity_nonce, 0, NONCE_SIZE);
		free(identity_nonce);
		memset(identity_digest, 0, DIGEST_SIZE);
		free(identity_digest);
		memset(identity_iv, 0, IV_SIZE);
		free(identity_iv);
		memset(data_cikey, 0, KEY_SIZE);
		free(data_cikey);
		memset(data_key, 0, KEY_SIZE);
		free(data_key);
		memset(identity_tag, 0, TAG_SIZE);
		free(identity_tag);
	} else {
		sprintf(&baton->err_msg[strlen(baton->err_msg)], "Cannot load Masterkey\n");
	}

	memset(masterkey_buf, 0, MASTERKEY_BUF_SIZE);
	free(masterkey_buf);
}

void Ibekg::DataKeyAfter(uv_work_t* req) {
	v8::HandleScope scope;
	Baton* baton = static_cast<Baton*>(req->data);

	if (baton->err_code) {
		v8::Local<v8::Value> err = v8::Exception::Error(v8::String::New(baton->err_msg));

		// Prepare the parameters for the callback function.
		const unsigned argc = 1;
		v8::Local<v8::Value> argv[argc] = { err };

		// Wrap the callback function call in a TryCatch so that we can call
		// node's FatalException afterwards. This makes it possible to catch
		// the exception from JavaScript land using the
		// process.on('uncaughtException') event.
		v8::TryCatch try_catch;
		baton->callback->Call(v8::Context::GetCurrent()->Global(), argc, argv);

		// The callback is a permanent handle, so we have to dispose of it manually.
		DisposeBaton(baton);	

		if (try_catch.HasCaught()) {
			node::FatalException(try_catch);
		}
	} else {
		// In case the operation succeeded, convention is to pass null as the
		// first argument before the result arguments.
		// In case you produced more complex data, this is the place to convert
		// your plain C++ data structures into JavaScript/V8 data structures.

		v8::Local<v8::String> json_arr = v8::String::New("");

		if (baton->jsn_data_out) {
			json_set_alloc_funcs(secure_malloc, secure_free);

			char *json_buff;

			json_buff = json_dumps(baton->jsn_data_out, 0);

			v8::Local<v8::Value> jsn_data_out = v8::String::New(json_buff);

			secure_free(json_buff);

			v8::Local<v8::Value> args[] = { jsn_data_out };
			json_arr = v8::Local<v8::String>::Cast(parse->Call(JSON, 1, args));
		}

		const unsigned argc = 2;

		v8::Local<v8::Value> argv[argc] = {
			v8::Local<v8::Value>::New(v8::Null()),
			//v8::Local<v8::Value>::New(((baton->jsn_data) ? v8::String::New(baton->jsn_data) : v8::String::New("")))
			v8::Local<v8::Value>::New(((baton->jsn_data_out) ? json_arr : v8::Null()))
		};

		// Wrap the callback function call in a TryCatch so that we can call
		// node's FatalException afterwards. This makes it possible to catch
		// the exception from JavaScript land using the
		// process.on('uncaughtException') event.
		v8::TryCatch try_catch;
		baton->callback->Call(v8::Context::GetCurrent()->Global(), argc, argv);

		// The callback is a permanent handle, so we have to dispose of it manually.
		DisposeBaton(baton);	

		if (try_catch.HasCaught()) {
			node::FatalException(try_catch);
		}
	}
}

void DisposeBaton(Baton *baton)
{
	if (baton) {
		if (baton->data_random_buf && baton->data_random_buf_len > 0) {
			memset(baton->data_random_buf, 0, baton->data_random_buf_len);
			free(baton->data_random_buf);
		}

		if (baton->identity_random_buf && baton->identity_random_buf_len > 0) {
			memset(baton->identity_random_buf, 0, baton->identity_random_buf_len);
			free(baton->identity_random_buf);
		}

		if (baton->jsn_options) {
			json_decref(baton->jsn_options);
		}

		if (baton->jsn_data_in) {
			json_decref(baton->jsn_data_in);
		}

		if (baton->jsn_data_out) {
			json_decref(baton->jsn_data_out);
		}

		if (baton->ibekg_uri) {
			memset(baton->ibekg_uri, 0, strlen(baton->ibekg_uri));
			free(baton->ibekg_uri);
		}

		if (baton->identity_id) {
			memset(baton->identity_id, 0, strlen(baton->identity_id));
			free(baton->identity_id);
		}

		memset(baton, 0, sizeof(baton));
		baton->callback.Dispose();
		delete baton;
	}
}

void Ibekg::Init(v8::Handle<v8::Object> target) {
	v8::HandleScope scope;

	v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(New);

	v8::Persistent<v8::FunctionTemplate> s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
	s_ct->InstanceTemplate()->SetInternalFieldCount(1);
	s_ct->SetClassName(v8::String::NewSymbol("Ibekg"));

	NODE_SET_PROTOTYPE_METHOD(s_ct, "getCryptoInfo", GetCryptoInfo);
	NODE_SET_PROTOTYPE_METHOD(s_ct, "setupEngine", SetupEngine);
	NODE_SET_PROTOTYPE_METHOD(s_ct, "createMasterKey", CreateMasterKey);
	NODE_SET_PROTOTYPE_METHOD(s_ct, "encryptDataKey", EncryptDataKey);
	NODE_SET_PROTOTYPE_METHOD(s_ct, "decryptDataKey", DecryptDataKey);

	target->Set(v8::String::NewSymbol("Ibekg"), s_ct->GetFunction());
}
#pragma warning(pop)

void RegisterModule(v8::Handle<v8::Object> target) {
	Ibekg::Init(target);
}

NODE_MODULE(nodejs_ibekg, RegisterModule);
