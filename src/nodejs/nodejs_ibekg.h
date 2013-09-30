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

#include "../ibekg.h"

// nonce RND generator generates "Identity nonce", "Data Key", "Identity IV" and "Data IV"
static unsigned char nonce_entropy_buf[RND_ENTROPY_BUF_SIZE] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

//static unsigned char datakey_nonce_buf[RND_NONCE_BUF_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static unsigned char iv_nonce_buf[RND_NONCE_BUF_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

struct Baton {
	// libuv's request struct.
	uv_work_t request;

	// This handle holds the callback function we'll call after the work request
	// has been completed in a threadpool thread. It's persistent so that V8
	// doesn't garbage collect it away while our request waits to be processed.
	// This means that we'll have to dispose of it later ourselves.
	v8::Persistent<v8::Function> callback;

	json_t *jsn_options;
	char *ibekg_uri;
	char *identity_id;

	int data_random_buf_len;
	unsigned char *data_random_buf;

	int identity_random_buf_len;
	unsigned char *identity_random_buf;

	json_t *jsn_data_in;
	json_t *jsn_data_out;

	// Tracking errors that happened in the worker function. You can use any
	// variables you want. E.g. in some cases, it might be useful to report
	// an error number.
	int err_code;
	char err_msg[ERR_MSG_BUF_SIZE];

	// Custom data you can pass through.
	int32_t result;
};

void DisposeBaton(Baton *baton);

typedef struct {
	const unsigned char *ent;
	size_t entlen;
	int entcnt;
	const unsigned char *nonce;
	size_t noncelen;
	int noncecnt;
} DRBG_ENT;

class Ibekg: node::ObjectWrap {
private:
	int engine_setup;
	char ibekg_uri[IBEKG_URI_LEN_MAX + 1];
	char masterkey_storage_entropy[MASTERKEY_STORAGE_ENTROPY_LEN_MAX + 1];
#ifdef OPENSSL_FIPS_BUILD
	DRBG_CTX *nonce_drbg_ctx;
	DRBG_ENT nonce_drbg_ent;
	static size_t drbg_get_entropy(DRBG_CTX *ctx, unsigned char **pout,	int entropy, size_t min_len, size_t max_len);
	static size_t drbg_get_nonce(DRBG_CTX *ctx, unsigned char **pout,	int entropy, size_t min_len, size_t max_len);
#endif
	static void *secure_malloc(size_t size)
	{
		/* Store the memory area size in the beginning of the block */
		void *ptr = malloc(size + 8);
		*((size_t *)ptr) = size;
		return (char *)ptr + 8;
	}

	static void secure_free(void *ptr)
	{
		size_t size;

		ptr = (char *)ptr - 8;
		size = *((size_t *)ptr);

		/*guaranteed_*/memset(ptr, 0, size);
		free(ptr);
	} 
	static v8::Local<v8::Object> JSON;
	static v8::Persistent<v8::Function> stringify;
	static v8::Persistent<v8::Function> parse;
	static void EncryptDataKeyWork(uv_work_t* req);
	static void DecryptDataKeyWork(uv_work_t* req);
	static void DataKeyAfter(uv_work_t* req);
public:
	static void Init(v8::Handle<v8::Object> target);
	Ibekg() { }
	~Ibekg()
	{
		// Destructor is never called. Garbage collection is not guaranteed in V8!
	}
	static v8::Handle<v8::Value> New(const v8::Arguments& args);
	static v8::Handle<v8::Value> GetCryptoInfo(const v8::Arguments& args);
	static v8::Handle<v8::Value> SetupEngine(const v8::Arguments& args);
	static v8::Handle<v8::Value> CreateMasterKey(const v8::Arguments& args);
	static v8::Handle<v8::Value> EncryptDataKey(const v8::Arguments& args);
	static v8::Handle<v8::Value> DecryptDataKey(const v8::Arguments& args);
};
