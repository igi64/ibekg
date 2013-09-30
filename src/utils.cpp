/*************************************************************************
  Ibekg/utils.cpp

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

#include <assert.h>

#define NULL 0

char *charToHex(char *dst, const char *src, unsigned int n) {
	assert(dst != NULL && src != NULL);

	static const char* hex_lookup = "0123456789ABCDEF";
	for (int i = 0 ; i != n ; i++) {
		*dst++ = hex_lookup[(unsigned char)src[i] >> 4];
		*dst++ = hex_lookup[(unsigned char)src[i] & 0x0F];
	}
	*dst = '\0';

	return dst;
}

unsigned char *hexToChar(unsigned char* dst, const char* src, unsigned int n) {
	assert(dst != NULL && src != NULL);

	for (int i = 0; i != n; i++)	{
		char mask = (i & 1) ? 0xf0 : 0x0f;
		char charval = ((*(src + i) >= '0' && *(src + i) <= '9') ? *(src + i) - '0' : *(src + i) - 'A' + 10);
		dst[i >> 1] = (dst[i >> 1] &mask) | charval << ((i & 1) ? 0 : 4);
	}

	return dst;
}

int isHex(char* c, unsigned int n) {
	assert(c != NULL);

	for (int i = 0; i != n; i++)	{
		if (c[i] < '0' || (c[i] > '9' && c[i] < 'A') || c[i] > 'F')
			return 0;
	}

	return 1;
}
