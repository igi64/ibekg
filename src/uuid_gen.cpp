/*************************************************************************
  Ibekg/uuid_gen.cpp

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

#ifdef _WIN32
#include <windows.h>

long GetUUID(char* value) {
	GUID guid;
	long rslt = CoCreateGuid(&guid);

	static const char* hex_lookup = "0123456789ABCDEF";
	static const unsigned char i_lookup[sizeof(guid)] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
	static const unsigned char j_lookup[sizeof(guid)] = {0,0,0,1,0,1,0,1,0,1,0,0,0,0,0,0};

	int j = 0;
	for (int i = 0; i != sizeof(guid); i++) {
		value[j++] = hex_lookup[((unsigned char*)(&guid))[i_lookup[i]] >> 4];
		value[j++] = hex_lookup[((unsigned char*)(&guid))[i_lookup[i]] & 0x0F];
		j += j_lookup[i];
	}

	return rslt;
}
#else
#include <stdlib.h>
#include <time.h>

long GetUUID(char* value) {
	char guid[16];

	srand(time(NULL));

	for (int i = 0; i != sizeof(guid); i++) {
		guid[i] = rand() % 255;
	}

	guid[6] = 0x40 | (guid[6] & 0xf);
	guid[8] = 0x80 | (guid[8] & 0x3f);

	static const char* hex_lookup = "0123456789ABCDEF";
	static const unsigned char j_lookup[sizeof(guid)] = {0,0,0,1,0,1,0,1,0,1,0,0,0,0,0,0};

	int j = 0;
	for (int i = 0; i != sizeof(guid); i++) {
		value[j++] = hex_lookup[((unsigned char*)(&guid))[i] >> 4];
		value[j++] = hex_lookup[((unsigned char*)(&guid))[i] & 0x0F];
		j += j_lookup[i];
	}

	return 0;
}
#endif
