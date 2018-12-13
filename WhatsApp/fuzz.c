// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

int i = 0;

extern void* apthread(void* dst, const void* src, int *len){

	char path[1024];
	sprintf(path, "/data/data/com.whatsapp/files/t%d", i);
	i++;
	
	FILE* f = fopen(path, "wb");
	char* pack = (char*) src;

	if(i > 50){
		int q = rand() % 100;
		if(q > 80){ // replace one byte
			int ind = rand() % *len;
			if(ind < 12)
				ind = *len -1;
			pack[ind] = rand();
		}
		if(q < 5){ // replace entire packet
			for(int ind = 12; ind < *len; ind++){
				pack[ind] = rand();
			}
        	}

		if((q > 15) && (q < 25)){ // extend or trucate packet
			int l = rand()%1470;
			if (l < 16)
				l = 500;
			*len = l;
        	}
	}

	fwrite(src, 1, *len, f);	
	fclose(f);

	memcpy(dst, src, *len);
	return (void*) dst;
}


