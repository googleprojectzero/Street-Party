// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

#define bool int;
#define true 1
#define false 0

char ssrc120[4];
char ssrc124[4];
char ssrc102[4];
char ssrc103[4];

bool s120 = false;
bool s124 = false;
bool s102 = false;
bool s103 = false;


int i = 0;

extern void* apthread(void* dst, const void* src, int *len){

	char path[1024];
	sprintf(path, "/data/data/com.whatsapp/files/t%d", i);
	i++;
	FILE* f = fopen(path, "rb");
	fseek(f, 0L, SEEK_END);
	*len = ftell(f);
	rewind(f);
	char* pack = (char*) src;
	char header[12];
	memcpy(header, pack, 12);
	int ipayload = header[1] & 0x7f;
	switch (ipayload){
		case 120:
			if(!s120){
				s120 = true;
				memcpy(ssrc120, &header[8], 4);
			}
			break;
		case 124:
			if(!s124){
				s124 = true;
				memcpy(ssrc124, &header[8], 4);
			}
			break;
		case 102:
			if(!s102){
				s102 = true;
				memcpy(ssrc102, &header[8], 4);
			}
			break;
		case 103:
			if(!s103){
				s103 = true;
				memcpy(ssrc103, &header[8], 4);
			}
			break;
		default:
			abort();

	}

	char* b = malloc(*len);
	fread(b, 1, *len, f);
	int npayload = b[1] & 0x7f;

	switch(npayload){
		case 120:
			memcpy( b + 8, ssrc120, 4);
			break;
		case 124:
			memcpy( b + 8, ssrc124, 4);
			break;
		case 103:
			memcpy( b + 8, ssrc103, 4);
			break;
		case 102:
			memcpy( b + 8, ssrc102, 4);
			break;
		default:
			abort();
	}
	
	fclose(f);

	memcpy(dst, b, *len);
	return (void*) dst;
}


