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


extern void* apthread(void* dst, const void* src, int *len){

	char path[1024];
	sprintf(path, "/data/data/com.whatsapp/files/t%d", i);

	
	FILE* f = fopen(path, "wb");
	char* pack = (char*) src;

	fwrite(src, 1, *len, f);	
	fclose(f);

	memcpy(dst, src, *len);
	return (void*) dst;
}


