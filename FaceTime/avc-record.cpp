// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include  <CommonCrypto/CommonCryptor.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include "sandbox.h"
#include <pthread.h>
#include <sys/types.h>
#include <atomic>
#include <sys/socket.h>
#include <queue>
#include <map>
#define DYLD_INTERPOSE(_replacment,_replacee) \
__attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

CCCryptorRef    vidRef;
unsigned char* vidkey = 0;
unsigned char* audkey = 0;
unsigned char* vidiv = 0;
unsigned char* audiv = 0;

CCCryptorStatus myCCCryptorCreateWithMode(
                                          CCOperation     op,
                                          CCMode            mode,
                                          CCAlgorithm        alg,
                                          CCPadding        padding,
                                          const void         *iv,
                                          const void         *key,
                                          size_t             keyLength,
                                          const void         *tweak,
                                          size_t             tweakLength,
                                          int                numRounds,
                                          CCModeOptions     options,
                                          CCCryptorRef    *cryptorRef){
    
    dispatch_queue_t queue = dispatch_get_current_queue();
    const char * name =  dispatch_queue_get_label(queue);
    FILE* hFile;
    char name2[1024];
    pthread_t         self;
    self = pthread_self();
    pthread_getname_np(self, name2, 1024);
    
    // The first time an audio or video packet is encrypted, save the key and iv in files for the sendmsg hook
    
    if ((strcmp(name,  "com.apple.VideoConference.videoTransmit") == 0)){

        if(!vidkey){
            char* path = "/out/vkey";
            FILE* keyfile = fopen(path, "wb");
            vidkey = (unsigned char*) malloc(keyLength);
            memcpy(vidkey, key, keyLength);
            fwrite(vidkey, 1, keyLength, keyfile);
            fclose(keyfile);
        }
        
        if(!vidiv){
            char* path = "/out/vidiv";
            FILE* ivfile = fopen(path, "wb");
            vidiv = (unsigned char*) malloc(16);
            memcpy(vidiv, iv, 16);
            fwrite(vidiv, 1, 16, ivfile);
            fclose(ivfile);
        }
    }
    
    if((strcmp(name2,  "com.apple.avconference.packetThread.com.apple.AVConference.auio") == 0)){
        
        if(!audkey){
            char* path = "/out/audkey";
            FILE* keyfile = fopen(path, "wb");
            audkey = (unsigned char*)malloc(keyLength);
            memcpy(audkey, key, keyLength);
            fwrite(audkey, 1, keyLength, keyfile);
            fclose(keyfile);
        }
        
        if(!audiv){
            char* path = "/out/audiv";
            FILE* ivfile = fopen(path, "wb");
            audiv = (unsigned char*)malloc(keyLength);
            memcpy(audiv, iv, 16);
            fwrite(audiv, 1, 16, ivfile);
            fclose(ivfile);
        }

    }
    
    CCCryptorStatus s = CCCryptorCreateWithMode(op, mode, alg, padding, iv, key, keyLength, tweak, tweakLength, numRounds, options, cryptorRef);
    
    return s;
    
}

DYLD_INTERPOSE(myCCCryptorCreateWithMode, CCCryptorCreateWithMode);


int loop = 0;

static std::atomic_flag spinlock = ATOMIC_FLAG_INIT;
CCCryptorStatus mycryptor(
	CCCryptorRef cryptorRef,
	const void *dataIn,
	size_t dataInLength,
	void *dataOut,				
	size_t dataOutAvailable,
	size_t *dataOutMoved) {

    // prevent encryption so the packet can be logged, encryption will be applied in sendmsg loop
    
    while (atomic_flag_test_and_set_explicit(&spinlock,
                                             std::memory_order_acquire)) { // this lock is so that log files can be added to this function if needed
    }
    
    dispatch_queue_t queue = dispatch_get_current_queue();
    const char * name =  dispatch_queue_get_label(queue);
    char name2[1024];
    pthread_t         self;
    self = pthread_self();
    pthread_getname_np(self, name2, 1024);
    
    int is_rtp = 0;
    CCCryptorStatus status;

    if ((strcmp(name,  "com.apple.VideoConference.videoTransmit") == 0)){
        is_rtp = 1;
    }
    
    if ((strcmp(name2,  "com.apple.avconference.packetThread.com.apple.AVConference.auio") == 0)){
        is_rtp = 1;
    }

    if(is_rtp){
        
        char* unencrypted = (char*)malloc(dataInLength);
        memcpy(unencrypted, dataIn, dataInLength);
        
        status = CCCryptorUpdate(cryptorRef, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved); // call for side-effects
        
        memcpy(dataOut, unencrypted, dataInLength);
    }else{
        status = CCCryptorUpdate(cryptorRef, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
    }
    
    atomic_flag_clear_explicit(&spinlock, std::memory_order_release);
    return status;
    
}

DYLD_INTERPOSE(mycryptor, CCCryptorUpdate);
