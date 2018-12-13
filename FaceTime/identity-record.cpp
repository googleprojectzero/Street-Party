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
#include <CommonCrypto/CommonCryptor.h>
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

#define VIDEOPAYLOAD '\x7b'
#define AUDIOPAYLOAD '\x68'

CCCryptorRef   vidRef;
unsigned char* vidkey = 0;
unsigned char* audkey = 0;
unsigned char* vidiv = 0;
unsigned char* audiv = 0;
int msgloop = 0;
unsigned char vidfix = 0;
unsigned char vidfixlo = 0;
unsigned char audfix = 0;
unsigned char audfixlo = 0;
int audkeyread =0;
int vidkeyread = 0;

enum MsgType {NONE, UDPSTUN, DATAGRAMCHANNEL};

static std::atomic_flag spinlock2 = ATOMIC_FLAG_INIT;

ssize_t idensendmsg(int sockfd, const struct msghdr *msg, int flags){
    
    // log the unencrypted packets and then encrypt them
    
    char name2[1024];
    pthread_t         self;
    self = pthread_self();
    pthread_getname_np(self, name2, 1024);
   
    unsigned char* pack = 0; //packet contents
    int size = 0; // packet  size
    enum MsgType msgtype = NONE;
    
    if(strcmp(name2,  "com.apple.avconference.mediaqueue.sendproc") == 0){
        if(msg->msg_iovlen > 1){
            msgtype = UDPSTUN;
            size = msg->msg_iov[1].iov_len;
            pack = (unsigned char*) msg->msg_iov[1].iov_base;
        }
    }
    
    if(strcmp(name2,  "TransportThread Primary") == 0){
        if(msg->msg_iovlen == 1){
            msgtype = DATAGRAMCHANNEL;
            unsigned char* rtptest = (unsigned char*) msg->msg_iov[0].iov_base;
            size = msg->msg_iov[0].iov_len -4;
            if((rtptest[4] == 0x80) || (rtptest[4] == 0x90)){
                pack = rtptest+4;
            }
        }
    }
    
    if(pack){
        while (atomic_flag_test_and_set_explicit(&spinlock2,
                                                 std::memory_order_acquire)) {}

        if(size > 0){
            
            
            /* fuzz here */
            
            char logname[1024];
            sprintf(logname, "/out/extra_%d", msgloop);
            FILE* logfile = 0;
            logfile = fopen(logname, "wb");
            if(!logfile){
                abort(); // if you hit this, you probably forgot to fix the sandbox or create /out
            }
            
            fwrite(pack, size, 1, logfile);
            fclose(logfile);

            int offset = 12; // encryption starts after extensions end
            char h = pack[0];
            if(h & 0x10){
                int extlen = pack[15]; // this won't work if there are more than 255 extensions, but I've never seen more than 5
                offset = offset + 4 + extlen*4;
            }
            if(offset > size){
                offset = size;
            }
            if(vidkeyread == 0 && (pack[1]&0x7f) == VIDEOPAYLOAD){
                FILE* ivfile = fopen("/out/vidiv", "rb");
                if(!ivfile){
                    abort();
                }
                
                vidiv = (unsigned char*)malloc(16);
                fread(vidiv, 16, 1, ivfile);
                fclose(ivfile);
                remove("/out/vidiv");
                
                vidfix = pack[3] ^ ((vidiv)[13]);
                vidfixlo = pack[2] ^ ((vidiv)[12]);
    
                if(!vidkey){
                    
                    FILE* keyfile = fopen("/out/vkey", "rb");
                    if(!keyfile){
                        abort();
                    }
                    vidkey = (unsigned char*)malloc(32);
                    fread(vidkey, 32, 1, keyfile);
                    fclose(keyfile);
                    remove("/out/vkey");
                }
                vidkeyread = 1;
            }
            
            if(audkeyread == 0 && (pack[1]&0x7f) == AUDIOPAYLOAD){
                
                FILE* ivfile = fopen("/out/audiv", "rb");
                
                if(!ivfile){
                    abort();
                }
            
                audiv = (unsigned char*)malloc(16);
                fread(audiv, 16, 1, ivfile);
                fclose(ivfile);
                
                audfix = pack[3] ^ (audiv)[13];
                audfixlo = pack[2] ^ (audiv)[12];
                audkeyread=1;
                
                if(!audkey){
                    FILE* keyfile = fopen("/out/audkey", "rb");
                    if(!keyfile){
                        abort();
                    }
                    
                    audkey = (unsigned char*)malloc(32);
                    fread(audkey, 32, 1, keyfile);
                    fclose(keyfile);
                    remove("/out/audkey");
                }
            }
            
            size_t encryptedsize;
            int payload = pack[1] & 0x7f;
            
            if(payload == VIDEOPAYLOAD){
                unsigned char civ[16];
                memcpy(civ, vidiv, 16);
                civ[13] = pack[3] ^ vidfix;
                civ[12] = pack[2] ^ vidfixlo;
                
                CCCryptorStatus s = CCCryptorCreateWithMode(0, 4, 0, 0, civ, vidkey, 32, 0, 0, 0, 2, &vidRef);
                
                CCCryptorUpdate(vidRef, pack+ offset, size - offset, pack+ offset, size -offset, &encryptedsize);
            
                
                CCCryptorRelease(vidRef);
            
            } else{
                unsigned char civ[16];
                memcpy(civ, audiv, 16);
                civ[13] = pack[3] ^ audfix;
                civ[12] = pack[2] ^ audfixlo;
                
                CCCryptorStatus s = CCCryptorCreateWithMode(0, 4, 0, 0, civ, audkey, 32, 0, 0, 0, 2, &vidRef);
                CCCryptorUpdate(vidRef, pack+ offset, size - offset, pack+ offset, size -offset, &encryptedsize);
                
                CCCryptorRelease(vidRef);
                    
            }

        }else{
            abort();
        }

        if(msgtype==UDPSTUN){
            msg->msg_iov[1].iov_base = pack;
            msg->msg_iov[1].iov_len  = size;
            ((char*)msg->msg_iov[0].iov_base)[2] = (((size) & 0xff00) >> 8);
            ((char*)msg->msg_iov[0].iov_base)[3] = (size) & 0xff; //correct the STUN size
        }else{
            char* p = (char*) malloc(size + 4);
            memcpy(p, (char*)msg->msg_iov[0].iov_base, 4);
            memcpy(p+4, pack, size);
            p[2] = (((size) & 0xff00) >> 8);
            p[3] = (size) & 0xff;
            msg->msg_iov[0].iov_base = p;
            msg->msg_iov[0].iov_len  = size+4;
        }
        
        msgloop++;
        
        atomic_flag_clear_explicit(&spinlock2, std::memory_order_release);
        return sendmsg(sockfd, msg, flags);
    }
    
    return sendmsg(sockfd, msg, flags);

}

DYLD_INTERPOSE(idensendmsg, sendmsg);
