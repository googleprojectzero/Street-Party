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

#define VIDEOPAYLOAD '\x7b'
#define AUDIOPAYLOAD '\x68'

CCCryptorRef    vidRef;
unsigned char* vidkey = 0;
unsigned char* audkey = 0;
unsigned char* vidiv = 0;
unsigned char* audiv = 0;
int msgloop = 0;
int seq = 0;
int hseq = 0;
int seq1 = 0;
int hseq1 = 0;
int sinit = 0;
int vinit = 0;
int ainit1 = 0;
char vidssrc[4];
char assrc1[4];
char vidseq[2];
char aseq1[2];
unsigned char vidfix = 0;
unsigned char vidfixlo = 0;
unsigned char audfix = 0;
unsigned char audfixlo = 0;
int audkeyread =0;
int vidkeyread = 0;

enum MsgType {NONE, UDPSTUN, DATAGRAMCHANNEL};

static std::atomic_flag spinlock2 = ATOMIC_FLAG_INIT;

ssize_t idensendmsg(int sockfd, const struct msghdr *msg, int flags){
    
    char name2[1024];
    pthread_t         self;
    self = pthread_self();
    pthread_getname_np(self, name2, 1024);
   
    unsigned char* pack = 0; //packet contents
    enum MsgType msgtype = NONE;
    
    if(strcmp(name2,  "com.apple.avconference.mediaqueue.sendproc") == 0){
        if(msg->msg_iovlen > 1){
            msgtype = UDPSTUN;
            pack = (unsigned char*) msg->msg_iov[1].iov_base;
        }
    }
    
    if(strcmp(name2,  "TransportThread Primary") == 0){
        if(msg->msg_iovlen == 1){
            msgtype = DATAGRAMCHANNEL;
            char* rtptest = (char*) msg->msg_iov[0].iov_base;
            if((rtptest[4] == '\x80') || (rtptest[4] == '\x90')){
                 char payload = rtptest[5] &0x7f;
                 if((payload!=AUDIOPAYLOAD) && (payload!=VIDEOPAYLOAD)){
                     return 100;
                 }
                pack = (unsigned char*) rtptest+4;
            }
        }
    }
    
    
    if(pack){
        while (atomic_flag_test_and_set_explicit(&spinlock2,
                                                 std::memory_order_acquire)) {}

        if(msgtype != NONE){

            if(!sinit){ // get the SSRCs and initial seq numbers from the first packets
                char payload = pack[1];
                payload = payload & 0x7f;
                if (payload == VIDEOPAYLOAD){
                    if(!vinit){
                        memcpy(&vidssrc, pack + 8, 4);
                        memcpy(&vidseq, pack + 2, 2);
                        if ( seq == 0){
                            ((char*)&seq)[0] = pack[3];
                            ((char*)&seq)[1] = pack[2];
                        }
                        vinit = 1;
                    }
                } else if ( payload == AUDIOPAYLOAD){
                    if(!ainit1){
                        if ( seq1 == 0){
                            ((char*)&seq1)[0] = pack[3];
                            ((char*)&seq1)[1] = pack[2];
                            
                        }
                        memcpy(&assrc1, pack + 8, 4);
                        memcpy(&aseq1, pack + 2, 2);
                        ainit1 = 1;
                    }
                }
                if(vinit==1 && ainit1 == 1){
                    sinit = 1;
                }
                    
            }
            
            char logname[1024];
            sprintf(logname, "/out/extra_%d", msgloop);
            FILE* logfile = 0;
            logfile = fopen(logname, "rb");
            if(!logfile){
                abort(); // can't find input file
            }
            size_t loggedsize = 0;
            unsigned char* loggedpacket = 0;
            fseek(logfile, 0L, SEEK_END);
            loggedsize = ftell(logfile);
            rewind(logfile);
            loggedpacket = (unsigned char*)malloc(loggedsize);
            fread(loggedpacket, loggedsize, 1, logfile);
            fclose(logfile);

           unsigned char* newpacket = (unsigned char*) malloc(loggedsize);

            newpacket[0] = loggedpacket[0]; //header
            newpacket[1] = loggedpacket[1]; //payload type
            newpacket[4] = loggedpacket[4]; //timestamp
            newpacket[5] = loggedpacket[5]; //timestamp
            newpacket[6] = loggedpacket[6]; //timestamp
            newpacket[7] = loggedpacket[7]; //timestamp

            // correct SSRC and sequence number of packet
            
            char loggedpayload = loggedpacket[1] & 0x7f;
            if( loggedpayload == VIDEOPAYLOAD){
                if(seq==0){
                    atomic_flag_clear_explicit(&spinlock2, std::memory_order_release);
                    return 100;
                }
                if ( hseq == 0){
                    ((char*)&hseq)[0] = loggedpacket[3];
                    ((char*)&hseq)[1] = loggedpacket[2];
                }
                
                int cseq = 0;
                ((char*)&cseq)[0] = loggedpacket[3];
                ((char*)&cseq)[1] = loggedpacket[2];
                int nseq = seq + (cseq - hseq);
                newpacket[3] = nseq & 0xff;
                newpacket[2] = (nseq & 0xff00) >> 8;
                memcpy(newpacket+8, &vidssrc, 4);
            }else{
                if(seq1==0){
                    atomic_flag_clear_explicit(&spinlock2, std::memory_order_release);
                    return 100;
                }
                if ( hseq1 == 0){
                    ((char*)&hseq1)[0] = loggedpacket[3];
                    ((char*)&hseq1)[1] = loggedpacket[2];
                }
                int cseq = 0;
                ((char*)&cseq)[0] = loggedpacket[3];
                ((char*)&cseq)[1] = loggedpacket[2];
                int nseq = seq1 + (cseq - hseq1);
                newpacket[3] = nseq & 0xff;
                newpacket[2] = (nseq & 0xff00) >> 8;
                memcpy(newpacket+8, &assrc1, 4);
            }
                    
            memcpy(newpacket+12, loggedpacket+12, loggedsize - 12);

            int offset = 12;
            char h = newpacket[0];
            if(h & 0x10){
                int extlen = newpacket[15];
                offset = offset + 4 + extlen*4;
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
                vidfix = pack[3] ^ (vidiv)[13];
                vidfixlo = pack[2] ^ (vidiv)[12];
                if(!vidkey){
                    FILE* keyfile = fopen("/out/vidkey", "rb");
                    if(!keyfile){
                        abort();
                    }
                    vidkey = (unsigned char*)malloc(32);
                    fread(vidkey, 32, 1, keyfile);
                    fclose(keyfile);
                    remove("/out/vidkey");
                }
                vidkeyread = 1;
            }
      
            if(audkeyread == 0 && (pack[1]&0x7f)==AUDIOPAYLOAD){
                FILE* ivfile = fopen("/out/audiv", "rb");
                if(!ivfile){
                    abort();
                }
                audiv = (unsigned char*)malloc(16);
                fread(audiv, 16, 1, ivfile);
                fclose(ivfile);
                remove("/out/audiv");
                
                audfix = pack[3] ^ audiv[13];
                audfixlo = pack[2] ^ audiv[12];
            
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
            char newpayload = newpacket[1] & 0x7f;
            if(newpayload == VIDEOPAYLOAD){
                unsigned char civ[16];
                if(vidkeyread == 0){
                    atomic_flag_clear_explicit(&spinlock2, std::memory_order_release);
                    return 100;
                }else{
                    memcpy(civ, vidiv, 16);
                    civ[13] = newpacket[3] ^ vidfix;
                    civ[12] = newpacket[2] ^ vidfixlo;
                }
                
                CCCryptorStatus s = CCCryptorCreateWithMode(0, 4, 0, 0, civ, vidkey, 32, 0, 0, 0, 2, &vidRef);
                
                CCCryptorUpdate(vidRef, newpacket+ offset, loggedsize - offset, newpacket+ offset, loggedsize -offset, &encryptedsize);
            
                CCCryptorRelease(vidRef);
                
            } else{
                unsigned char civ[16];
                if(audkeyread==0){
                    atomic_flag_clear_explicit(&spinlock2, std::memory_order_release);
                    return 100;
                }else{
                    memcpy(civ, audiv, 16);
                    civ[13] = newpacket[3] ^ audfix;
                    civ[12] = newpacket[2] ^ audfixlo;
                }

                CCCryptorStatus s = CCCryptorCreateWithMode(0, 4, 0, 0, civ, audkey, 32, 0, 0, 0, 2, &vidRef);
                
                CCCryptorUpdate(vidRef, newpacket+offset, loggedsize - offset, newpacket+offset, loggedsize-offset, &encryptedsize);
                
                CCCryptorRelease(vidRef);
                    
            }
            
            if(msgtype==UDPSTUN){
                msg->msg_iov[1].iov_base = newpacket;
                msg->msg_iov[1].iov_len  = loggedsize;
                ((char*)msg->msg_iov[0].iov_base)[2] = (((loggedsize) & 0xff00) >> 8);
                ((char*)msg->msg_iov[0].iov_base)[3] = (loggedsize) & 0xff; //correct the STUN size
            }else{
                char* p = (char*) malloc(loggedsize + 4);
                memcpy(p, pack-4, 4);
                memcpy(p+4, newpacket, loggedsize);
                p[2] = (((loggedsize) & 0xff00) >> 8);
                p[3] = (loggedsize) & 0xff;
                msg->msg_iov[0].iov_base = p;
                msg->msg_iov[0].iov_len  = loggedsize+4;
            }

        }else{
            abort();
        }
        msgloop++;
        atomic_flag_clear_explicit(&spinlock2, std::memory_order_release);
        return sendmsg(sockfd, msg, flags);
        }
    
    return sendmsg(sockfd, msg, flags);

}

DYLD_INTERPOSE(idensendmsg, sendmsg);
