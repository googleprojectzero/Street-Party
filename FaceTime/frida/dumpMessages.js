// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0

var ind = 0;
var unpaired =[]
var paired = []

send("Hooking VTP_Send");
Interceptor.attach(Module.getExportByName(null, "hwrandom").add(0x10085c), {
    onEnter: function(args) {
                   console.log("pack len " + args[2])
                   var p1 = args[1].readByteArray(args[2].toInt32());
                   var p = new Uint8Array(p1);
                   var ext = p[0]&0x10;
                   var len = 0
                   var pt = p[1]&0x7f;
                   console.log(p[1])
                   console.log(pt)
                   if(pt == 0x7b || pt == 0x68){
                   
                   	if(ext){
                   		len = p[15]*4+4 +12;
                   
                   	}else{
                   		len = 12;
                   	}
                   var this_pair=0;
                   for(var key in paired){
                   	var e = new Uint8Array(paired[key][1]);
                   	if(e.length == p.length - len){
                   		match = true;
                   		for(var i = 0; i < e.length; i++){
                   			if(e[i] != p[i+len]){
                    				match = false
                   			}
                   			if(match){
                   				this_pair = paired[key];
                   			}
                   		}
                   	}
                   }
                   if(!this_pair){
                   	send("PAIR ERROR");
                   }
         
                   var  s = "/out/test" + ind;
                   ind = ind + 1;
                   var f = new File(s, "wb")
                   f.write(Array.prototype.slice.call(p, 0, len));
                   console.log("pair length " + this_pair[0].byteLength)
                   f.write(this_pair[0])
                   f.close()
                   send(s);
		}
	}
});

Interceptor.attach(Module.getExportByName(null, "CCCryptorUpdate"), {
	onEnter: function(args) {
                   
                   var p = args[1].readByteArray(args[2].toInt32());
                   
                   this.unencrypted = p;
                   this.ptr = args[1];
                   this.len = args[2].toInt32();
                   
                   },
	onLeave: function(retval) {
                   
                   var p = this.ptr.readByteArray(this.len);
                   
                   paired.push([this.unencrypted, p])
                   
	}
});
