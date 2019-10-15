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
var aud_thread=0
var vid_thread=0
var audind = 0;
var vidind=0;
var audq = [];
var vidq = []
var first_aud_seq = 0;
var first_aud_seqr = 0;
var first_vid_seq = 0;
var first_vid_seqr = 0;
var save = [];
send("Hooking VTP_Send");

Interceptor.attach(Module.getExportByName(null, "hwrandom").add(0xdd820), {
                   onEnter: function(args) {
                   	var old = aud_thread;
                   	if(aud_thread && old != aud_thread){
                   
                   		console.log("error aud");
                   	}

                   	aud_thread = Process.getCurrentThreadId();
                   
                   
                   	}
                   });

Interceptor.attach(Module.getExportByName(null, "hwrandom").add(0x229c9), {
                   onEnter: function(args) {
                   	var old = vid_thread;
                   	if(vid_thread && old != vid_thread){
                   
                   		console.log("error vid");
                   	}

                   	vid_thread = Process.getCurrentThreadId();
                                  
                   	}
                   });

Interceptor.attach(Module.getExportByName(null, "hwrandom").add(0x10085c), {
    onEnter: function(args) {
                   
                   var p1 = args[1].readByteArray(args[2].toInt32());
                   var p = new Uint8Array(p1, 0, args[2].toInt32());
                   var ext = p[0]&0x10;
                   var len = 0
                   var pt = p[1]&0x7f;

                   if(pt == 0x7b || pt == 0x68){
                   
                   	pack = 0
                   	var is_vid = 0;
                   	if(pt==0x7b){
                   		is_vid=1;
                   		pack = vidq[0];
                   		vidq.shift()
                   	if(first_vid_seq==0){
                   		first_vid_seq = p[2] + (p[3] << 8);
                   		var data = pack[0];
                   		var q = new Uint8Array(pack[0].readByteArray(20), 0, 20);
                   		first_vid_seqr = q[2] + (q[3] << 8);
                   	}
                   }else if(pt == 0x68){
                   	pack = audq[0];
                   	audq.shift()
                   	if(first_aud_seq==0){
                   		first_aud_seq = p[2] + (p[3] << 8);
                   		var data = pack[0];
                   		var q = new Uint8Array(pack[0].readByteArray(20), 0, 20);
                   		first_aud_seqr = q[2] + (q[3] << 8); 
                   	}
                   }else{
         	          console.log("NO PACKET");
         	          return;          
                   }
                   
                   
                   var tdata = pack[0];
                   var data = Memory.alloc(2048);
                   Memory.copy(data, tdata, pack[1]);
                   
                   var q = new Uint8Array(pack[0].readByteArray(20), 0, 20);
                   if(is_vid){
                   	var curr_seq = q[2] + (q[3] << 8);
                   	var seq = first_vid_seq + (curr_seq- first_vid_seqr);
                   	console.log("seq "+seq + " q " + q.byteLength);
                   	data.add(2).writeByteArray([seq&0xff, (seq&0xff00) >> 8]);
                   
                   }else{
                   	var curr_seq = q[2] + (q[3] << 8);
                   	var seq = first_aud_seq + (curr_seq- first_aud_seqr);
                   	console.log("seq "+seq + " q " + q.byteLength);
                   	data.add(2).writeByteArray([seq&0xff, (seq&0xff00) >> 8]);
                   
                   }

                   data.add(4).writeByteArray([q[4], q[5], q[6], q[7], p[8], p[9], p[10], p[11]]);
                   args[1] = data;
                   args[2] = new NativePointer(pack[1]);
           
                   
                   var  s = 0
                   if(is_vid){
                   	s = "/out/vidtest" + vidind;
                   }else{
                   
                   	s = "/out/audtest" + audind;
                   }
                   var f = new File(s, "wb")
                   
                   f.write(data.readByteArray(pack[1]));
                   f.close()
                   save.push(data);
                   console.log("sent" + args[2]);

		}
	}
});

var ccc = Interceptor.attach(Module.getExportByName(null, "CCCryptorUpdate"), {
                   onEnter: function(args) {
                   if(Process.getCurrentThreadId()==aud_thread){
                   	console.log("START AUD " + audind);
                   	var d = ObjC.classes.NSData.dataWithContentsOfFile_("/out/aud" + audind);
                   	audind++;
                   	var realbytes = ptr(d.bytes());
                   	var tmp = realbytes.readByteArray(d.length());
                   	var m = Memory.alloc(d.length());

                            
                   	Memory.copy(m, realbytes, d.length());
                   	var p = new Uint8Array(tmp);
                   	var ext = p[0]&0x10;
                   	var len = 0;
                   	if(ext){
                   		len = p[15]*4+4 +12;
                   
                   	}else{
                   		len = 12;
                   	}
                   
                   

                   	console.log("/out/aud" + audind + " u "+ d);
                   	console.log(m);
                   	console.log(m.add(len));
                   	console.log(d.length()-len);
                   	args[1] = m.add(len);
                   	args[2] = new NativePointer(d.length()-len);
                   	args[3] = m.add(len);
                   	args[4] = new NativePointer(d.length()-len);
                   	console.log(m);

                   	audq.push([m, d.length(), d]);
                
                   	console.log("aud end");
                   }
                   
                   if(Process.getCurrentThreadId()==vid_thread){
                   	console.log("START VID" + vidind);
                   	var d = ObjC.classes.NSData.dataWithContentsOfFile_("/out/vid" + vidind);
                   
                   	vidind++;
                   	var realbytes = ptr(d.bytes());
                   	var tmp = realbytes.readByteArray(d.length());
                   	var m = Memory.alloc(d.length());
                   	Memory.copy(m, realbytes, d.length());
                   	var p = new Uint8Array(tmp);
                   	var ext = p[0]&0x10;
                   	var len = 0;
                   	if(ext){
	                	len = p[15]*4+4 +12;
                   
                   	}else{
	                	len = 12;
                   	}

                   	console.log(d);
                        console.log(m.add(len));
                        console.log(d.length()-len);

                   	console.log(m);
                   	args[1] = m.add(len);
                   	args[2] = new NativePointer(d.length()-len);
                   	args[3] = m.add(len);
                   	args[4] = new NativePointer(d.length()-len);


                   	vidq.push([m, d.length(), d]);
                   	console.log("vid end");
                   }
	}
});
