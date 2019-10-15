# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0

import frida
import sys
import os

vid_index=0
aud_index = 0

def on_message(message, data):
    global vid_index
    global aud_index
    print(message)
    if 'payload' in message:
        payload = message['payload']
        print(payload)
        f = open(payload, 'rb')
        s = f.read()
        f.close()
        pt = s[1]&0x7f;

        if pt == 0x7b:
            f = open("/out/vid" + str(vid_index), 'wb')
            f.write(s)
            f.close()
            vid_index = vid_index + 1
        if pt == 0x68:
            f = open("/out/aud" + str(aud_index), 'wb')
            f.write(s)
            f.close()
            aud_index = aud_index + 1
        os.remove(payload)



session = frida.attach("avconferenced")
code = open('dumpMessages.js', 'r').read()
script = session.create_script(code);
script.on("message", on_message)
script.load()

print("Press Ctrl-C to quit")
sys.stdin.read()
