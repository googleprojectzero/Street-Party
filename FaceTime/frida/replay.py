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
  



session = frida.attach("avconferenced")
code = open('replay.js', 'r').read()
script = session.create_script(code);
script.on("message", on_message)
script.load()

print("Press Ctrl-C to quit")
sys.stdin.read()
