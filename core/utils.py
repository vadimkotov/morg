import sys
import hashlib
import os
import subprocess
from threading import Thread
import base64
import simplejson
import zlib

def get_sha256(data):
    return hashlib.sha256(data).hexdigest()

def write_file(path, data):
    with open(path, "wb") as fd:
        fd.write(data)

def read_file(path):
    with open(path, "rb") as fd:
        return fd.read()
    
def hash_to_dir(hashstr, root="", n=2):
    path = root
    for i in range(0,n*2,2):
        path = os.path.join(path, hashstr[i:i+2])
    return path

def remove(path):
    if os.path.exists(path):
        os.remove(path)
                                                                

def check_output(cmd):
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            
    output = p.stdout.read()
    return output

def start_daemon(target, kwargs=dict()):
    worker = Thread(target=target, kwargs=kwargs)
    worker.setDaemon(True)
    worker.start()

def progress(cnt, total):
    sys.stdout.write( "{} / {} ({:.2f}%)\r".format(cnt, total, float(cnt)/total*100) )
    sys.stdout.flush()


def strip_nulls(str_):
    while str_[-1] == "\00":
        str_ = "".join(list(str_)[:-1])
        if not str_:
            return "<empty_string>"
    return str_

def b64enc(str_):
    return base64.b64encode(str_)

def pack(data):
    return zlib.compress(simplejson.dumps(data))

def unpack(data):
    return simplejson.loads(zlib.decompress(data))
        
