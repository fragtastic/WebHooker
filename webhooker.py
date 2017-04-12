#!/usr/bin/env python3

import hashlib, hmac, json, os, sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from subprocess import Popen


class WebHooker(BaseHTTPRequestHandler):

    def do_POST(self):
        config = {}
        with open('webhooker.json') as json_data_file:
            config = json.load(json_data_file)
        xhubsignature = self.headers.get('X-Hub-Signature')
        if xhubsignature is None:
            self.send_response(403, 'No signature')
        sha_type, signature = xhubsignature.split('=')
        if sha_type != 'sha1':
            self.send_response(403, 'Unsupported hash type')
        content_length = int(self.headers.get('Content-Length'))
        payloadb = self.rfile.read(content_length)
        payloads = payloadb.decode('UTF-8')
        payloadj = json.loads(payloads)

        repository = payloadj['repository']['full_name']
        secret = config[repository]['secret']
        mac = hmac.new(bytes(secret.encode('ascii')), msg=payloadb, digestmod=hashlib.sha1)
        if not str(mac.hexdigest()) == str(signature):
            self.send_response(403, 'Invalid signature')

        event = self.headers.get('X-Github-Event')
        if event == 'ping':
            self.send_response(200, '{"msg": "pong"}')
        elif event == 'push':
            branch = payloadj['ref'].split('/')[2]
            command = config[repository][event][branch]['command']
            try:
                Popen(command).wait()
                self.send_response(200, '{"msg": "success"}')
            except:
                self.send_response(500, '{"msg": "fail"}')
        self.end_headers()

# TODO - arguments, listen address, port number, config file?
if __name__ == '__main__':
    httpd = HTTPServer(('127.0.0.1', 8723), WebHooker)
    httpd.serve_forever()
