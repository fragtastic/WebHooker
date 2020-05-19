#!/usr/bin/env python

import hashlib
import hmac
import json
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from subprocess import check_output


class WebHooker(BaseHTTPRequestHandler):

    def do_POST(self):
        config = {}
        with open('webhooker.json') as json_data_file:
            config = json.load(json_data_file)
        xhubsignature = self.headers.get('X-Hub-Signature')
        print(self.headers)
        if xhubsignature is None:
            return self.send_complex_response(403, 'No "X-Hub-Signature" signature')
        sha_type, signature = xhubsignature.split('=')
        print(sha_type, signature)
        if sha_type != 'sha1':
            return self.send_complex_response(403, 'Unsupported hash type')
        content_length = int(self.headers.get('Content-Length'))
        if content_length <= 0:
            return self.send_complex_response(403, 'Invalid content length')
        payloadb = self.rfile.read(content_length)
        payloads = payloadb.decode('UTF-8')
        # print(payloads)
        payloadj = json.loads(payloads)
        repository = payloadj['repository']['full_name']
        if repository not in config:
            return self.send_complex_response(500, 'Unsupported repository')
        secret = config[repository]['secret']
        mac = hmac.new(bytes(secret.encode('ascii')), msg=payloadb, digestmod=hashlib.sha1)
        if str(mac.hexdigest()) != str(signature):
            return self.send_complex_response(403, 'Invalid signature')
        event = self.headers.get('X-Github-Event')
        if event == 'ping':
            return self.send_complex_response(200, 'Success')
        elif event == 'push':
            branch = payloadj['ref'].split('/')[2]
            command = config[repository][event][branch]['command']
            try:
                body = check_output(command).decode('utf-8')
                print(f'{command}: {body}')
                return self.send_complex_response(200, 'Success', body)
            except Exception as e:
                return self.send_complex_response(500, e)
        else:
            return self.send_complex_response(500, 'Unsupported event')

    def send_complex_response(self, code, message, body=None):
        self.send_response(code, message)
        self.end_headers()
        if body is None:
            body = message
        self.wfile.write(body.encode("utf-8"))

# TODO - arguments, listen address, port number, config file?
if __name__ == '__main__':
    httpd = HTTPServer(('127.0.0.1', 8723), WebHooker)
    httpd.serve_forever()
