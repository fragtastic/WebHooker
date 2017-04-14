#!/usr/bin/env python3

import hashlib, hmac, json, os, sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from subprocess import check_output


class WebHooker(BaseHTTPRequestHandler):

    def do_POST(self):
        config = {}
        with open('webhooker.json') as json_data_file:
            config = json.load(json_data_file)
        xhubsignature = self.headers.get('X-Hub-Signature')
        if xhubsignature is not None:
            sha_type, signature = xhubsignature.split('=')
            if sha_type == 'sha1':
                content_length = int(self.headers.get('Content-Length'))
                if content_length > 0:
                    payloadb = self.rfile.read(content_length)
                    payloads = payloadb.decode('UTF-8')
                    payloadj = json.loads(payloads)
                    repository = payloadj['repository']['full_name']
                    if repository in config:
                        secret = config[repository]['secret']
                        mac = hmac.new(bytes(secret.encode('ascii')), msg=payloadb, digestmod=hashlib.sha1)
                        if str(mac.hexdigest()) == str(signature):            
                            event = self.headers.get('X-Github-Event')
                            if event == 'ping':
                                self.send_complex_response(200, 'Success')
                            elif event == 'push':
                                    branch = payloadj['ref'].split('/')[2]
                                    command = config[repository][event][branch]['command']
                                    try:
                                        body = check_output(command)
                                        self.send_complex_response(200, 'Success', body)
                                    except:
                                        self.send_complex_response(500, 'Something went wrong')
                            else:
                                self.send_complex_response(500, 'Unsupported event')
                        else:
                            self.send_complex_response(403, 'Invalid signature')
                    else:
                        self.send_complex_response(500, 'Unsupported repository')
                else:
                    self.send_complex_response(403, 'Invalid content length')
            else:
                self.send_complex_response(403, 'Unsupported hash type')
        else:
            self.send_complex_response(403, 'No "X-Hub-Signature" signature')

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
