#!/usr/bin/env python3

import os
import json
import logging

from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler

def get_uname():
	unm = os.uname()
	resp = {
		"sysname": unm.sysname,
		"nodename": unm.nodename,
		"release": unm.release,
		"version": unm.version,
		"machine": unm.machine
	}
	return json.dumps(resp).encode("utf-8")

class AgentHTTPRequestHandler(BaseHTTPRequestHandler):
	def set_response(self):
		self.send_response(200)
		self.send_header("Content-type", "application/json")
		self.end_headers()

	def do_GET(self):
		logging.debug("Received GET request")
		self.set_response()
		self.wfile.write(get_uname())

	def do_POST(self):
		logging.debug("Received POST request")
		content_length = int(self.headers['Content-Length'])
		post_data = self.rfile.read(content_length)
		logging.debug(post_data)
		self.set_response()
		self.wfile.write("{\"status\":\"ok\"}".encode("utf-8"))

def run(server_class=HTTPServer, handler_class=AgentHTTPRequestHandler):
	server_address = ('', 80)
	httpd = server_class(server_address, handler_class)
	try:
		logging.warning("OpenWRT agent started")
		httpd.serve_forever()
	except KeyboardInterrupt:
		logging.warning("Interrupted by keyboard")
	httpd.server_close()

def init():
	logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
	init()
	run()
else:
	print("This is not a module!")
	sys.exit(1)
