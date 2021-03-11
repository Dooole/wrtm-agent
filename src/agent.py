#!/usr/bin/env python3

import os
import json
import logging
import random

from http import cookies
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler

sessions = {}

def uname_get():
	unm = os.uname()
	uname = {
		"sysname": unm.sysname,
		"nodename": unm.nodename,
		"release": unm.release,
		"version": unm.version,
		"machine": unm.machine
	}
	return uname

def stats_build():
	stats = {
		"kernelInfo": uname_get(),
		"system": {
			"cpuLoad": random.randint(30,50),
			"memUsage": random.randint(25,35)
		},
		"network": {
			"rxRate": random.randint(50,60),
			"txRate": random.randint(50,60)
		}
	}
	return json.dumps(stats).encode("utf-8")

def config_build():
	config = {
		"system": {
			"hostname": "openwrt"
		},
		"network": {
			"ip": "192.168.56.56",
			"nm": "255.255.255.0",
			"gw": "192.168.56.1",
			"dns": ["8.8.8.8", "8.8.4.4"]
		}
	}
	return json.dumps(config).encode("utf-8")

def config_push(data):
	logging.debug("Config push")
	return True

def login(data):
	token = ""
	if not "username" in data or not "password" in data:
		logging.debug("Missing login params")
		return token

	# TODO: hash based/passwd auth!
	if data["username"] != "root" or data["password"] != "root":
		logging.debug("Incorrect user or password")
		return token

	token = str(random.getrandbits(128))
	sessions[data["username"]] = token
	return token

def authorize(req):
	if not "Cookie" in req.headers:
		logging.debug("No cookie")
		return False

	cookie = cookies.SimpleCookie()
	cookie.load(req.headers["Cookie"])
	if not "token" in cookie or not cookie["token"].value:
		logging.debug("No security token")
		return False

	found = False
	for user, token in sessions.items():
		if token == cookie["token"].value:
			found = True
			break

	if not found:
		logging.debug("No such token")
	return found

def logout(req):
	if not "Cookie" in req.headers:
		logging.debug("No cookie")
		return

	cookie = cookies.SimpleCookie()
	cookie.load(req.headers["Cookie"])
	if not "token" in cookie or not cookie["token"].value:
		logging.debug("No security token")
		return

	token_user = ""
	for user, token in sessions.items():
		if token == cookie["token"].value:
			token_user = user
			break

	if not token_user:
		logging.debug("No such token")
		return

	del sessions[token_user]

class AgentHTTPRequestHandler(BaseHTTPRequestHandler):
	def set_response(self, code):
		self.send_response(code)
		self.send_header("Content-type", "application/json")
		self.end_headers()

	def do_GET(self):
		logging.debug("Received GET request for {}".format(self.path))

		if not authorize(self):
			logging.debug("Unauthorized")
			self.set_response(403)
			return

		if self.path == "/logout":
			logout(self)
			self.set_response(200)
		elif self.path == "/config":
			self.set_response(200)
			self.wfile.write(config_build())
		elif self.path == "/stats":
			self.set_response(200)
			self.wfile.write(stats_build())
		else:
			logging.debug("Unsupported URI")
			self.set_response(404)

	def do_POST(self):
		logging.debug("Received POST request")
		length = int(self.headers["Content-Length"])
		if length == 0:
			logging.debug("Zero post length")
			self.set_response(400)
			return

		data = self.rfile.read(length).decode("utf-8")
		if not data:
			logging.debug("Failed to read post")
			self.set_response(400)
			return
		logging.debug(data)

		jsondata = json.loads(data)
		if not jsondata:
			logging.debug("Failed to parse post")
			self.set_response(400)
			return

		# login is public
		if self.path == "/login":
			token = login(jsondata)
			if token:
				self.set_response(200)
				resp = { "token": token }
				self.wfile.write(json.dumps(resp).encode("utf-8"))
				return
			else:
				logging.debug("Login failed")
				self.set_response(400)
				return

		if not authorize(self):
			logging.debug("Unauthorized")
			self.set_response(403)
			return

		if self.path == "/config":
			config_push(jsondata)
			self.set_response(200)
		else:
			logging.debug("Unsupported URI")
			self.set_response(404)

def run(server_class=HTTPServer, handler_class=AgentHTTPRequestHandler):
	server_address = ("", 80)
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
