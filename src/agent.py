#!/usr/bin/env python3

import os
import sys
import json
import getopt
import hashlib
import logging
import random
import ssl

from http import cookies
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler

class SessionList:
	sessions = {}

	def create(self, user):
		rnum = random.getrandbits(128)
		hash = hashlib.sha256()
		hash.update(rnum.to_bytes((rnum.bit_length() // 8) + 1, byteorder="little"))
		self.sessions[user] = str(hash.hexdigest())
		return self.sessions[user]

	def destroy(self, user):
		del self.sessions[user]

	def find(self, token_value):
		token_user = None
		for user, token in self.sessions.items():
			if token == token_value:
				token_user = user
				break
		return token_user

class Statistics:
	def uname(self):
		uname = os.uname()
		return {
			"sysname": uname.sysname,
			"nodename": uname.nodename,
			"release": uname.release,
			"version": uname.version,
			"machine": uname.machine
		}

	def cpu_load(self):
		try:
			cmd = '''grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage }' '''
			fh = os.popen(cmd)
			data = fh.readline()
			fh.close()
			return round(float(data), 1)
		except:
			return 0

	def mem_usage(self):
		try:
			fh = os.popen("free -t -m")
			data = fh.readlines()
			if not data:
				fh.close()
				return 0
			fh.close()

			total, used, free, s, c, a = map(int, data[1].split()[1:])
			if free == 0:
				return 0
			return round((used/total) * 100, 1)
		except:
			return 0

	def build(self):
		stats = {
			"kernelInfo": self.uname(),
			"system": {
				"cpuLoad": self.cpu_load(),
				"memUsage": self.mem_usage()
			}
		}
		return json.dumps(stats).encode("utf-8")

class UCIOperations:
	basecmd = "uci -q"

	def exec(self, cmd):
		fh = os.popen(cmd)
		if not fh:
			return False

		data = fh.readline()
		if fh.close():
			return False

		return data

	def get(self, key):
		return self.exec("{} get {}".format(self.basecmd, key)).strip()

	def set(self, key, val):
		return self.exec("{} set {}={}".format(self.basecmd, key, val))

	def set_list(self, key, list):
		self.exec("{} delete {}".format(self.basecmd, key))
		for val in list:
			self.exec("{} add_list {}={}".format(self.basecmd, key, val))

	def revert(self, cfg):
		return self.exec("{} revert {}".format(self.basecmd, cfg))

	def commit(self, cfg):
		return self.exec("{} commit {}".format(self.basecmd, cfg))

	def modified(self):
		out = self.exec("{} changes".format(self.basecmd))
		if out != False and len(out) > 0:
			return True
		else:
			return False

class Configuration:
	uci = UCIOperations()

	def build(self):
		config = {
			"system": {
				"hostname": self.uci.get("system.@system[0].hostname")
			},
			"network": {
				"ip": self.uci.get("network.wan.ipaddr"),
				"nm": self.uci.get("network.wan.netmask"),
				"gw": self.uci.get("network.wan.gateway"),
				"dns": self.uci.get("network.wan.dns").split(" ", 1)
			}
		}
		return json.dumps(config).encode("utf-8")

	def push(self, data):
		reboot = False

		if "system" in data:
			if "hostname" in data["system"]:
				self.uci.set("system.@system[0].hostname", data["system"]["hostname"])

			if self.uci.modified():
				reboot = True
				self.uci.commit("system")

		if "network" in data:
			if "ip" in data["network"]:
				self.uci.set("network.wan.ipaddr", data["network"]["ip"])
			if "nm" in data["network"]:
				self.uci.set("network.wan.netmask", data["network"]["nm"])
			if "gw" in data["network"]:
				self.uci.set("network.wan.gateway", data["network"]["gw"])
			if "dns" in data["network"]:
				self.uci.set_list("network.wan.dns", data["network"]["dns"])

			if self.uci.modified():
				reboot = True
				self.uci.commit("network")

		if reboot:
			logging.warning("Rebooting!")
			os.system("reboot")

sessions = SessionList()

class AgentHTTPRequestHandler(BaseHTTPRequestHandler):
	stats = Statistics()
	config = Configuration()

	def headers_send(self, http_code):
		self.send_response(http_code)
		self.send_header("Content-type", "application/json")
		self.end_headers()

	def login(self, data):
		if not "username" in data or not "password" in data:
			logging.debug("Missing login params")
			return None

		# Single built-in user for now
		default_user="root"
		default_hash="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"

		if data["username"] != default_user:
			logging.debug("Incorrect username")
			return None

		hash = hashlib.sha256()
		hash.update(bytearray(data["password"], "utf8"))
		if str(hash.hexdigest()) != default_hash:
			logging.debug("Incorrect password")
			return None

		token = sessions.create(data["username"])
		return token

	def session_user_get(self):
		if not "Cookie" in self.headers:
			logging.debug("No cookie")
			return None

		cookie = cookies.SimpleCookie()
		cookie.load(self.headers["Cookie"])
		if not "token" in cookie or not cookie["token"].value:
			logging.debug("No security token")
			return None

		user = sessions.find(cookie["token"].value)
		if not user:
			logging.debug("Token not found")
			return None

		return user

	def authorize(self):
		user = self.session_user_get()
		if not user:
			logging.debug("No such user")
			return False

		logging.debug("Logged in: '{}'".format(user))
		return True

	def logout(self):
		user = self.session_user_get()
		if not user:
			logging.debug("No such user")
			return False

		sessions.destroy(user)

	def do_GET(self):
		logging.debug("Received GET request for {}".format(self.path))

		if self.path == "/login":
			self.headers_send(200)
			resp = { "authorized": self.authorize() }
			self.wfile.write(json.dumps(resp).encode("utf-8"))
			return

		if not self.authorize():
			logging.debug("Unauthorized")
			self.headers_send(403)
			return

		if self.path == "/logout":
			self.logout()
			self.headers_send(200)
		elif self.path == "/config":
			self.headers_send(200)
			self.wfile.write(self.config.build())
		elif self.path == "/stats":
			self.headers_send(200)
			self.wfile.write(self.stats.build())
		else:
			logging.debug("Unsupported URI")
			self.headers_send(404)

	def do_POST(self):
		logging.debug("Received POST request")
		length = int(self.headers["Content-Length"])
		if length == 0:
			logging.debug("Zero post length")
			self.headers_send(400)
			return

		data = self.rfile.read(length).decode("utf-8")
		if not data:
			logging.debug("Failed to read post")
			self.headers_send(400)
			return
		logging.debug(data)

		jsondata = json.loads(data)
		if not jsondata:
			logging.debug("Failed to parse post")
			self.headers_send(400)
			return

		if self.path == "/login":
			token = self.login(jsondata)
			if token:
				self.headers_send(200)
				resp = { "token": token }
				self.wfile.write(json.dumps(resp).encode("utf-8"))
				return
			else:
				logging.debug("Login failed")
				self.headers_send(400)
				return

		if not self.authorize():
			logging.debug("Unauthorized")
			self.headers_send(403)
			return

		if self.path == "/config":
			self.config.push(jsondata)
			self.headers_send(200)
		else:
			logging.debug("Unsupported URI")
			self.headers_send(404)

def agent_run(port):
	httpd = HTTPServer(("", port), AgentHTTPRequestHandler)
	try:
		logging.warning("Agent started on port {}".format(port))
		httpd.socket = ssl.wrap_socket(
			httpd.socket,
			certfile="/etc/agent/agent.pem",
			keyfile="/etc/agent/agent.key",
			server_side=True
		)
		httpd.serve_forever()
	except KeyboardInterrupt:
		logging.warning("Interrupted!")
	httpd.server_close()

def usage():
	name = os.path.basename(__file__)
	sys.stdout.write("usage: %s [OPTION]\n"
		"\t-h --help          show this usage\n"
		"\t-p --port          bind to this port\n" % (name));

if __name__ == "__main__":
	shortopts = "hp:"
	longopts = ["help", "port"]
	try:
		opts, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
	except getopt.GetoptError as e:
		sys.stderr.write("%s\n" % (str(e)))
		usage()
		sys.exit(1)

	port = 443
	for o, v in opts:
		if o in ("-h", "--help"):
			usage()
			sys.exit(0)
		elif o in ("-p", "--port"):
			port = int(v)
			if port <= 0 or port > 65536:
				sys.stderr.write("Invalid port!\n")
				sys.exit(1)
		else:
			assert False, "invalid option(s)"
			usage()
			sys.exit(1)

	agent_run(port)
else:
	sys.stderr.write("This is a script only!")
	sys.exit(1)
