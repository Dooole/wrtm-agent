#!/usr/bin/env python3

import os
import sys
import json
import getopt
import hashlib
import logging
import time

from http.client import HTTPConnection

#stores cmd arguments
CTX = {
	"timeout": 10, # Seconds.
	"interval": 5, # Seconds.
	"server": "127.0.0.1",
	"port": 80,
	"password": ""
}

class Statistics: #class to collect device stats, manily based on pipe to system shell commands 
	def __init__(self, status):
		self.status = status
		self.uname = os.uname() #py builtin method which returns general system info

	def mac_address(self):
		try:
			fh = open("/sys/class/net/eth0/address", "r") #directly reads mac addr from file
			data = fh.readline()
			fh.close()
			return data.strip()
		except:
			logging.error("Failed to read mac file")
			return "00:00:00:00:00:00"

	def cpu_load(self):
		try:
			cmd = '''grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage }' ''' #exsecutes grep and awk in shell to get cpu load as string
			fh = os.popen(cmd)
			data = fh.readline()
			fh.close()
			return round(float(data), 1) #converts string to floating point number with 1 digit precision
		except:
			logging.error("Failed to exe cpu load command")
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
			logging.error("Failed to exe mem usage command")
			return 0

	def get(self):
		model = "{} {} {} {}".format(
			self.uname.sysname,
			self.uname.nodename,
			self.uname.release,
			self.uname.machine
		)
		stats = {
			"system": {
				"model": model,
				"status": self.status,
				"mac": self.mac_address(),
				"cpu_load": self.cpu_load(),
				"memory_usage": self.mem_usage(),
			}
		}
		return stats

class UCIOperations: #class to set, get and delete uci config , implemented as a wraper of uci shell command
	basecmd = "uci -q"

	def exec(self, cmd):
		fh = os.popen(cmd) #opens pipe to the shell, exsecutes uci command and returns result
		if not fh:
			logging.error("Failed to open uci pipe: {}".format(cmd))
			return False

		data = fh.readline()
		fh.close()
		return data

	def get(self, key):
		return self.exec("{} get {}".format(self.basecmd, key)).strip()

	def set(self, key, val):
		return self.exec("{} set {}={}".format(self.basecmd, key, val))

	def set_list(self, key, list):
		oldlist = self.get(key).split(" ", 1)
		self.exec("{} delete {}".format(self.basecmd, key))
		idx = 0
		for val in list:
			if idx < len(oldlist):
				if val == True:
					self.exec("{} add_list {}={}".format(self.basecmd, key, oldlist[idx]))
				else:
					self.exec("{} add_list {}={}".format(self.basecmd, key, val))
				idx = idx + 1
			elif val != True:
				self.exec("{} add_list {}={}".format(self.basecmd, key, val))

	def add_list(self, key, list):
		for val in list:
			self.exec("{} add_list {}={}".format(self.basecmd, key, val))

	def revert(self, cfg):
		return self.exec("{} revert {}".format(self.basecmd, cfg))

	def commit(self, cfg):
		return self.exec("{} commit {}".format(self.basecmd, cfg))

	def modified(self):
		out = self.exec("{} changes".format(self.basecmd))
		if len(out) > 0:
			return True
		else:
			return False

#class for config collection and application
class Configuration:
	uci = UCIOperations() #obj to manipulate openwrt uci config (native config)

	def get(self): #collects current uci config into py dict
		dns =  self.uci.get("network.wan.dns").split(" ", 1)
		dns1 = "0.0.0.0"
		if 0 < len(dns):
			dns1 = dns[0]
		dns2 = "0.0.0.0"
		if 1 < len(dns):
			dns2 = dns[1]

		config = {
			"system": {
				"hostname": self.uci.get("system.@system[0].hostname")
			},
			"network": {
				"ip": self.uci.get("network.wan.ipaddr"),
				"netmask": self.uci.get("network.wan.netmask"),
				"gateway": self.uci.get("network.wan.gateway"),
				"dns1": dns1,
				"dns2": dns2,
			}
		}
		return config

	def set(self, cfg): #parses py dict and applies it as new uci config
		reboot = False

		if "system" in cfg:
			if "hostname" in cfg["system"]:
				self.uci.set("system.@system[0].hostname", cfg["system"]["hostname"])

			if self.uci.modified():
				reboot = True
				logging.warning("System config modified")
				self.uci.commit("system")
			else:
				logging.warning("System config not changed")

		if "network" in cfg:
			if "ip" in cfg["network"]:
				self.uci.set("network.wan.ipaddr", cfg["network"]["ip"])
			if "netmask" in cfg["network"]:
				self.uci.set("network.wan.netmask", cfg["network"]["netmask"])
			if "gateway" in cfg["network"]:
				self.uci.set("network.wan.gateway", cfg["network"]["gateway"])
			if "dns1" in cfg["network"]:
				self.uci.set_list("network.wan.dns", [cfg["network"]["dns1"], True])
			if "dns2" in cfg["network"]:
				self.uci.set_list("network.wan.dns",[True, cfg["network"]["dns2"]])
		
			if self.uci.modified():
				reboot = True
				logging.warning("Network config modified")
				self.uci.commit("network")
			else:
				logging.warning("Network config not changed")

		if reboot:
			logging.warning("Rebooting!")
			os.system("reboot")

#input is python dict. function serializes this dict, sends to provided server, 
#waits for response, deserializes response to dict, and returns dict
def server_send(datadict):
	try:
		reqdata = json.dumps(datadict).encode("utf-8")
	except:
		logging.error("Failed to serialize request data")
		return None

	headers = {"Content-type": "application/json"}
	conn = HTTPConnection(CTX["server"], CTX["port"], CTX["timeout"])
	try:
		conn.request("POST", "/wrtapp/provisioning", reqdata, headers)
	except:
		logging.error("Failed to send request")
		conn.close()
		return None

	response = conn.getresponse()
	if response.status != 200:
		logging.error("Server returned error: {}".format(str(response.status)))
		conn.close()
		return None

	respdata = response.read()
	if not respdata:
		logging.error("Failed to read response data")
		conn.close()
		return None

	conn.close()
	try:
		resp = json.loads(respdata.decode("utf-8"))
		return resp
	except:
		logging.error("Failed to deserialize response data")
		return None

def calculate_token():
	hash = hashlib.sha256()
	hash.update(bytearray(CTX["password"], "utf8"))
	return hash.hexdigest()

#collect device current config and stats , sends to server 
#parse response, set new config if exsits
def provisioning_sync():
	config = Configuration()
	initStats = Statistics("OK") 

	reqdict = {
		"statistics": initStats.get(),
		"configuration": config.get(),
		"token": calculate_token(),
	}

	respdict = server_send(reqdict)
	if not respdict:
		logging.warning("No data from server")
		return
	if not "configuration" in respdict:
		return

	logging.warning("Received new configuration")
	# Update device state on backend.
	interimStats = Statistics("CONFIGURING")
	reqdict["statistics"] = interimStats.get()
	server_send(reqdict)

	# Apply new config
	config.set(respdict["configuration"])

def agent_run():
	try:
		logging.warning("Agent started, server {}:{}".format(CTX["server"], CTX["port"]))

		while True:
			try:
				provisioning_sync() #main agent function
			except:
				logging.error("Failed to sync provisioning")
			time.sleep(CTX["interval"])

	except KeyboardInterrupt:
		logging.warning("Interrupted!")

def usage():
	name = os.path.basename(__file__)
	sys.stdout.write("usage: %s [OPTION]\n"
		"\t-h --help          show this usage\n"
		"\t-s --server        server IP/hostname\n"
		"\t-p --port          server port\n"
		"\t-w --password      server password\n"
		"\t-i --interval      update interval\n" % (name));

#script start, exit if module
if __name__ == "__main__":
	shortopts = "hs:p:w:i:"
	longopts = ["help", "server", "port", "password", "interval"]
	try:
		opts, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
	except getopt.GetoptError as e:
		sys.stderr.write("%s\n" % (str(e)))
		usage()
		sys.exit(1)

	for o, v in opts:
		if o in ("-h", "--help"):
			usage()
			sys.exit(0)
		elif o in ("-s", "--server"):
			server = str(v)
			if len(server) == 0:
				sys.stderr.write("Invalid server!\n")
				sys.exit(1)
			CTX["server"] = server
		elif o in ("-p", "--port"):
			port = int(v)
			if port <= 0 or port > 65536:
				sys.stderr.write("Invalid port!\n")
				sys.exit(1)
			CTX["port"] = port
		elif o in ("-w", "--password"):
			password = str(v)
			if len(password) == 0:
				sys.stderr.write("Invalid password!\n")
				sys.exit(1)
			CTX["password"] = password
		elif o in ("-i", "--interval"):
			interval = int(v)
			if interval < 5 or interval > 300:
				sys.stderr.write("Invalid interval!\n")
				sys.exit(1)
			CTX["interval"] = interval
		else:
			assert False, "invalid option(s)"
			usage()
			sys.exit(1)

	agent_run() #infinite loop function
else:
	sys.stderr.write("This is a script only!")
	sys.exit(1)
