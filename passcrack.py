#!/usr/bin/env python3

import sys, getopt, execnet, hashlib, base64, time

HOSTS_FILE = 'slacr.hosts'
WORDLISTS_FILE = 'wordlists'
DEFAULT_HASH_ALGORITHM = 'sha256'

def readlines(filename):
	try:
		lines = [line.strip() for line in open(filename, encoding='utf-8')]
		return lines
	except IOError as strerror:
		print("I/O error:", str(strerror))
	except ValueError:
		print("Could not convert data in file to lines.")
	except:
		print("Unexpected error:", sys.exc_info()[0])
		raise

def partition(list_, n):
	for i in range(0, len(list_), n):
		yield list_[i:i+n]

def create_group(hostfile):
	hosts = ["ssh=" + h for h in readlines(hostfile)]
	gateways = []
	for h in hosts:
		try: 
			gateways.append(execnet.makegateway(h))
			print("{0} connected".format(h))
		except: 
			print("Could not open gateway:", sys.exc_info()[0])
	return gateways

def hash_compare(channel, target, word_list, hash_name):
	import hashlib, base64
	hasha = getattr(hashlib, hash_name, 'sha256')
	hashed = ''
	app = []
	for word in word_list:
		hashed = str(base64.b64encode(hasha(word.encode('utf-8')).digest()))
		if hashed == target:
			channel.send([word, target])
			return
	channel.send(None)

def master(gateways, target_hash, wordlists, hash_algorithm_name):
	for ls in wordlists:
		print("Attempting wordlist {0}".format(ls))
		passlist = readlines(ls)
		parted = partition(passlist, round(len(passlist)/len(gateways)))
		node_data = zip(gateways, list(parted))
		channels = []
		for node, data in node_data:
			channels.append(node.remote_exec(hash_compare, target=target_hash, word_list=data, hash_name=hash_algorithm_name))
		
		multich = execnet.MultiChannel(channels)
		queue = multich.make_receive_queue()
		for g in gateways:
			out = queue.get()[1]
			if out is not None:
				execnet.default_group.terminate()
				return out
		return

def usage(verbose=None):
	print("""\
   Usage: passcrack <file containing target hash> [-w <file containing list of dictionaries>] [-a <hashing algorithm name>]""")	
	if verbose is not None:
		print("""
        -w | --wordlist=FILENAME
            FILENAME is a file containing a list of filenames, separated by newlines, of dictionary list files to attempt in order.
        -a | --algorithm=HASH_NAME
				HASH_NAME can be any hashing algorithm provided by python's hashlib library: sha1, sha224, sha256, sha384, sha512, and md5. Additional hashing algorithms may be available depending on the OpenSSL library that python uses on your platform, but unless it's available to every machine in your cluster you'll run into some issues.""")
	print("""
        (for example: ./passcrack passhash.txt -w passdicts.txt --algorithm=md5)
	""")

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hw:a:", ["help", "wordlists=", "algorithm="])
	except getopt.GetoptError as err:
		print(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)
	
	target_hash_file = args[0]
	wordlists_file = WORDLISTS_FILE
	hash_algorithm_name = DEFAULT_HASH_ALGORITHM

	for o, a in opts:
		if (o in ("-h", "--help")) or (a in ("help", "usage")):
			usage(1)
			sys.exit()
		elif o in ("-w", "--wordlists"):
			wordlists_file = a
		elif o in ("-a", "--algorithm"):
			hash_algorithm_name = a
		else:
			assert False, "unhandled option"
	
	try:
		f = open(target_hash_file, encoding='utf-8')
	except IOError as err:
		print("I/O error: {0}".format(err))
	except:
		print("Unexpected error:", sys.exc_info()[0])
		raise
	target = f.readline().strip()
	wordlists = readlines(wordlists_file)
	group = create_group(HOSTS_FILE)
	password_hash = master(group, target, wordlists, hash_algorithm_name)
	if password_hash:
		print("""The password is '{0}'
      hashing algorithm: {1}
      original hash: {2}
      total processing time to completion: {3} seconds""".format(password_hash[0], hash_algorithm_name, password_hash[1], time.clock()))
	else:
		print("The password cannot be discovered. Maybe you should expand your dictionary?")

	
if __name__ == '__main__':
	if len(sys.argv) <= 1: usage()
	else: main()
