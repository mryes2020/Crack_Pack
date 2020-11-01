#!/usr/bin/python3

import os
import sys
import hashlib


#global variables


#global functions

# clear terminal function
def clearTerminal():
	if (os.name == "nt"):
		os.system("cls")
	else:
		os.system("clear")
# show banner function
def ShowBanner():
	clearTerminal()
	print (" _____                    _     ______             _    ")
	print ("/  __ \\                  | |    | ___ \\           | |   ")
	print ("| /  \/ _ __  __ _   ___ | | __ | |_/ /__ _   ___ | | __")
	print ("| |    | '__|/ _` | / __|| |/ / |  __// _` | / __|| |/ /")
	print ("| \__/\| |  | (_| || (__ |   <  | |  | (_| || (__ |   < ")
	print (" \\____/|_|   \\__,_| \\___||_|\_\\ \\_|   \__,_| \___||_|\\_\\")
	print ("			Coded by: MrYes2020 \n")

# show help function
def ShowHelp():
	ShowBanner()
	print ("\nUsage: ./pack_.py [hashing algorithm] [hash] [wordlist]")
	print ("Example: ./pash_.py 1 827ccb0eea8a706c4c34a16891f84e7b /usr/share/wordlists/rockyou.txt")
	print ("\nHashing Algorithms: ")
	print (" - 1: MD5")
	print (" - 2: SHA1")
	print (" - 3: SHA224")
	print (" - 4: SHA256")
	print (" - 5: SHA384")
	print (" - 6: SHA512")
	print (" - 7: BLAKE2B")
	print (" - 8: BLAKE2S")

	print ("\n------------------------------------------------------------")
	print ("Example2: ./pack_.py 1 8287458823facb8ff918dbfabcd22ccb default")
	print ("Example2: ./pack_.py 3 efbccc6fe7d20c2cb493319a7eba6e511ada8094b6e3650fd10f8e4b /usr/share/wordlists/rockyou.txt")
	print ("Example3: ./pack_.py 6 6226ff0e50b5313f287a6904ecf242b67d00d28bd211ddae51e8f044d24de0defd4daaa32eecac9bb13f9d2fe462941838937f16613aafdd075075ef9dfe7b64 default")



	print ("\n")

# hash functions

# hash md5
def hash_md5(string, encoding="utf-8"):
	md5_hash_manager = hashlib.md5()
	md5_hash_manager.update(string.encode(encoding).strip())
	return md5_hash_manager.hexdigest()

# hash sha1
def hash_sha1(string, encoding="utf-8"):
	sha1_hash_manager = hashlib.sha1()
	sha1_hash_manager.update(string.encode(encoding).strip())
	return sha1_hash_manager.hexdigest()

# hash sha224
def hash_sha224(string, encoding="utf-8"):
        sha224_hash_manager = hashlib.sha224()
        sha224_hash_manager.update(string.encode(encoding).strip())
        return sha224_hash_manager.hexdigest()

# hash sha256
def hash_sha256(string, encoding="utf-8"):
        sha256_hash_manager = hashlib.sha256()
        sha256_hash_manager.update(string.encode(encoding).strip())
        return sha256_hash_manager.hexdigest()

# hash sha384
def hash_sha384(string, encoding="utf-8"):
        sha384_hash_manager = hashlib.sha384()
        sha384_hash_manager.update(string.encode(encoding).strip())
        return sha384_hash_manager.hexdigest()

# hash sha512
def hash_sha512(string, encoding="utf-8"):
        sha512_hash_manager = hashlib.sha512()
        sha512_hash_manager.update(string.encode(encoding).strip())
        return sha512_hash_manager.hexdigest()

# hash blake2b
def hash_blake2b(string, encoding="utf-8"):
        blake2b_hash_manager = hashlib.blake2b()
        blake2b_hash_manager.update(string.encode(encoding).strip())
        return blake2b_hash_manager.hexdigest()

# hash blake2s
def hash_blake2s(string, encoding="utf-8"):
        blake2s_hash_manager = hashlib.blake2s()
        blake2s_hash_manager.update(string.encode(encoding).strip())
        return blake2s_hash_manager.hexdigest()



# crack functions


# crack md5 function
def crackmd5_(hash, wordlist):
	file = open(wordlist, "r")
	x = 0
	for line in file:
		hashed_line = hash_md5(line)
		if (hashed_line == hash):
			print ("[+] Found match: " + line.strip())
			print ("[+] Matched Hash: " + hashed_line + "\n")
			x = x + 1
			break
	if (x == 0):
		print ("[-] No matches found!!")

# crack sha1
def cracksha1_(hash, wordlist):
        file = open(wordlist, "r")
        x = 0
        for line in file:
                hashed_line = hash_sha1(line)
                if (hashed_line == hash):
                        print ("[+] Found match: " + line.strip())
                        print ("[+] Matched Hash: " + hashed_line + "\n")
                        x = x + 1
                        break
        if (x == 0):
                print ("[-] No matches found!!")

# crack sha224
def cracksha224_(hash, wordlist):
	file = open(wordlist, "r")
	x = 0
	for line in file:
		hashed_line = hash_sha224(line)
		if (hashed_line == hash):
			print ("[+] Found match: " + line.strip())
			print ("[+] Matched Hash: " + hashed_line + "\n")
			x = x + 1
			break
	if (x == 0):
		print ("[-] No matches found!!")

# crack sha256
def cracksha256_(hash, wordlist):
        file = open(wordlist, "r")
        x = 0
        for line in file:
                hashed_line = hash_sha256(line)
                if (hashed_line == hash):
                        print ("[+] Found match: " + line.strip())
                        print ("[+] Matched Hash: " + hashed_line + "\n")
                        x = x + 1
                        break
        if (x == 0):
                print ("[-] No matches found!!")

# crack sha384
def cracksha384_(hash, wordlist):
        file = open(wordlist, "r")
        x = 0
        for line in file:
                hashed_line = hash_sha384(line)
                if (hashed_line == hash):
                        print ("[+] Found match: " + line.strip())
                        print ("[+] Matched Hash: " + hashed_line + "\n")
                        x = x + 1
                        break
        if (x == 0):
                print ("[-] No matches found!!")

# crack sha512
def cracksha512_(hash, wordlist):
        file = open(wordlist, "r")
        x = 0
        for line in file:
                hashed_line = hash_sha512(line)
                if (hashed_line == hash):
                        print ("[+] Found match: " + line.strip())
                        print ("[+] Matched Hash: " + hashed_line + "\n")
                        x = x + 1
                        break
        if (x == 0):
                print ("[-] No matches found!!")

# crack blake2b
def crackblake2b_(hash, wordlist):
        file = open(wordlist, "r")
        x = 0
        for line in file:
                hashed_line = hash_blake2b(line)
                if (hashed_line == hash):
                        print ("[+] Found match: " + line.strip())
                        print ("[+] Matched Hash: " + hashed_line + "\n")
                        x = x + 1
                        break
        if (x == 0):
                print ("[-] No matches found!!")

# crack blake2s
def crackblake2s_(hash, wordlist):
        file = open(wordlist, "r")
        x = 0
        for line in file:
                hashed_line = hash_blake2s(line)
                if (hashed_line == hash):
                        print ("[+] Found match: " + line.strip())
                        print ("[+] Matched Hash: " + hashed_line + "\n")
                        x = x + 1
                        break
        if (x == 0):
                print ("[-] No matches found!!")


# the main function
def main():
	if (len(sys.argv) == 4):
		ShowBanner()
		mode = sys.argv[1]
		hash = sys.argv[2]
		wordlist = sys.argv[3]
		if (int(mode) == 1):
			# md5
			print (" -> Type: MD5")
			print ("[!!] Cracking started")
			crackmd5_(hash, wordlist)
		elif (int(mode) == 2):
			# sha1
			print (" -> Type: SHA1")
			print ("[!!] Cracking started")
			cracksha1_(hash, wordlist)
		elif (int(mode) == 3):
			# sha224
			print (" -> Type: SHA224")
			print ("[!!] Cracking started")
			cracksha224_(hash, wordlist)
		elif (int(mode) == 4):
			# sha256
			print (" -> Type: SHA256")
			print ("[!!] Cracking started")
			cracksha256_(hash, wordlist)
		elif (int(mode) == 5):
			# sha384
			print (" -> Type: SHA384")
			print ("[!!] Cracking started")
			cracksha384_(hash, wordlist)
		elif (int(mode) == 6):
			# sha512
			print (" -> Type: SHA512")
			print ("[!!] Cracking started")
			cracksha512_(hash, wordlist)
		elif (int(mode) == 7):
			# blake2b
			print (" -> Type: BLAKE2B")
			print ("[!!] Cracking started")
			crackblake2b_(hash, wordlist)
		elif (int(mode) == 8):
			# blake2s
			print (" -> Type: BLAKE2S")
			print ("[!!] Cracking started")
			crackblake2s_(hash, wordlist)
		else:
			ShowHelp()
	else:
		ShowHelp()

# start the program boiiiiii
if __name__ == "__main__":
	main()
