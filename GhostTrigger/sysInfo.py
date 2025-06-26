import platform
import os
import sys
import uuid
import socket
import datetime

def is_android():
    return 'ANDROID_ROOT' in os.environ or os.path.exists('/system/build.prop')

def get_os_name():
    return "Android" if is_android() else platform.system()

def format_mac(mac_int):
    return ':'.join(f'{(mac_int >> i) & 0xff:02x}' for i in range(40, -1, -8))

def get_mac_address():
    mac_int = uuid.getnode()
    is_random = (mac_int >> 40) & 0x02
    if is_random:
        return "Could not reliably determine"
    return format_mac(mac_int)

def get_all_ip_addresses():
    try:
        return list(set([socket.gethostbyname(socket.gethostname())]))
    except:
        return ["Unavailable"]

def get_environment_vars():
    keys = ['PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'OS', 'COMPUTERNAME', 'ANDROID_ROOT']
    return {key: os.environ.get(key, "Not set") for key in keys}

def get_cpu_count():
    return os.cpu_count() or "Unavailable"

def get_memory_info():
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
    return dt.strftime("%Y-%m-%d %H:%M:%S (%A)")

def print_pretty(title, data_dict):
    output = ''
    print(f"\n===== {title} =====")
    max_len = max(len(k) for k in data_dict)
    for key in sorted(data_dict):
       output+= f"  {key.ljust(max_len)} : {data_dict[key]}\n"
    print(output)

def sys_info():
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
    print_pretty("System Info", system_info)
    print_pretty("Hardware Info", hardware_info)
    print_pretty("Network Info", network_info)
    print_pretty("User & Environment", user_env)
    print_pretty("Date & Time", dt_info)
if __name__ == "__main__":
    sys_info()