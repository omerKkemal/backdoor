# PhantomGate - Multi-purpose Remote Administration and Botnet Utility

**PhantomGate** is a cross-platform remote administration tool (RAT) and botnet client, designed for advanced command-and-control (C2) operations. With features including remote command execution, botnet management, file transfer, and DDoS capabilities, PhantomGate is a powerful framework for remote system management and automation.

> **DISCLAIMER:**  
> This project is for educational and authorized research purposes only. Unauthorized use, deployment, or distribution of this software is illegal and unethical.

---

## Features

- **Remote Command Execution:**  
  Execute arbitrary shell commands on registered clients via API.

- **Botnet Operations:**  
  Participate in botnet actions, including UDP flood (DoS attacks), custom instructions, and more.

- **Target Registration & Management:**  
  Automatically registers clients with a central API and keeps persistent state using SQLite.

- **File Transfer & Simple HTTP Server:**  
  Send and receive files, start a simple HTTP file server for sharing.

- **Cross-Platform Support:**  
  Works on Windows, Linux, and Android, with OS detection and platform-specific handling.

- **Command Output Reporting:**  
  Reports the results of executed commands back to the C2 server.

---

## How It Works

1. **Registration:**  
   On first run, the client registers itself with the C2 API server and saves its info in a local SQLite database.

2. **Polling:**  
   The client periodically polls the API for new commands or botnet instructions.

3. **Execution:**  
   Received commands are executed on the client system, and outputs are sent back to the server.

4. **Botnet Actions:**  
   If instructed, the client can perform UDP flood attacks or other custom botnet actions.

5. **File Operations:**  
   The client can serve files over HTTP or send files directly through the network.

---

## API Endpoints

By default, the C2 API server is expected at `http://127.0.0.1:5000`. Key endpoints include:

- `/api/registor_target` — Register a new target
- `/api/ApiCommand/<target>` — Get commands for a target
- `/api/Apicommand/save_output` — Post command output
- `/api/BotNet/<target>` — Get botnet instructions
- `/api/get_instraction/<target>` — Get instructions for a target

---

## Usage

```bash
python PhantomGate.py
```

- The client will start, register with the C2 server, and begin polling for instructions.
- All attack and management operations are controlled via the API server.

---

## Security & Ethical Notice

- **This tool is extremely powerful and dangerous if misused.**
- You must have explicit authorization to operate, test, or deploy this software.
- Unauthorized use is strictly prohibited and may result in severe legal consequences.

---

## Contributing

Contributions for educational, security research, and defense purposes are welcome. Please open issues or pull requests for improvements, bugfixes, or documentation.

---

## License

This project is provided for educational and authorized research purposes only.  
**No license for malicious use is granted.**

---

## Authors

- Original author: Unknown
- Repository: [omerKkemal/backdoor](https://github.com/omerKkemal/backdoor)
