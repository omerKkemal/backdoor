# Foreground colors and styles
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, CYAN, LIGHTBLUE, LIGHTGREEN, LIGHTRED, LIGHTCYAN, LIGHTMAGENTA, GRAY, BLACK, BOLD, UNDERLINE, BLINK, INVERT, END = '\033[94m', '\033[91m', '\033[97m', '\033[93m', '\033[1;35m', '\033[1;32m', '\033[96m', '\033[94m', '\033[92m', '\033[91m', '\033[96m', '\033[95m', '\033[90m', '\033[30m','\033[1m', '\033[4m', '\033[5m', '\033[7m', '\033[0m'

# Background colors
BG_RED, BG_GREEN, BG_YELLOW, BG_BLUE, BG_MAGENTA, BG_CYAN, BG_WHITE, BG_BLACK = '\033[41m', '\033[42m', '\033[43m', '\033[44m', '\033[45m', '\033[46m', '\033[47m', '\033[40m'

# Test output
print(f"{BLUE}This is BLUE text{END}")
print(f"{RED}This is RED text{END}")
print(f"{WHITE}This is WHITE text{END}")
print(f"{YELLOW}This is YELLOW text{END}")
print(f"{MAGENTA}This is MAGENTA text{END}")
print(f"{GREEN}This is GREEN text{END}")
print(f"{CYAN}This is CYAN text{END}")
print(f"{LIGHTBLUE}This is LIGHTBLUE text{END}")
print(f"{LIGHTGREEN}This is LIGHTGREEN text{END}")
print(f"{LIGHTRED}This is LIGHTRED text{END}")
print(f"{LIGHTCYAN}This is LIGHTCYAN text{END}")
print(f"{LIGHTMAGENTA}This is LIGHTMAGENTA text{END}")
print(f"{GRAY}This is GRAY text{END}")
print(f"{BLACK}This is BLACK text{END}")

print(f"{BOLD}This is BOLD text{END}")
print(f"{UNDERLINE}This is UNDERLINED text{END}")
print(f"{BLINK}This is BLINKING text (if supported){END}")
print(f"{INVERT}This is INVERTED text{END}")

print(f"{BG_RED}{WHITE}White on Red Background{END}")
print(f"{BG_GREEN}{BLACK}Black on Green Background{END}")
print(f"{BG_YELLOW}{BLACK}Black on Yellow Background{END}")
print(f"{BG_BLUE}{WHITE}White on Blue Background{END}")
print(f"{BG_MAGENTA}{WHITE}White on Magenta Background{END}")
print(f"{BG_CYAN}{BLACK}Black on Cyan Background{END}")
print(f"{BG_WHITE}{BLACK}Black on White Background{END}")
print(f"{BG_BLACK}{WHITE}White on Black Background{END}")
