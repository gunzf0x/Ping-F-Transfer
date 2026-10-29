CHUNK = 12  # file bytes per ping
INDEX_BYTES = 3  # chunk index, big-endian
RETRIES = 5
TIMEOUT = 2  # seconds to wait for each reply

CIPHERS = {
    'aes-128': ('aes-128-cbc', 16),
    'aes-128-cbc': ('aes-128-cbc', 16),
    'aes-192': ('aes-192-cbc', 24),
    'aes-192-cbc': ('aes-192-cbc', 24),
    'aes-256': ('aes-256-cbc', 32),
    'aes-256-cbc': ('aes-256-cbc', 32),
}

# Define color dictionary
color = {
    "NC": '\033[0m',
    "RED": '\033[91m',
    "GREEN": '\033[92m',
    "YELLOW": '\033[93m',
    "BLUE": '\033[94m',
    "MAGENTA": '\033[95m',
    "CYAN": '\033[96m',
    "WHITE": '\033[97m',
    "GRAY": '\033[37m'
}


# Define some pretty characters
STAR: str = f"{color['YELLOW']}[{color['BLUE']}*{color['YELLOW']}]{color['NC']}"
STAR_v2: str = f"{color['CYAN']}[{color['RED']}+{color['CYAN']}]{color['NC']}"
WARNING_STR: str = f"{color['RED']}[{color['YELLOW']}!{color['RED']}]{color['NC']}"
