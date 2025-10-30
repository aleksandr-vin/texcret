import os
import re
from pathlib import Path


STATE_DIR = Path(os.path.expanduser("~/.config/texcrets"))
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "secrets.json"

# ===== Formats & constants =====
MAGIC2 = b"YKLB2\x00"  # 6 bytes
DATA_IV_LEN = 12  # AES-GCM IV for data
WRAP_IV_LEN = 12  # AES-GCM IV for wrapping
SALT_LEN = 16  # salt for HKDF/PBKDF2
PASSKEY_INFO = b"YK-largeBlob-text"
SECRET_LEN = 32

# ===== regexes =====

# Regex: matches {% texcret %}...{% endtexcret %}, including multiline content
TEXCRET_BLOCK_RE = re.compile(
    r"{%\s*texcret\s*%}(.*?){%\s*endtexcret\s*%}",
    re.DOTALL | re.IGNORECASE,
)

# Regex: matches [Texcret start]: #...[Texcret end]: #, including multiline content
TEXCRETED_BLOCK_RE = re.compile(
    r"\n?\[\s*Texcret\s*start\s*\]:\s*#(.*?)\[\s*Texcret\s*end\s*\]:\s*#\n?",
    re.DOTALL | re.IGNORECASE,
)
