# Veil

A small suite of standalone, end-to-end encrypted tools written in pure Python 3:

| Tool | What it does |
|---|---|
| **`veil.py`** | Encrypted chat and file sharing over your LAN (or Tailscale) |
| **`veil_pm.py`** | Local password manager with its own passphrase |
| **`veil_vault.py`** | Encrypted vault for files and folders |

No build system, no framework — just Python scripts.

---

## Requirements

### Required

- **Python 3.8+**
- **[`cryptography`](https://pypi.org/project/cryptography/)** — the only PyPI dependency, used by all three tools

```bash
pip install cryptography
# or, on Void Linux:
xbps-install -S python3-cryptography
# or, on Debian/Ubuntu:
apt install python3-cryptography
```

### Optional (recommended)

| Package | Used by | Purpose | Fallback |
|---|---|---|---|
| `libargon2` (`libargon2.so.1`) | all | Argon2id key derivation | PBKDF2 (600 000 iterations) |
| `figlet` | all | Banner at startup | Plain text banner |
| `xdg-open` | vault | Opening decrypted files | Silently skipped |
| `wl-copy` / `xclip` / `xsel` | pm | Copy passwords to clipboard | Silent fallback |
| `nano` (or `$EDITOR`) | vault | Edit files from the REPL | — |

```bash
# Void Linux
xbps-install -S libargon2 figlet xdg-utils wl-clipboard

# Debian/Ubuntu
apt install libargon2 figlet xdg-utils wl-clipboard
```

> **Note:** if one machine uses Argon2id and the other falls back to PBKDF2, the
> handshake in `veil.py` will fail. Install `libargon2` on both ends (or force a
> KDF with the environment variables listed below).

---

## Installation

```bash
git clone https://github.com/Prealidia/Veil_project.git
cd Veil_project
pip install cryptography
```

Everything runs directly from the repository — no install step needed.

---

## veil.py — encrypted chat & file sharing

Two instances talk to each other over **TCP port 50000**. All traffic is
end-to-end encrypted: X25519 key exchange, proof-of-work, PSK authentication
derived from a shared passphrase, HKDF session keys and Fernet (AES-128-CBC +
HMAC) for the payload. Messages are padded to fixed size thresholds so traffic
analysis cannot tell short messages from long ones.

### Run

```bash
python3 veil.py
```

On first launch it asks for:

1. The **IP address of the other machine** (comma-separated for multiple:
   LAN + Tailscale, for example) — stored in `~/.config/localdrop/config.json`
2. A **passphrase** (≥ 16 characters; 5–6 random words recommended)

Then it generates a long-term X25519 identity and starts listening.

### Prompt

| Input | Action |
|---|---|
| A file path | Sends the file, encrypted in 1 MiB chunks |
| Plain text (or text in quotes) | Sends a chat message |
| `TAB` | Path completion |
| `q` / `quit` / `exit` | Quit |

### CLI options

```
--read-log                 Show stored chat messages (decrypted)
--change-password          Change the passphrase, re-encrypting logs and identity
--migrate-kdf {argon2id,pbkdf2}   Convert local files to a different KDF
--save-passphrase          Save the passphrase to disk (~/.config/localdrop/password)
--forget DAYS              Delete chat history older than DAYS (0 = everything)
--bind IP                  Listen only on that address (saved to config.json)
```

### Environment

- `CHATDEFENDER_KDF=argon2id|pbkdf2` — force a specific KDF

### Both machines must agree on

- Protocol version (currently `4`)
- The same passphrase
- The same KDF (Argon2id vs PBKDF2)
- Port **50000** open and reachable
- Each other's IP in the allowlist

### Data locations

| Path | Contents |
|---|---|
| `~/localdrop/` | Received files |
| `~/localdrop/messaggi/*.log` | Encrypted chat history |
| `~/.config/localdrop/` | Config, identity keys, KDF record (all `0600`) |
| `~/.local/state/chatdefender/sicurezza.log` | Security log (rotated at 5 MiB) |

---

## veil_pm.py — password manager

Passwords are stored in a single encrypted file (`~/.local/share/veil_pm/entries.json`),
protected by a passphrase that is **never written to disk**.

### Run

```bash
python3 veil_pm.py
```

First launch creates the salt and verification tag automatically.

### Commands (REPL)

```
list / ls            List all entries
add <site>           Add a new entry
get <site> [-c]      Show a password (-c copies to clipboard)
find <text>          Search entries
change <site>        Update an entry
rm / del <site>      Delete an entry
help                 Show help
q / quit / exit      Quit
```

Max **3 passphrase attempts**, then the tool exits.

### Environment

- `VEIL_PM_DB` — custom database path
- `VEIL_PM_KDF` — `argon2id` or `pbkdf2`

---

## veil_vault.py — encrypted file vault

Files and folders are stored as individual encrypted items (`<name>.veil`) in
`~/localdrop/vault/`. Folders are packed into a tar archive before encryption.

### Run

```bash
python3 veil_vault.py              # interactive REPL
python3 veil_vault.py init         # create vault + passphrase
python3 veil_vault.py list         # list items
python3 veil_vault.py add <path>   # encrypt a file or folder (-n <name>, -f to overwrite)
python3 veil_vault.py open <name>  # decrypt to cache, open, auto-delete cache
python3 veil_vault.py export <dir> # decrypt everything to a directory
python3 veil_vault.py rm <name>    # delete an item
```

### REPL commands

```
list, ls <name[/path]>, add <path> [-f] [-n name],
open <name[/path]>, export <dir>, rm <name>, help, q
```

`open` inside the REPL launches `$EDITOR` (default `nano`) for editing, then
re-encrypts with a round-trip verification. From the CLI it uses `xdg-open`.

### Environment

- `VEIL_VAULT_DIR` — custom vault directory
- `VEIL_VAULT_KDF` — `argon2id` or `pbkdf2`
- `$EDITOR` — editor used by `open` in the REPL

---

## Security notes

- Passphrases are **never stored in plain text** (unless you explicitly pass
  `--save-passphrase` to `veil.py`).
- Weak / predictable passphrases are rejected.
- Peer identity pins are only written **after** a successful authenticated
  handshake — a MITM cannot poison them.
- The vault rejects path traversal, symlinks, FIFOs and device nodes when
  extracting archives.
- All config and key files are written with `0600` permissions inside `0700`
  directories.

## License

MIT — see [LICENSE](LICENSE).
