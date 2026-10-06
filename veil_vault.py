#!/usr/bin/env python3
"""
vault - encrypted file vault with its own passphrase.

Use it like veil: run `vault`, it shows the banner, asks for the passphrase
and opens an interactive `>>> ` prompt. Each terminal is a fresh session, so
every new terminal asks the passphrase again.

One-shot commands still exist for scripts: `vault list`, `vault add <path>`,
`vault ls <name>`, `vault open <name>`, `vault export <dir>`, `vault rm <name>`.

`add` accepts a file or a folder. A folder is stored as a single archive
and can be inspected with `ls <name>` without extracting it, opened as a
whole (`open <name>`) or file by file (`open <name>/<subpath>`).
"""
import argparse
import copy
import ctypes
import getpass
import hashlib
import hmac
import io
import os
import subprocess
import sys
import tarfile
import time
from shutil import rmtree

from base64 import urlsafe_b64encode
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import readline
except ImportError:
    pass

MAGIC = b"VEILVAULT\x00\x01"
MAGIC_DIR = b"VEILVAULT_DIR\x00\x01"
ARGON2_TEMPO = 3
ARGON2_MEMORIA_KIB = 65536
ARGON2_PARALLELISMO = 4
SALT_SIZE = 16

VAULT_DIR = Path(os.environ.get("VEIL_VAULT_DIR", Path.home() / "localdrop" / "vault"))
CONFIG_DIR = Path.home() / ".config" / "veil_vault"
KDF_FILE = CONFIG_DIR / "kdf"
SALT_FILE = CONFIG_DIR / "salt"
CHECK_FILE = CONFIG_DIR / "check"


def prepara_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass


def scrivi_privato(percorso, dati):
    prepara_config()
    fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(dati)


_KDF_AVVISATO = set()


def _kdf_valido(scelta):
    return scelta if scelta in ("argon2id", "pbkdf2") else None


def kdf_salvato():
    """Il KDF registrato su disco, se c'e'."""
    try:
        return _kdf_valido(KDF_FILE.read_text().strip()) if KDF_FILE.exists() else None
    except OSError:
        return None


def kdf_attivo():
    """Il KDF con cui creare un vault NUOVO: env -> record -> autodetect."""
    scelta = _kdf_valido(os.environ.get("VEIL_VAULT_KDF", ""))
    if scelta:
        return scelta
    salvato = kdf_salvato()
    if salvato:
        return salvato
    try:
        ctypes.CDLL("libargon2.so.1")
        scelta = "argon2id"
    except OSError:
        scelta = "pbkdf2"
    scrivi_privato(KDF_FILE, (scelta + "\n").encode())
    return scelta


def kdf_del_vault():
    """Il KDF con cui e' stato creato questo vault. Il record su disco vince
    sempre: se vincesse l'env, un export con VEIL_VAULT_KDF sbagliato
    deriverebbe una chiave diversa e il vault sembrerebbe corrotto."""
    return kdf_salvato() or kdf_attivo()


def _avvisa_conflitto_kdf():
    """Dice una volta sola che VEIL_VAULT_KDF viene ignorato, invece di
    lasciare che l'utente creda che l'override sia entrato in vigore."""
    salvato = kdf_salvato()
    env = _kdf_valido(os.environ.get("VEIL_VAULT_KDF", ""))
    if salvato and env and env != salvato and env not in _KDF_AVVISATO:
        _KDF_AVVISATO.add(env)
        print(f"[!] VEIL_VAULT_KDF={env} ignored: this vault was created with "
              f"{salvato}. Unset it to silence this warning.")


def argon2id(segreto, sale):
    try:
        lib = ctypes.CDLL("libargon2.so.1")
    except OSError:
        return None
    lib.argon2id_hash_raw.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
    ]
    uscita = ctypes.create_string_buffer(32)
    rc = lib.argon2id_hash_raw(
        ARGON2_TEMPO, ARGON2_MEMORIA_KIB, ARGON2_PARALLELISMO,
        segreto, len(segreto), sale, len(sale), uscita, 32,
    )
    if rc != 0:
        raise RuntimeError(f"argon2 error {rc}")
    return uscita.raw


def radice_kdf(passphrase, sale, kdf=None):
    dati = passphrase.encode()
    if (kdf or kdf_del_vault()) == "argon2id":
        chiave = argon2id(dati, sale)
        if chiave is None:
            # il vault vuole argon2id ma la libreria non c'e': continua a pbkdf2
            # e lascia che 'verifica' dica che la passphrase non torna
            print("[!] libargon2 not found, this vault needs argon2id: "
                  "deriving with pbkdf2 instead (the passphrase will not match)")
        else:
            return chiave
    return hashlib.pbkdf2_hmac("sha256", dati, sale, 600_000)


def sottochiave(radice, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(radice)


def _kdf_candidati():
    """I KDF da provare, in ordine. Se il record c'e' e' l'unico candidato: al
   trimenti (vault creato prima che il record esistesse) se ne provano due,
    perche' l'autodetect di oggi potrebbe non coincidere con quello di allora e
    segnerebbe 'passphrase sbagliata' su un vault perfettamente integro."""
    salvato = kdf_salvato()
    if salvato:
        return [salvato]
    env = _kdf_valido(os.environ.get("VEIL_VAULT_KDF", ""))
    if env:
        altro = "pbkdf2" if env == "argon2id" else "argon2id"
        return [env, altro]
    try:
        ctypes.CDLL("libargon2.so.1")
        primo = "argon2id"
    except OSError:
        primo = "pbkdf2"
    return [primo, "pbkdf2" if primo == "argon2id" else "argon2id"]


def deriva(passphrase):
    prepara_config()
    if not SALT_FILE.exists():
        return None
    _avvisa_conflitto_kdf()
    sale = SALT_FILE.read_bytes()
    for kdf in _kdf_candidati():
        radice = radice_kdf(passphrase, sale, kdf=kdf)
        if verifica(radice):
            if kdf_salvato() != kdf:
                #vault recuperato: da ora in poi il KDF e' noto
                scrivi_privato(KDF_FILE, (kdf + "\n").encode())
            return radice
    return None


def verifica(radice):
    if not CHECK_FILE.exists():
        return False
    atteso = CHECK_FILE.read_bytes()
    if len(atteso) != 16:
        return False
    calcolato = hmac.new(radice, b"veil-vault-check", hashlib.sha256).digest()[:16]
    return hmac.compare_digest(calcolato, atteso)


def _chiedi_frase(prompt):
    """Chiede una passphrase. Alza EOFError se l'input e' finito: senza
    passphrase non ha senso proseguire, ma non deve uscire un traceback."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt).strip()
    return input(prompt).strip()


def legge_frase():
    try:
        return _chiedi_frase("Vault passphrase: ")
    except EOFError:
        raise SystemExit("vault: no passphrase given (stdin ended)")


# ----- encrypted files -----

def chiave_file(radice, sale_file):
    return Fernet(urlsafe_b64encode(sottochiave(radice, b"veil-vault-file" + sale_file)))


def scrivi_vault(percorso, dati):
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(dati)


def percorso_vault(nome):
    """Il path di un item del vault. Il nome non puo' contenere separatori:
    senza questo controllo 'rm ../altro' cancellerebbe, e 'add -n ../altro'
    scriverebbe, fuori dalla cartella del vault."""
    separatori = {s for s in (os.sep, os.altsep) if s}
    if not nome or nome in (".", "..") or any(s in nome for s in separatori):
        raise ValueError(f"invalid item name: {nome!r}")
    return VAULT_DIR / (nome + ".veil")


def cifra(radice, sorgente, nome, magic=MAGIC, dati=None):
    if dati is None:
        dati = sorgente.read_bytes()
    sale_file = os.urandom(SALT_SIZE)
    fernet = chiave_file(radice, sale_file)
    accompagnato = magic + sale_file + fernet.encrypt(dati)
    scrivi_vault(percorso_vault(nome), accompagnato)


def decifra(radice, nome):
    percorso = percorso_vault(nome)
    dati = percorso.read_bytes()
    if dati.startswith(MAGIC_DIR):
        magic = MAGIC_DIR
        is_dir = True
    elif dati.startswith(MAGIC):
        magic = MAGIC
        is_dir = False
    else:
        raise ValueError(f"{nome}: not a vault file")
    if len(dati) < len(magic) + SALT_SIZE + 1:
        raise ValueError(f"{nome}: not a vault file")
    sale_file = dati[len(magic):len(magic) + SALT_SIZE]
    token = dati[len(magic) + SALT_SIZE:]
    try:
        return chiave_file(radice, sale_file).decrypt(token), is_dir
    except InvalidToken:
        raise ValueError(f"wrong passphrase or corrupted file ({nome})")


def archivia_cartella(sorgente, arcname=None):
    arcname = arcname or sorgente.name
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        tar.add(sorgente, arcname=arcname)
    return buf.getvalue()


def _prefisso_superiore(membri):
    """Le cartelle sono archiviate con il proprio nome in cima: toglilo."""
    if not membri:
        return ""
    primo = membri[0].name.strip("/")
    if primo and "/" not in primo and all(
        m.name == primo or m.name.startswith(primo + "/") for m in membri
    ):
        return primo + "/"
    return ""


def voci_cartella(radice, nome, sottopercorso=None):
    """Elenca il contenuto di una cartella cifrata senza estrarla su disco.
    Ritorna la lista di (percorso relativo, tipo, dimensione, link)."""
    dati, is_dir = decifra(radice, nome)
    if not is_dir:
        raise ValueError(f"{nome} is not a folder")
    try:
        with tarfile.open(fileobj=io.BytesIO(dati), mode="r") as tar:
            membri = tar.getmembers()
    except tarfile.TarError as e:
        raise ValueError(f"{nome}: corrupted archive ({e})")
    prefisso = _prefisso_superiore(membri)
    voci = []
    for m in membri:
        voce = m.name
        if prefisso:
            if voce == prefisso.rstrip("/"):
                continue  # la cartella radice stessa
            rel = voce[len(prefisso):] if voce.startswith(prefisso) else voce
        else:
            rel = voce
        rel = rel.strip("/")
        if not rel:
            continue
        if m.isdir():
            voci.append((rel, "dir", 0, ""))
        elif m.issym() or m.islnk():
            voci.append((rel, "link", 0, m.linkname))
        elif m.isfile():
            voci.append((rel, "file", m.size, ""))
        else:
            voci.append((rel, "other", 0, ""))
    if sottopercorso:
        sotto = sottopercorso.strip("/")
        dentro = [v for v in voci if v[0] == sotto or v[0].startswith(sotto + "/")]
        if not dentro:
            raise ValueError(f"{nome}: {sotto} not in the folder")
        voci = []
        for r, kind, size, link in dentro:
            if r == sotto:
                # la cartella di partenza: elenchiamo il contenuto, non lei stessa
                if kind != "dir":
                    voci.append((r, kind, size, link))  # il subpath è un file/link
            else:
                voci.append((r[len(sotto) + 1:], kind, size, link))
    return sorted(voci)


def _albero(voci):
    """Dalla lista di (percorso, tipo, dimensione, link) costruisce un
    dict annidato: nome -> {"tipo": str, "size": int, "link": str, "figli": {...}}."""
    radice = {"tipo": "dir", "size": 0, "link": "", "figli": {}}
    for percorso, kind, size, link in voci:
        parti = [p for p in percorso.split("/") if p and p != "."]
        if not parti:
            continue
        nodo = radice
        for p in parti[:-1]:
            nodo = nodo["figli"].setdefault(
                p, {"tipo": "dir", "size": 0, "link": "", "figli": {}})
        ultimo = parti[-1]
        if kind == "dir":
            nodo["figli"].setdefault(
                ultimo, {"tipo": "dir", "size": 0, "link": "", "figli": {}})
        else:
            nodo["figli"][ultimo] = {
                "tipo": kind, "size": size, "link": link, "figli": {}}
    return radice


def _stampa_albero(nodo, prefisso=""):
    figli = sorted(nodo["figli"].items(),
                   key=lambda kv: (kv[1]["tipo"] != "dir", kv[0].lower()))
    for i, (nome, info) in enumerate(figli):
        ultimo = i == len(figli) - 1
        ramo = "└── " if ultimo else "├── "
        if info["tipo"] == "dir":
            print(f"{prefisso}{ramo}{nome}/")
            _stampa_albero(info, prefisso + ("    " if ultimo else "│   "))
        elif info["tipo"] == "link":
            print(f"{prefisso}{ramo}{nome} -> {info['link']}")
        elif info["tipo"] == "other":
            print(f"{prefisso}{ramo}{nome}  (special file, not extracted by open)")
        else:
            print(f"{prefisso}{ramo}{nome}  "
                  f"({info['size']} byte{'s' if info['size'] != 1 else ''})")


def elenca():
    if not VAULT_DIR.exists():
        return []
    voci = []
    for p in sorted(VAULT_DIR.glob("*.veil")):
        voci.append((p.name[:-5], p.stat().st_size))
    return voci


def _file_aperto(percorso):
    try:
        pids = os.listdir("/proc")
    except OSError:
        return False
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"/proc/{pid}/fd/{fd}") == str(percorso):
                    return True
            except OSError:
                continue
    return False


def esiste_aperto(sotto):
    try:
        pids = os.listdir("/proc")
    except OSError:
        return False
    base = str(sotto.resolve()) + os.sep
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"/proc/{pid}/fd/{fd}").startswith(base):
                    return True
            except OSError:
                continue
    return False


def _membro_estraibile(m):
    """filter='data' accetta solo file e directory: symlink e file speciali
    (socket, fifo, device) vengono rifiutati, e senza trattarli a parte
    extractall() aborta l'intero archivio lasciando file parziali in giro."""
    return m.isdir() or m.isfile()


def estrai_archivio(dati, destinazione):
    """Estrae un archivio del vault in `destinazione`, membro alla volta.
    Le voci che filter='data' non accetta vengono saltate e restituite, cosi'
    il chiamante le puo' segnalare invece di perdere il contenuto.
    Ritorna la lista dei nomi saltati."""
    saltati = []
    with tarfile.open(fileobj=io.BytesIO(dati), mode="r") as tar:
        for m in tar.getmembers():
            if not _membro_estraibile(m):
                saltati.append(m.name)
                continue
            try:
                tar.extract(m, path=destinazione, filter="data")
            except (tarfile.TarError, OSError, ValueError) as e:
                saltati.append(m.name)
                print(f"[!] skipped {m.name}: {e}")
    return saltati


def riarray_archivio(dati_originali, bersaglio, radice_int, nuovi_dati):
    """Ricostruisce l'archivio di una cartella sostituendo un solo file.

    Non si riusa la copia estratta su disco: filter='data' non estrae
    symlink, fifo e device, quindi ri-archiviando la directory estratta
    quei membri sparirebbero dal vault al primo salvataggio. Qui si
    ripartisce dai membri originali e si scrive solo il file modificato,
    conservando link, permessi e mtime di tutto il resto."""
    with tarfile.open(fileobj=io.BytesIO(dati_originali), mode="r") as src:
        membri = src.getmembers()
        prefisso = _prefisso_superiore(membri)
        relativo = bersaglio.relative_to(radice_int).as_posix()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as dst:
            for m in membri:
                if prefisso and m.name == prefisso + relativo:
                    nuovo = copy.copy(m)
                    nuovo.type = tarfile.REGTYPE
                    nuovo.size = len(nuovi_dati)
                    dst.addfile(nuovo, io.BytesIO(nuovi_dati))
                elif m.isfile():
                    dst.addfile(m, src.extractfile(m))
                else:
                    dst.addfile(m)
    return buf.getvalue()


def _avvisa_saltati(saltati, radice=None):
    if not saltati:
        return
    anteprima = ", ".join(saltati[:3])
    if len(saltati) > 3:
        anteprima += f", ... (+{len(saltati) - 3})"
    dove = f" in {radice}" if radice else ""
    print(f"[!] {len(saltati)} entrate non estraibili{dove} "
          f"(symlink o file speciali): {anteprima}")


def apri(radice, nome, sottopercorso=None):
    import tempfile
    contenuto, is_dir = decifra(radice, nome)
    cache = Path.home() / ".cache" / "veil_vault"
    cache.mkdir(parents=True, exist_ok=True)
    if is_dir:
        tmp = Path(tempfile.mkdtemp(prefix="veil_vault_", dir=cache))
        try:
            _avvisa_saltati(estrai_archivio(contenuto, tmp), nome)
            primo = list(tmp.iterdir())
            radice_int = primo[0] if (len(primo) == 1 and primo[0].is_dir()) else tmp
            if sottopercorso:
                bersaglio = (radice_int / sottopercorso).resolve()
                if str(bersaglio) != str(tmp.resolve()) and not str(bersaglio).startswith(str(tmp.resolve()) + os.sep):
                    raise ValueError(f"{nome}: invalid subpath")
                if not bersaglio.exists():
                    raise ValueError(f"{nome}: {sottopercorso} not in the folder")
                uscita = bersaglio
            else:
                uscita = radice_int
            print(f"Opened: {uscita}")
            try:
                if os.name == "nt":
                    os.startfile(str(uscita))
                else:
                    subprocess.run(["xdg-open", str(uscita)], check=False)
            except OSError:
                pass
            print("Waiting for the apps to close, then the cache copy is deleted.")
            if os.name == "nt":
                return
            try:
                while esiste_aperto(tmp):
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        finally:
            try:
                rmtree(tmp)
                print("[+] Cache copy deleted")
            except OSError:
                pass
    else:
        uscita = cache / nome
        scrivi_vault(uscita, contenuto)
        try:
            if os.name == "nt":
                os.startfile(str(uscita))
            else:
                subprocess.run(["xdg-open", str(uscita)], check=False)
        except OSError:
            pass
        print(f"Opened: {uscita}")
        print("Waiting for the app to close, then the cache copy is deleted.")
        if os.name == "nt":
            return
        try:
            while _file_aperto(uscita):
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                uscita.unlink()
                print("[+] Cache copy deleted")
            except OSError:
                pass


def apri_editor(radice, nome, sottopercorso=None):
    """Open a decrypted copy in the terminal editor (nano/$EDITOR).
    When the editor exits, any change is encrypted back into the vault."""
    import tempfile
    editor = os.environ.get("EDITOR", "nano")
    contenuto, is_dir = decifra(radice, nome)
    cache = Path.home() / ".cache" / "veil_vault"
    cache.mkdir(parents=True, exist_ok=True)
    if is_dir:
        tmp = Path(tempfile.mkdtemp(prefix="veil_vault_", dir=cache))
        try:
            _avvisa_saltati(estrai_archivio(contenuto, tmp), nome)
            primo = list(tmp.iterdir())
            radice_int = primo[0] if (len(primo) == 1 and primo[0].is_dir()) else tmp
            if not sottopercorso:
                raise ValueError("a folder has no single editor; use open <name>/<file>")
            bersaglio = (radice_int / sottopercorso).resolve()
            if str(bersaglio) != str(tmp.resolve()) and not str(bersaglio).startswith(str(tmp.resolve()) + os.sep):
                raise ValueError(f"{nome}: invalid subpath")
            if not bersaglio.exists() or bersaglio.is_dir():
                raise ValueError(f"{nome}: {sottopercorso} not a file in the folder")
            prima = bersaglio.read_bytes()
            print(f"Editing: {bersaglio}")
            subprocess.run([editor, str(bersaglio)], check=False)
            nuova = bersaglio.read_bytes()
            if nuova == prima:
                print("Unchanged.")
            else:
                nuovo_archivio = riarray_archivio(
                    contenuto, bersaglio, radice_int, nuova)
                cifra(radice, radice_int, nome, magic=MAGIC_DIR, dati=nuovo_archivio)
                verifica_archivio(radice, nome, nuovo_archivio)
                print(f"Saved: {nome} re-encrypted in the vault")
        finally:
            try:
                rmtree(tmp)
                print("[+] Cache copy deleted")
            except OSError:
                pass
    else:
        uscita = cache / nome
        scrivi_vault(uscita, contenuto)
        prima = contenuto
        print(f"Editing: {uscita}")
        try:
            subprocess.run([editor, str(uscita)], check=False)
        except FileNotFoundError:
            print(f"editor '{editor}' not found (set $EDITOR or install nano)")
            uscita.unlink()
            return
        nuova = uscita.read_bytes()
        if nuova == prima:
            print("Unchanged.")
            uscita.unlink()
            return
        cifra(radice, None, nome, dati=nuova)
        verifica_archivio(radice, nome, nuova)
        try:
            uscita.unlink()
            print("[+] Cache copy deleted")
        except OSError:
            pass
        print("Saved: re-encrypted in the vault")


# ----- authentication -----

def cmd_init(args):
    prepara_config()
    if SALT_FILE.exists():
        raise SystemExit("vault: already initialized")
    while True:
        try:
            frase = _chiedi_frase("Choose a vault passphrase (at least 12 characters): ")
        except EOFError:
            raise SystemExit("vault: no passphrase given (stdin ended)")
        if not frase:
            continue
        if len(frase) < 12 and input("Very short, use it anyway? [y/N]: ").strip().lower() != "y":
            continue
        try:
            conferma = _chiedi_frase("Repeat the vault passphrase: ")
        except EOFError:
            raise SystemExit("vault: no passphrase given (stdin ended)")
        if conferma != frase:
            print("They differ, try again")
            continue
        break
    sale = os.urandom(SALT_SIZE)
    # il KDF va deciso e registrato insieme al vault: dopo questo punto
    # kdf_del_vault() legge il record e non puo' piu' cambiare sotto i piedi
    scelta = kdf_attivo()
    scrivi_privato(KDF_FILE, (scelta + "\n").encode())
    scrivi_privato(SALT_FILE, sale)
    radice = radice_kdf(frase, sale, kdf=scelta)
    scrivi_privato(CHECK_FILE, hmac.new(radice, b"veil-vault-check", hashlib.sha256).digest()[:16])
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Vault initialized. KDF: {scelta} | Folder: {VAULT_DIR}")


def acquisisci():
    prepara_config()
    if not SALT_FILE.exists():
        print("First launch: this vault has no passphrase yet.")
        cmd_init(None)
    for _ in range(3):
        frase = legge_frase()
        if not frase:
            continue
        radice = deriva(frase)  # deriva() restituisce None se non verifica
        if radice is not None:
            return radice
        print("[!] Wrong vault passphrase")
    raise SystemExit("vault: too many failed attempts")


# ----- commands (operate on an unlocked master key) -----

def _tipo_item(percorso):
    try:
        with open(percorso, "rb") as f:
            testa = f.read(len(MAGIC_DIR))
    except OSError:
        return ""
    if testa == MAGIC_DIR:
        return " (folder)"
    return ""


def do_list(radice):
    if not VAULT_DIR.exists():
        print("(empty)")
        return
    voci = []
    for p in sorted(VAULT_DIR.glob("*.veil")):
        voci.append((p.name[:-5], p.stat().st_size, p))
    if not voci:
        print("(empty)")
        return
    for nome, size, p in voci:
        print(f"{nome}  ({size} bytes){_tipo_item(p)}")


def verifica_archivio(radice, nome, atteso):
    try:
        dati, is_dir = decifra(radice, nome)
    except ValueError as e:
        raise SystemExit(f"vault: verification failed, original NOT deleted: {e}")
    if dati != atteso:
        raise SystemExit("vault: verification mismatch, original NOT deleted")


def EliminaOriginale(sorgente):
    print()
    if sys.stdin.isatty():
        risposta = input(f"Delete the original plaintext source? [y/N]: ").strip().lower()
        print()
        return risposta in ("y", "yes")
    return False


def do_add(radice, path, nome=None, force=False):
    sorgente = Path(path).expanduser()
    if not sorgente.exists():
        raise SystemExit("vault: file or folder not found")
    is_dir = sorgente.is_dir()
    nome = nome or sorgente.name
    try:
        destinazione = percorso_vault(nome)
    except ValueError as e:
        raise SystemExit(f"vault: {e}")
    if destinazione.exists() and not force:
        raise SystemExit(f"vault: {nome} already in the vault (use -f to overwrite)")
    if is_dir:
        dati = archivia_cartella(sorgente)
        cifra(radice, sorgente, nome, magic=MAGIC_DIR, dati=dati)
        verifica_archivio(radice, nome, dati)
        print(f"Added: {nome}/ (folder)")
    else:
        dati = sorgente.read_bytes()
        cifra(radice, sorgente, nome, dati=dati)
        verifica_archivio(radice, nome, dati)
        print(f"Added: {nome}")
    if EliminaOriginale(sorgente):
        if is_dir:
            rmtree(sorgente, ignore_errors=True)
            print(f"Removed the original folder: {sorgente}")
        else:
            try:
                sorgente.unlink()
                print(f"Removed the original file: {sorgente}")
            except OSError as e:
                print(f"could not remove it: {e}")


def _dividi(arg):
    """'nome' oppure 'nome/sotto/percorso' -> (nome, sottopercorso|None)."""
    if "/" in arg and not arg.endswith("/"):
        nome, sottopercorso = arg.split("/", 1)
        return nome, sottopercorso
    return arg, None


def do_ls(radice, arg):
    nome, sottopercorso = _dividi(arg.rstrip("/"))
    try:
        voci = voci_cartella(radice, nome, sottopercorso)
    except (ValueError, OSError) as e:
        print(f"vault: {e}")
        return
    if not voci:
        print("(empty folder)")
        return
    _stampa_albero(_albero(voci))
    n_dir = sum(1 for v in voci if v[1] == "dir")
    n_file = sum(1 for v in voci if v[1] == "file")
    n_link = sum(1 for v in voci if v[1] == "link")
    n_tot = sum(v[2] for v in voci)
    extra = f", {n_link} link{'s' if n_link != 1 else ''}" if n_link else ""
    print(f"\n{n_dir} director{'ies' if n_dir != 1 else 'y'}, "
          f"{n_file} file{'s' if n_file != 1 else ''}{extra}, "
          f"{n_tot} byte{'s' if n_tot != 1 else ''}")


def do_open(radice, arg, editor=False):
    nome, sottopercorso = _dividi(arg)
    try:
        if editor:
            apri_editor(radice, nome, sottopercorso)
        else:
            apri(radice, nome, sottopercorso)
    except ValueError as e:
        print(f"vault: {e}")


def do_export(radice, dest):
    uscita = Path(dest).expanduser()
    uscita.mkdir(parents=True, exist_ok=True)
    n = 0
    for nome, _ in elenca():
        try:
            dati, is_dir = decifra(radice, nome)
        except ValueError as e:
            print(f"skipping {nome}: {e}")
            continue
        if is_dir:
            # export della cartella: le voci non estraibili vengono segnalate
            # ma non fanno perdere il resto del contenuto
            _avvisa_saltati(estrai_archivio(dati, uscita), nome)
        else:
            scrivi_vault(uscita / nome, dati)
        n += 1
    print(f"Exported {n} items to {uscita}")


def do_rm(radice, nome):
    try:
        percorso = percorso_vault(nome)
    except ValueError as e:
        raise SystemExit(f"vault: {e}")
    if not percorso.exists():
        raise SystemExit("vault: not in the vault")
    percorso.unlink()
    print(f"Removed: {nome}")


# ----- one-shot wrappers -----

def cmd_list(args):
    do_list(acquisisci())


def cmd_ls(args):
    do_ls(acquisisci(), args.name)


def cmd_add(args):
    do_add(acquisisci(), args.path, args.name, args.force)


def cmd_open(args):
    do_open(acquisisci(), args.name)


def cmd_export(args):
    do_export(acquisisci(), args.dir)


def cmd_rm(args):
    do_rm(acquisisci(), args.name)


# ----- interactive shell -----

def banner():
    try:
        subprocess.run(["figlet", "-f", "slant", "Veil_vault"])
    except FileNotFoundError:
        print("V E I L _ V A U L T")


AIUTO = """Commands:
  list              show the items in the vault
  ls <name>         list the content of a stored folder
  ls <name>/<path>  list a subfolder of a stored folder
  add <path>        encrypt a file or folder into the vault  (-f overwrite, -n <name>)
  open <name>       open a file in your editor (nano/$EDITOR)
  open <name>/<path> open a single file inside a stored folder
  export <dir>      decrypt every item into a plaintext folder
  rm <name>         remove an item from the vault
  help              show this help
  q / quit          exit
"""


def elabora(riga, radice):
    pulito = riga.strip()
    if not pulito:
        return True
    parole = pulito.split()
    cmd = parole[0].lower()
    if cmd in ("q", "quit", "exit"):
        return False
    if cmd in ("h", "help", "?"):
        print(AIUTO)
        return True
    if cmd == "list":
        do_list(radice)
        return True
    if cmd == "ls":
        if len(parole) < 2:
            print("Usage: ls <name>  or  ls <name>/<subpath>")
            return True
        do_ls(radice, parole[1])
        return True
    if cmd == "add":
        path = None
        nome = None
        force = False
        i = 1
        while i < len(parole):
            p = parole[i]
            if p in ("-f", "--force"):
                force = True
            elif p in ("-n", "--name") and i + 1 < len(parole):
                nome = parole[i + 1]
                i += 1
            else:
                path = p
            i += 1
        if path is None:
            print("Usage: add <path> [-f] [-n name]")
            return True
        try:
            do_add(radice, path, nome, force)
        except SystemExit as e:
            print(e)
        return True
    if cmd == "open":
        if len(parole) < 2:
            print("Usage: open <name>  or  open <name>/<path>")
            return True
        do_open(radice, parole[1], editor=True)
        return True
    if cmd == "export":
        do_export(radice, parole[1] if len(parole) > 1 else ".")
        return True
    if cmd == "rm":
        if len(parole) < 2:
            print("Usage: rm <name>")
            return True
        try:
            do_rm(radice, parole[1])
        except SystemExit as e:
            print(e)
        return True
    print(f"Unknown command: {cmd} (try 'help')")
    return True


def repl():
    banner()
    prepara_config()
    if not SALT_FILE.exists():
        print("First launch: this vault has no passphrase yet.")
        cmd_init(None)
    radice = None
    while radice is None:
        print("Unlock the vault (this terminal session only).")
        try:
            radice = acquisisci()
        except SystemExit as e:
            print(e)
            return
    print(f"Vault: {VAULT_DIR} | unlocked for this terminal only")
    print("(q to quit)\n")
    try:
        while True:
            try:
                riga = input(">>> ")
            except (KeyboardInterrupt, EOFError):
                print("\nBye!")
                break
            if not elabora(riga, radice):
                print("Bye!")
                break
    finally:
        pass


def main():
    parser = argparse.ArgumentParser(
        prog="vault",
        description="Encrypted file vault with its own passphrase. Run `vault` with no "
                    "arguments for the interactive shell, or use the subcommands directly.",
    )
    sotto = parser.add_subparsers(dest="comando")

    p = sotto.add_parser("init", help="create the vault and choose its passphrase")
    p.set_defaults(fun=cmd_init)

    p = sotto.add_parser("list", help="show the files in the vault")
    p.set_defaults(fun=cmd_list)

    p = sotto.add_parser("ls", help="list the content of a folder in the vault (nothing is extracted)")
    p.add_argument("name", help="folder name, or <name>/<subpath>")
    p.set_defaults(fun=cmd_ls)

    p = sotto.add_parser("add", help="encrypt a file or folder into the vault")
    p.add_argument("path")
    p.add_argument("-n", "--name", help="store it under a different name")
    p.add_argument("-f", "--force", action="store_true", help="overwrite an existing item")
    p.set_defaults(fun=cmd_add)

    p = sotto.add_parser("open", help="open a file, or extract a folder (optionally a file inside it)")
    p.add_argument("name", help="item name, or <name>/<path> for a file inside a folder")
    p.set_defaults(fun=cmd_open)

    p = sotto.add_parser("export", help="decrypt every file into a plaintext folder")
    p.add_argument("dir")
    p.set_defaults(fun=cmd_export)

    p = sotto.add_parser("rm", help="remove an item from the vault")
    p.add_argument("name")
    p.set_defaults(fun=cmd_rm)

    args = parser.parse_args()
    if args.comando is None:
        repl()
        return
    args.fun(args)


if __name__ == "__main__":
    main()
