# Veil 2 — installazione

Tre macchine, tre ruoli. Nessuna richiede root per usarlo.

| macchina | ruolo | cosa le serve |
|---|---|---|
| Debian | hub (relay) + DuckDNS | un IP pubblico raggiungibile |
| Void (questo PC) | client | niente |
| Mint (l'altro PC) | client | niente |

Il client non è un servizio: lo lancii quando vuoi chattare. Niente daemon,
niente `sudo`, niente WireGuard, niente `wg`, niente aperture di porte.

---

## 1. Server Debian

### 1.1 Pacchetti

```sh
sudo apt update
sudo apt install -y python3 python3-cryptography curl
```

`python3-cryptography` serve all'hub solo per generare il certificato
autofirmato. `curl` serve a DuckDNS.

### 1.2 Utente dedicato e cartelle

L'hub non ha bisogno di root. Gli diamo un utente suo.

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin veil2
sudo install -d -o veil2 -g veil2 -m 0750 /opt/veil2
sudo install -d -o veil2 -g veil2 -m 0750 /etc/veil2
sudo install -d -o veil2 -g veil2 -m 0700 /etc/veil2/tls
sudo install -d -o veil2 -g veil2 -m 0750 /var/lib/veil2
```

### 1.3 Copia dell'hub

```sh
sudo install -m 0755 hub.py /opt/veil2/hub.py
```

### 1.4 Certificato e impronta

```sh
sudo -u veil2 python3 /opt/veil2/hub.py --genera-tls /etc/veil2/tls --hostname miohub.duckdns.org
```

Stampa l'impronta SHA-256 del certificato, una riga tipo:

```
impronta SHA-256: 9d:9b:59:9f:...:86:b4
```

**Segnala questa impronta**: è quella che i due PC dovranno pinnare, e
l'unico modo per essere sicuri di parlare col proprio hub e non con qualcun
altro è confrontarla a voce o guardandosi. L'hub la ristampa identica ogni
volta che parte.

Se il dominio non è ancora deciso, puoi rimandare: il nome dentro al
certificato non viene controllato (col pin si controlla l'impronta).

### 1.5 Avvio come servizio

```sh
sudo install -m 0644 systemd/veil2-hub.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now veil2-hub
systemctl status veil2-hub
```

Per leggere cosa sta succedendo:

```sh
sudo journalctl -u veil2-hub -f
```

Se hai scelto una porta sopra la 1024 (vedi 1.7), modifica `ExecStart` prima
di installare l'unit.

### 1.6 Firewall

Serve **una sola regola**. Nessun UDP, nessuna 51820, nessuna 50001.

```sh
sudo ufw allow 443/tcp comment 'veil2 hub'
sudo ufw status verbose
```

Verifica che SSH sia ancora aperto prima di anything else:

```sh
sudo ufw status | grep -i ssh
```

Se usi `firewalld` invece di ufw:

```sh
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

Nei PC client invece non si apre **niente**: devono solo poter uscire.

```sh
# sul client Void, se vuoi restringerlo:
sudo nft add rule inet filter output tcp dport 443 accept
sudo nft add rule inet filter output ct state established,related accept
```

### 1.7 Se il Debian sta dietro un router di casa

Questo è il caso in cui ti serve DuckDNS **e** il port forwarding.

- Router: inoltra **TCP 443** dall'esterno all'IP locale del Debian.
  (Servizio "port forwarding" / "virtual server" / "NAT".)
- Se il tuo IP pubblico è dinamico, l'IP del Debian non è raggiungibile finché
  non lo aggiorni: è il compito di `duckdns.sh` (§2).
- Se invece il Debian è un VPS con IP pubblico fisso, **DuckDNS non ti serve**
  e puoi saltare tutta la §2.

Per non dipendere dalla porta 443 (e non aver bisogno di `CAP_NET_BIND_SERVICE`),
puoi anche far ascoltare l'hub sulla 8443 e inoltrare quella. In quel caso
nell'unit togli `AmbientCapabilities` e `CapabilityBoundingSet`, e i client
useranno `miohub.duckdns.org:8443`.

---

## 2. DuckDNS

DuckDNS serve a una cosa sola: dire al mondo "il mio IP pubblico è questo".
Va installato **sul Debian**, non sui PC client: il dominio deve puntare
all'hub, e l'hub è l'unica macchina con un IP pubblico.

### 2.1 Creare il dominio

1. Vai su <https://www.duckdns.org> e accedi (GitHub o Google).
2. In basso trovi il tuo **token**: una stringa tipo
   `abcdef01-2345-6789-abcd-ef0123456789`. Conservala.
3. In "Subdomains" scegli un nome, per esempio `miohub`. Il dominio completo
   sarà `miohub.duckdns.org`.

### 2.2 Installare lo script

```sh
sudo install -m 0755 duckdns.sh /usr/local/sbin/duckdns.sh
sudo install -m 0640 -o root -g veil2 duckdns.conf.example /etc/veil2/duckdns.conf
sudo nano /etc/veil2/duckdns.conf
```

Nel file metti il token e il nome del dominio **senza** `.duckdns.org`:

```
DUCKDNS_TOKEN="abcdef01-2345-6789-abcd-ef0123456789"
DUCKDNS_DOMAIN="miohub"
DUCKDNS_VEDUTO="/var/lib/veil2/duckdns.ultimo"
```

Il file è `root:veil2 0640`: il token non è leggibile dagli altri utenti.

### 2.3 Avviarlo — qui sta la risposta alla domanda

Non in cron e non a mano: **un timer systemd**, che parte subito e poi ogni
5 minuti, e soprattutto **dopo che la rete è su** (altrimenti al primo avvio
proverebbe a chiedere il DNS senza rete e fallirebbe).

```sh
sudo install -m 0644 systemd/veil2-duckdns.service /etc/systemd/system/
sudo install -m 0644 systemd/veil2-duckdns.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now veil2-duckdns.timer
```

Controlla che il timer sia registrato:

```sh
systemctl list-timers veil2-duckdns.timer
```

Fai girare un aggiornamento subito, senza aspettare i 5 minuti:

```sh
sudo systemctl start veil2-duckdns.service
journalctl -u veil2-duckdns -n 20 --no-pager
```

Se è andato bene vedrai una riga sola:

```
duckdns: miohub.duckdns.org -> 93.184.216.34
```

Se l'IP non è cambiato, il giro dopo non scrive niente: è apposta, così il
journal non si riempie ogni 5 minuti.

In caso di problemi:

```sh
systemctl status veil2-duckdns.timer
journalctl -u veil2-duckdns -n 50 --no-pager
```

Errori tipici:

- `risposta 'KO' TOKEN NON VALIDO` → il token è sbagliato o ha dentro gli spazi.
- `curl ha fallito` → manca `curl`, o la rete non è ancora su.
- `non leggo /etc/veil2/duckdns.conf` → file non leggibile dall'utente `veil2`.

### 2.4 Verificare che il dominio punti qui

```sh
getent hosts miohub.duckdns.org
```

Deve dare l'IP pubblico del Debian. Se non è aggiornato, il resolver lo
ricarica entro qualche minuto.

Prova end-to-end dalla porta:

```sh
python3 -c "import socket; socket.create_connection(('miohub.duckdns.org',443),10); print('443 aperta')"
```

---

## 3. Client (questo PC Void, e l'altro Mint)

### 3.1 Pacchetti

Void:

```sh
sudo xbps-install -Suy
sudo xbps-install python3-cryptography libargon2 python3-qrcode
```

Mint:

```sh
sudo apt update
sudo apt install -y python3-cryptography libargon2-1 python3-qrcode
```

`python3-qrcode` serve solo per il QR dell'invito: senza, funziona tutto lo
resto. `libargon2` (o `libargon2-1`) serve per il KDF Argon2id: senza,
`veil_2.py` cade su PBKDF2 e **i due PC non si parlano** se uno ce l'ha e
l'altro no. Se lo installi dopo, allinea i due con `veil2.py --migra-kdf argon2id`.

Su questo Void `python3-cryptography` e `libargon2` ci sono già; manca solo
`python3-qrcode`, che è facoltativo.

### 3.2 Copia dello script

```sh
sudo install -d -m 0755 ~/bin
install -m 0755 veil_2.py ~/bin/veil2.py
export PATH="$HOME/bin:$PATH"   # mettilo in ~/.bashrc per tenerlo
```

Nessun `sudo` per usarlo. Nessun servizio, nessun runit: è un programma da
terminale.

### 3.3 Primo avvio

Al primo lancio ti chiede una **passphrase del PC** (almeno 12 caratteri).
Non è quella del contatto, e serve a cifrare identità e rubrica su disco.
La chiede una volta sola.

```sh
veil2.py
```

### 3.4 Agganciare l'hub e pinnarlo

```sh
veil2.py imposta-hub miohub.duckdns.org
```

Stampa l'impronta del certificato e chiede se pinnarla. **Prima di dire `s`,
confrontala con quella stampata sul Debian (§1.4)**: devono essere identiche
carattere per carattere. Se non lo sono, qualcuno si è messo in mezzo:
chiudi e indaga.

Il comando con `--pin` che ti ha stampato §1.4 fa la stessa cosa, se preferisci
non rispondere alle domande.

### 3.5 Creare il contatto

Sul PC che "inizia":

```sh
veil2.py nuovo mario
```

Stampa una riga tipo:

```
veil2.py aggiungi mario v1.mario.4Fzp...aBc9
```

e un QR. **Quella riga è tutto il canale**: chi la legge può leggere i
messaggi. Portala all'altro PC di persona, o su un canale che consideri
affidabile. È anche salvata in `~/.veil2-inviti/mario.invito`.

Sull'altro PC:

```sh
veil2.py aggiungi mario v1.mario.4Fzp...aBc9
```

### 3.6 Chattare

```sh
veil2.py
```

Al primo incontro con quel contatto i due PC si mostrano a vicenda le
impronte delle loro chiavi e chiedono conferma. È l'unica verifica possibile
fra due macchine nuove: fatela guardando lo schermo dell'altro, non al
telefono. Se non confermi, la connessione si chiude e il contatto resta senza
pin.

Nella chat:

| cosa scrivi | cosa succede |
|---|---|
| `mario` | scegli il contatto |
| `mario ciao` | gli scrivi subito |
| `q` | torni alla lista |
| `?` | lista dei contatti con lo stato |
| `/percorso/file` | invii un file |
| `x` | esci |

I file arrivano in `~/localdrop/`, i log in `~/localdrop/messaggi/<nick>/`.

```sh
veil2.py --leggi-log mario
```

### 3.7 Quando qualcosa non torna

```sh
veil2.py stato            # l'hub è vivo? quante stanze, quante coppie
veil2.py hub              # che hub sto usando
veil2.py impronta         # il pin attuale e l'impronta attuale dell'hub
veil2.py --leggi-log mario
```

Se l'hub non risponde ma il PC è sulla rete, quasi sempre è il firewall o
il port forwarding. Se risponde ma i due PC non si vedono, il problema è
dall'altra parte: passphrase diverse, o `room_secret` diversi.

---

## 4. Cosa NON fa questo, detto chiaramente

- **L'hub non è privato.** Chi ha il tuo dominio e la tua stanza può
  collegarsi. Non vede i contenuti, ma vede le connessioni e da dove arrivano.
  Se ti serve anche quello, metti davanti un WireGuard o una VPN.
- **La passphrase del PC è salvata in chiaro** in
  `~/.config/veil2/password` (permessi `0600`). Protegge da chi legge la tua
  home in giro, non da root né da un malware. I *log delle chat* invece sono
  cifrati con la passphrase del **contatto**, che non viene mai salvata: quelli
  sono realmente protetti.
- **Il pin è la prima conoscenza.** Se lo pinni senza guardare, hai fidato
  l'hub sbagliato. Se non lo pinni, sei vulnerabile a un uomo in mezzo.
  L'hub con `--pin` non si collega e lo dice.
- **Niente recupero.** Se perdi l'invito, perdi il contatto. Se perdi la
  passphrase del PC, perdi identità e rubrica (i log restano, si rileggono
  con la passphrase del contatto).
- **Niente IPv6 nativo.** L'hub ascolta su IPv4. Ai PC non serve un IP
  pubblico: fanno una connessione in uscita e basta.

---

## 5. Manutenzione

```sh
# nuovo certificato (stesso hostname): i due PC dovranno ripinnare
sudo systemctl stop veil2-hub
sudo rm /etc/veil2/tls/cert.pem /etc/veil2/tls/key.pem
sudo -u veil2 python3 /opt/veil2/hub.py --genera-tls /etc/veil2/tls --hostname miohub.duckdns.org
sudo systemctl start veil2-hub
# poi sui due PC:  veil2.py impronta <nuova_impronta>
```

Cambiare la passphrase del PC:

```sh
veil2.py --cambia-password
```
