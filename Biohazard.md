# Biohazard — TryHackMe | Write-up

> **Machine:** Biohazard
> **Platform:** TryHackMe
> **Difficulty:** Medium
> **Theme:** Resident Evil (the mansion, the emblems, the crests and the traitor Weasker)
> **IP (this session):** `10.82.165.234`

A huge room full of chained puzzles: every item unlocks the next one. It's more of a "collect items and decode stuff" CTF than a service-exploitation one. The idea is to explore the mansion room by room, collect emblems/items, decode layers of encoding, and keep unlocking doors until you land on real FTP → SSH → root credentials.

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Web Enumeration — "the mansion"](#2-web-enumeration--the-mansion)
3. [Shield Key (Vigenère)](#3-shield-key-vigenère)
4. [The 4 crests → FTP credentials](#4-the-4-crests--ftp-credentials)
5. [FTP: steganography + GPG → Helmet Key](#5-ftp-steganography--gpg--helmet-key)
6. [New doors: studyRoom and hiddenCloset](#6-new-doors-studyroom-and-hiddencloset)
7. [SSH access](#7-ssh-access)
8. [Pivot: umbrella_guest → weasker](#8-pivot-umbrella_guest--weasker)
9. [Privilege escalation → root](#9-privilege-escalation--root)
10. [Chain summary](#10-chain-summary)

---

## 1. Enumeration

Start with the usual `nmap`:

```bash
nmap -sC -sV -oN nmap.txt 10.82.165.234
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Beginning of the end
```

Three ports: FTP (no anonymous access for now), SSH and an Apache server. FTP and SSH most likely come into play later — the way in is the web.

---

## 2. Web Enumeration — "the mansion"

The home page (`http://10.82.165.234/`) is just a themed screen ("Beginning of the end"). Directory fuzzing:

```bash
gobuster dir -u http://10.82.165.234/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt
```

The output looks like **a map of the mansion** — each directory is a room:

```
/diningRoom/
/teaRoom/
/artRoom/
/barRoom/
/diningRoom2F/
/tigerStatusRoom/
/galleryRoom/
/studyRoom/      (locked at first)
/armorRoom/
/attic/          (locked at first)
```

Going room by room (and always reading each page's **source code** — `Ctrl+U`), the first items/flags start showing up:

```
emblem{fec832623ea498e20bf4fe1821d58727}
lock_pick{037b35e2ff90916a9abf99129c8e1837}
music_sheet{362d72deaf65f5bdc63daece6a1f676e}
gold_emblem{58a8c41a9d08b8a4e38d02a4d7ff4843}
blue_jewel{e1d457e96cac640f863ec7bc475d48aa}
```

Hints scattered across the pages point the way from one room to the next, for example:

> *"You get the blue gem by pushing the status to the lower floor. The gem is on the diningRoom first floor. Visit `sapphire.html`"*

In other words: the rooms have **hidden pages** (`sapphire.html`, `emblem_slot.php`, etc.) that only show up if you read the hints or fuzz inside each directory.

You can also pull some likely usernames from the theme/pages:

```
Chris, Jill, Barry, Weasker, Joseph, Kenneth
```

---

## 3. Shield Key (Vigenère)

Inside `barRoom` there is an "emblem slot": `emblem_slot.php`. Submitting the emblem we already have:

```
http://10.82.165.234/barRoom<hash>/emblem_slot.php   (+ emblem{...})
→ rebecca
```

That lone word, `rebecca`, is a **Vigenère key**.

A second slot (in `diningRoom`, submitting the `gold_emblem`) returns a **ciphertext**. Since it's Vigenère, just drop it into [CyberChef](https://gchq.github.io/CyberChef/) → **Vigenère Decode** operation with key `rebecca`, or use dcode.fr. The result points to the flag:

```
shield_key{48a7a9227cd7eb89f0a062590798cbac}
```

> 💡 Vigenère preserves spaces, punctuation and `_`, it only scrambles the letters. If the decoded text still looks "scrambled", the key is wrong.

---

## 4. The 4 crests → FTP credentials

Scattered across the rooms there are **4 crests**, each encoded in several layers. The hints themselves say:

> *"You need to collect all 4 crests, combine and decode to reveal another path. The combination should be crest 1 + crest 2 + crest 3 + crest 4."*

Each crest, once decoded through its layers, becomes a **Base64 fragment**:

| Crest | Encoding | Fragment |
|---|---|---|
| Crest 1 | Base64 → Base32 | `RlRQIHVzZXI6IG` |
| Crest 2 | Base32 (two layers) | `h1bnRlciwgRlRQIHBh` |
| Crest 3 | Base64 → binary → hex | `c3M6IHlvdV9jYW50X2g` |
| Crest 4 | (layers) | `...ide_forever` |

Example with crest 1:

```bash
echo 'S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9' | base64 -d        # → KJWFEUKJJBLHUWSYJE3ESRY=  (Base32)
echo 'KJWFEUKJJBLHUWSYJE3ESRY=' | base32 -d                 # → RlRQIHVzZXI6IG
```

**Concatenating the 4 fragments in order** and decoding the final Base64:

```bash
echo 'RlRQIHVzZXI6IGh1bnRlciwgRlRQIHBhc3M6IHlvdV9jYW50X2hpZGVfZm9yZXZlcg==' | base64 -d
```

```
FTP user: hunter, FTP pass: you_cant_hide_forever
```

🎯 **FTP** credentials:

```
hunter : you_cant_hide_forever
```

---

## 5. FTP: steganography + GPG → Helmet Key

```bash
ftp 10.82.165.234      # hunter / you_cant_hide_forever
ftp> ls -la
```

```
001-key.jpg
002-key.jpg
003-key.jpg
helmet_key.txt.gpg
important.txt
```

> ⚠️ **Environment tip:** on Ubuntu, the `ftp` client (`tnftp`) ships with an **AppArmor** profile that only allows writing to `~/Downloads` and `/tmp`. If you get *"Permission denied"* even with `226 Transfer complete`, download into `~/Downloads` or use `wget`:
> ```bash
> wget -r -nH ftp://hunter:you_cant_hide_forever@10.82.165.234/
> ```

### important.txt

```
Jill,
I think the helmet key is inside the text file, but I have no clue on decrypting stuff.
Also, I come across a /hidden_closet/ door but it was locked.
From, Barry
```

Two pieces of info: the *helmet key* is inside the `.gpg`, and there's a new `/hidden_closet/` door.

### The three images — each hides something a different way

Running the full stego checklist on each image (`file`, `exiftool`, `strings`, `binwalk`, `steghide`):

```bash
# 001 — steghide with an EMPTY password
steghide extract -sf 001-key.jpg -p ""
cat key-001.txt            # → cGxhbnQ0Ml9jYW

# 002 — in the JPEG comment
exiftool 002-key.jpg | grep -i comment      # → 5fYmVfZGVzdHJveV9

# 003 — ZIP appended to the end of the image
binwalk -e 003-key.jpg
cat _003-key.jpg.extracted/key-003.txt       # → 3aXRoX3Zqb2x0
```

The three pieces are, again, **Base64 fragments**. Joining `001 + 002 + 003`:

```bash
echo 'cGxhbnQ0Ml9jYW5fYmVfZGVzdHJveV93aXRoX3Zqb2x0' | base64 -d
```

```
plant42_can_be_destroy_with_vjolt
```

That is the **passphrase** of the GPG file (symmetric AES256 encryption):

```bash
gpg -d helmet_key.txt.gpg       # passphrase: plant42_can_be_destroy_with_vjolt
```

This reveals the **helmet key**, which unlocks the two doors that were locked.

---

## 6. New doors: studyRoom and hiddenCloset

With the helmet key, both doors open (with a hash in the path, like the rest of the room):

### `/studyRoom<hash>/`

Downloads a `doom.tar.gz` file:

```bash
tar -xzf doom.tar.gz
cat eagle_medal.txt
```

```
SSH user: umbrella_guest
```

### `/hiddenCloset<hash>/`

Gives up two things:

```
SSH password: T_virus_rules

(ciphertext, Vigenère):
wpbwbxr wpkzg pltwnhro, txrks_xfqsxrd_bvv_fy_rvmexa_ajk
```

The SSH password comes ready to use. The ciphertext is set aside — we **don't have its key yet** (it shows up after login).

🎯 **SSH** credentials:

```
umbrella_guest : T_virus_rules
```

---

## 7. SSH access

```bash
ssh umbrella_guest@10.82.165.234     # T_virus_rules
```

```
umbrella_guest@umbrella_corp:~$ id
uid=1001(umbrella_guest) gid=1001(umbrella) groups=1001(umbrella)
```

In the home folder one hidden directory stands out: **`.jailcell`**. That's where we find **Chris**, locked up — exactly like in the story:

```bash
cat ~/.jailcell/chris.txt
```

```
Chris: Jill, you finally come. I was locked in the Jail cell for a while.
       It seem that weasker is behind all this.
...
Chris: here, take this MO Disk 2 with you. It look like the key to decipher something.

MO disk 2: albert
```

👉 `albert` is the **Vigenère key** for that ciphertext we saved from the hiddenCloset.

```bash
# Vigenère Decode, key = albert
# wpbwbxr wpkzg pltwnhro, txrks_xfqsxrd_bvv_fy_rvmexa_ajk
```

```
weasker login password, stars_members_are_my_guinea_pig
```

🎯 Password for the **weasker** user:

```
weasker : stars_members_are_my_guinea_pig
```

> Looking at `/etc/passwd`, `weasker` is **uid 1000** with `/bin/bash` — the main user of the box (and the traitor in the story).

---

## 8. Pivot: umbrella_guest → weasker

```bash
su weasker          # stars_members_are_my_guinea_pig
```

```
weasker@umbrella_corp:~$ id
uid=1000(weasker) gid=1000(weasker) groups=1000(weasker),4(adm),24(cdrom),27(sudo),...
```

`weasker` is in the **sudo** group. The home folder also has the story's ending (`weasker_note.txt`), where the Tyrant kills Weasker and Jill escapes.

---

## 9. Privilege escalation → root

```bash
sudo -l
```

```
User weasker may run the following commands on umbrella_corp:
    (ALL : ALL) ALL
```

`weasker` can run **any command as root**. Direct escalation:

```bash
sudo -i
id            # uid=0(root)
cat /root/root.txt
```

🏁 **Root.** Game over.

---

## 10. Chain summary

```
nmap (21/22/80)
   │
   ▼
Web "mansion" → emblems/items + per-room hints
   │
   ├── emblem_slot.php (emblem) → key "rebecca" ─┐
   │                                             ▼ Vigenère
   │   gold_emblem → ciphertext ────────────► shield_key{...}
   │
   ├── 4 crests (Base64/Base32/binary/hex) → combine → Base64
   │        → FTP: hunter : you_cant_hide_forever
   │
   ▼
FTP → 3 images (steghide / EXIF comment / appended zip)
   │        → Base64 fragments → "plant42_can_be_destroy_with_vjolt"
   │        → gpg -d helmet_key.txt.gpg → HELMET KEY
   │
   ├── studyRoom  → doom.tar.gz → SSH user: umbrella_guest
   └── hiddenCloset → SSH pass: T_virus_rules + Vigenère text
   │
   ▼
SSH umbrella_guest → ~/.jailcell/chris.txt → key "albert"
   │        → Vigenère → weasker password (stars_members_are_my_guinea_pig)
   │
   ▼
su weasker → sudo -l → (ALL : ALL) ALL → sudo -i → ROOT
```

### Flags collected

| Item | Flag |
|---|---|
| emblem | `emblem{fec832623ea498e20bf4fe1821d58727}` |
| lock_pick | `lock_pick{037b35e2ff90916a9abf99129c8e1837}` |
| music_sheet | `music_sheet{362d72deaf65f5bdc63daece6a1f676e}` |
| gold_emblem | `gold_emblem{58a8c41a9d08b8a4e38d02a4d7ff4843}` |
| blue_jewel | `blue_jewel{e1d457e96cac640f863ec7bc475d48aa}` |
| shield_key | `shield_key{48a7a9227cd7eb89f0a062590798cbac}` |

---

## Tools used

`nmap` · `gobuster` · `base64` / `base32` · CyberChef (Vigenère, From Base) · `ftp` / `wget` · `exiftool` · `binwalk` · `steghide` · `gpg` · `tar` · `ssh` · `su` · `sudo`

## Lessons / takeaways

- **Read the source of every page** and fuzz *inside* each directory — a lot is hidden in unlinked `.html`/`.php` files.
- On CTF images, test **every** stego technique: metadata (EXIF comment), appended data (`binwalk`), and `steghide` (always try an **empty password**).
- A `base64 -d` that "almost" works → there's probably **another layer** (Base32, binary, hex...). Keep peeling.
- Vigenère preserving spaces/punctuation is a great tell; the key is usually planted in another file ("MO disk", a note, etc.).
- In post-exploitation, `sudo -l` is always the first stop. `sudo` group + `(ALL:ALL) ALL` = instant root.
```
