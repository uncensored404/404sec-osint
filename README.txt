# 404sec

OSINT / CSINT reconnaissance toolkit. Domaines, IP, emails, pseudos, téléphones,
crypto, hashes, CVE et fichiers. Modules async, pivot récursif, watch + diff,
cache SQLite, exports JSON/CSV/MD/HTML/Graphviz.

by 404sec — v1.1.0 — MIT

## Installation

pip install -r requirements.txt

## Clés optionnelles

Les modules correspondants se désactivent proprement si la variable est absente.

export SHODAN_KEY=ta_cle
export CENSYS_ID=ton_id
export CENSYS_SECRET=ton_secret
export VT_KEY=ta_cle
export HIBP_KEY=ta_cle

## Usage

python 404sec.py example.com -v
python 404sec.py example.com --pivot --pivot-depth 1 --graph infra.dot
python 404sec.py 8.8.8.8 --only geoip,ports,shodan
python 404sec.py --targets domaines.txt --resume --json out/{t}.json
python 404sec.py example.com --watch 3600 --diff snap.json --only-new
python 404sec.py photo.jpg
python 404sec.py --list-modules

## Modules

(la sortie de --list-modules)

## Limites

- pivot borné par --pivot-depth, --rate à surveiller
- --watch ne diffère que dans la session, utiliser --diff sur un export pour du suivi long
- scan de ports = TCP connect, pas de SYN
- usage passif, à réserver aux cibles autorisées