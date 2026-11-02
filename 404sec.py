#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  404sec — OSINT / CSINT reconnaissance toolkit
  by 404sec
================================================================================
  Domaines · IP · emails · pseudos · téléphones · crypto · hashes · CVE · fichiers
  Pivot récursif · watch + diff · reprise · Graphviz · exports JSON/CSV/HTML/MD

  Usage passif uniquement (aucun paquet forgé). Le scan de ports est un TCP connect.
================================================================================
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import html as html_mod
import ipaddress
import json
import os
import random
import re
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import aiohttp
from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)
from rich.table import Table

try:
    import dns.asyncresolver
    import dns.exception
    import dns.query
    import dns.resolver
    import dns.reversename
    import dns.zone
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import phonenumbers
    HAS_PHONE = True
except ImportError:
    HAS_PHONE = False

try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


VERSION = "1.1.0"
AUTHOR  = "404sec"

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

BANNER = r"""
   ___  _  _   ___  ___  ___
  | __|/ |/ | / _ \| _ \/ __|  404sec
  |__ \_  _|| (_) |  _/\__ \  OSINT / CSINT toolkit v""" + VERSION + r"""
  |___/ |_|  \___/|_|  |___/  by """ + AUTHOR + r"""
"""

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow",
             "low": "cyan", "info": "dim"}

SUBDOMAINS = """www mail remote blog webmail server ns1 ns2 ns3 smtp secure vpn
m mta pop imap test dev staging stage preprod uat prod app api apis gateway
admin panel cpanel whm dashboard portal intranet extranet internal private
corp office git gitlab github bitbucket svn jenkins ci cd build deploy docker
k8s kubernetes registry nexus artifactory jira confluence wiki docs doc help
support status monitor monitoring grafana prometheus kibana elastic logs
metrics stats analytics tracking cdn static assets img images media files
upload uploads download downloads ftp sftp ssh db mysql postgres mongo redis
cache proxy lb loadbalancer haproxy nginx apache web web1 web2 web3 host node
cloud aws azure gcp s3 backup backups old new v1 v2 v3 beta alpha demo sandbox
lab research archive store shop pay payment billing invoice crm erp hr
webdisk autodiscover autoconfig mx mx1 mx2 email webmail2 exchange owa
security sip voip pbx meet chat conference video calendar drive cloud mail2
""".split()

PLATFORMS = {
    "GitHub":      ("https://github.com/{}",             [200], ["Not Found"]),
    "GitLab":      ("https://gitlab.com/{}",             [200], ["Page not found"]),
    "Bitbucket":   ("https://bitbucket.org/{}",          [200], ["not found"]),
    "Reddit":      ("https://www.reddit.com/user/{}",    [200], ["page not found"]),
    "Twitter/X":   ("https://x.com/{}",                  [200], []),
    "Instagram":   ("https://www.instagram.com/{}/",     [200], ["Page Not Found"]),
    "Facebook":    ("https://www.facebook.com/{}",       [200], []),
    "TikTok":      ("https://www.tiktok.com/@{}",        [200], ["Couldn't find"]),
    "YouTube":     ("https://www.youtube.com/@{}",       [200], ["404"]),
    "Twitch":      ("https://www.twitch.tv/{}",          [200], ["404"]),
    "Pinterest":   ("https://www.pinterest.com/{}/",     [200], ["Page not found"]),
    "Flickr":      ("https://www.flickr.com/people/{}",  [200], ["Page Not Found"]),
    "Vimeo":       ("https://vimeo.com/{}",              [200], ["Page not found"]),
    "SoundCloud":  ("https://soundcloud.com/{}",         [200], ["Page not found"]),
    "Medium":      ("https://medium.com/@{}",            [200], ["Page not found"]),
    "Dev.to":      ("https://dev.to/{}",                 [200], ["Page not found"]),
    "Keybase":     ("https://keybase.io/{}",             [200], ["Page not found"]),
    "HackerNews":  ("https://news.ycombinator.com/user?id={}", [200], ["No such user"]),
    "Lobsters":    ("https://lobste.rs/~{}",             [200], ["Page not found"]),
    "Codeberg":    ("https://codeberg.org/{}",           [200], ["Page not found"]),
    "Docker Hub":  ("https://hub.docker.com/u/{}",       [200], ["not found"]),
    "npm":         ("https://www.npmjs.com/~{}",         [200], ["Not found"]),
    "PyPI":        ("https://pypi.org/user/{}/",         [200], ["not found"]),
    "Kaggle":      ("https://www.kaggle.com/{}",         [200], ["Page Not Found"]),
    "Replit":      ("https://replit.com/@{}",            [200], ["not found"]),
    "Gravatar":    ("https://gravatar.com/{}",           [200], []),
    "Steam":       ("https://steamcommunity.com/id/{}",  [200], ["The specified profile could not be found"]),
    "Chess":       ("https://www.chess.com/member/{}",   [200], ["Page Not Found"]),
    "Strava":      ("https://www.strava.com/athletes/{}", [200], ["Page Not Found"]),
    "Behance":     ("https://www.behance.net/{}",        [200], ["Page Not Found"]),
    "Dribbble":    ("https://dribbble.com/{}",           [200], ["Page Not Found"]),
    "SlideShare":  ("https://www.slideshare.net/{}",     [200], ["Page Not Found"]),
    "About.me":    ("https://about.me/{}",               [200], []),
    "Linktree":    ("https://linktr.ee/{}",              [200], ["Page not found"]),
    "Telegram":    ("https://t.me/{}",                   [200], ["tgme_page_title"]),
}

TAKEOVER = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "Error 404 - Web app not found",
    "wordpress.com": "Do you want to register",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "netlify.app": "Not Found - Request ID",
    "vercel.app": "The deployment could not be found",
    "readthedocs.io": "unknown to Read the Docs",
    "ghost.io": "Domain not found",
    "zendesk.com": "Help Center Closed",
    "statuspage.io": "Statuspage not found",
    "unbounce.com": "The requested URL was not found",
    "tumblr.com": "There's nothing here",
    "feedpress.me": "The feed has not been found",
    "freshdesk.com": "May be the wrong domain",
}

DORK_TEMPLATES = [
    'site:{d}', 'site:{d} ext:pdf', 'site:{d} ext:xls', 'site:{d} ext:doc',
    'site:{d} ext:sql', 'site:{d} ext:env', 'site:{d} ext:bak', 'site:{d} ext:log',
    'site:{d} inurl:admin', 'site:{d} inurl:login', 'site:{d} inurl:dashboard',
    'site:{d} inurl:api', 'site:{d} inurl:upload', 'site:{d} inurl:config',
    'site:{d} intitle:index.of', 'site:{d} intitle:"index of /"',
    'site:{d} "password"', 'site:{d} "api_key"', 'site:{d} "BEGIN RSA PRIVATE KEY"',
    'site:{d} "DB_PASSWORD"', 'site:{d} intext:"sql syntax near"',
    'site:{d} -site:www.{d}', 'site:*.{d} -www',
    'site:{d} inurl:phpinfo.php', 'site:{d} inurl:.git',
    'site:pastebin.com "{d}"', 'site:trello.com "{d}"',
    'site:drive.google.com "{d}"', 'site:docs.google.com "{d}"',
    '"{d}" ext:txt', '"{d}" "internal use only"',
]

COMMON_PORTS = [21, 22, 23, 25, 53