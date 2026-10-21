"""
IronCladOS (merged build)
=========================
Link scanner + file scanner + password check/generator + ad/tracker blocker
+ local bridge for the IronClad Ad Blocker Chrome extension.

"Start protection" is the master switch: while it is ON, links and QR codes that the scanner
rates DANGEROUS (from the Link/QR pages or from the browser extension) are blocked automatically
and shared with the extension. Allowlisted sites are never auto-blocked.

Run:  python ironclad_improved.py   (Python 3.8+, standard library; QR images also need
      `pip install pillow pyzbar`)
"""
import base64
import codecs
import hashlib
import http.client
import ipaddress
import json
import logging
import logging.handlers
import math
import os
import queue
import re
import secrets
import select
import socket
import ssl
import string
import sys
import threading
import time
import traceback
import unicodedata
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import Counter, OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote, urlencode, urljoin, urlparse, parse_qsl

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
except ImportError:
    tk = None

# =============================================================================
#  LOGGING  (errors used to vanish into `except Exception: pass`; now they land in a log file)
# =============================================================================
LOG_PATH = os.path.join(os.path.expanduser("~"), ".ironclados.log")
log = logging.getLogger("ironclados")


def _setup_logging():
    if log.handlers:
        return
    log.setLevel(logging.INFO)
    log.propagate = False
    try:
        h = logging.handlers.RotatingFileHandler(LOG_PATH, maxBytes=256 * 1024,
                                                 backupCount=1, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(h)
    except OSError:
        log.addHandler(logging.NullHandler())   # read-only home dir etc.: keep running


_setup_logging()
_swallow_seen = {}          # (where, exception type) -> (last logged monotonic time, suppressed count)


def log_swallowed(where):
    """Call from inside an `except` block that deliberately keeps going.
    Writes one line per (place, error type) per minute so a noisy failure cannot flood the log."""
    try:
        et, ev, _tb = sys.exc_info()
        key = (where, et.__name__ if et else "?")
        now = time.monotonic()
        last, suppressed = _swallow_seen.get(key, (None, 0))
        if last is not None and now - last < 60.0:
            _swallow_seen[key] = (last, suppressed + 1)
            return
        _swallow_seen[key] = (now, 0)
        more = f" (+{suppressed} more in the last minute)" if suppressed else ""
        log.warning("ignored error in %s: %s: %s%s", where, key[1], ev, more)
    except Exception:
        return


def log_exc(where=""):
    """Log the current exception with its traceback (replaces log_exc(), which is
    invisible when the app is started without a console)."""
    try:
        log.error("unhandled error%s", f" in {where}" if where else "", exc_info=True)
    except Exception:
        return


# =============================================================================
#  IRONCLAD "LIQUID GLASS" COLOR SCHEME
#  Tk cannot make a widget see-through or blur what is behind it, so the glass
#  look is built from: an aurora backdrop, frosted slabs a few shades lighter
#  than the backdrop, rounded corners, a luminous 1px edge, a brighter
#  "specular" line along each top edge, and iOS system colours for accents.
# =============================================================================
def _rgb(c):
    return tuple(int(c[i:i + 2], 16) for i in (1, 3, 5))


def _hex(rgb):
    return "#%02x%02x%02x" % tuple(max(0, min(255, int(round(v)))) for v in rgb)


def mix(a, b, t):
    """Blend colour a towards colour b by t (0..1); both are '#rrggbb'."""
    ra, rb = _rgb(a), _rgb(b)
    return _hex([ra[i] + (rb[i] - ra[i]) * t for i in range(3)])


BG_ROOT = "#070b17"      # window backdrop base (the aurora is painted over it)
BG0 = "#0e1426"          # page surface inside the main glass panel
BG1 = "#111830"          # sidebar glass
BG2 = "#18213d"          # card glass
BG3 = "#222d50"          # raised / hover glass
BG4 = "#2e3b66"
BORDER = "#34426e"
BORDER_LIGHT = "#4c5d94"
GLASS_EDGE = mix(BG2, "#a9bbff", 0.30)   # luminous rim
GLASS_SPEC = mix(BG2, "#e4eaff", 0.55)   # brighter line along the top edge
SELECT_BG = "#33508f"

TEXT = "#f4f6ff"
TEXT_SECONDARY = "#c3cbe3"
MUTED = "#8b97b8"

ADOBE_RED = "#0fb8a4"            # IronClad teal (name kept: used all over the file)
ADOBE_RED_HOVER = "#13d1ba"
ACCENT = "#0a84ff"               # iOS system blue
ACCENT_HOVER = "#409cff"
ACCENT_LIGHT = "#64d2ff"

GREEN = "#30d158"
GREEN_HOVER = "#28b84c"
ORANGE = "#ff9f0a"
YELLOW = "#ffd60a"
DANGER = "#ff453a"
DANGER_HOVER = "#ff6961"
PURPLE = "#bf5af2"

LEVEL_COLOR = {"danger": DANGER, "warn": ORANGE, "caution": YELLOW, "info": ACCENT}
SHORT_VERDICT = {"danger": "Dangerous", "warn": "Suspicious",
                 "caution": "Caution", "info": "No red flags"}

UI_FONT = "Segoe UI"

# =============================================================================
#  DATA TABLES
# =============================================================================
BRANDS = {
    "paypal": ("paypal.com", "paypal.me"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "office365.com",
                  "microsoftonline.com", "outlook.com", "msn.com", "bing.com",
                  "xbox.com", "windows.com", "azure.com", "sharepoint.com",
                  "onedrive.com", "skype.com"),
    "google": ("google.com", "gmail.com", "youtube.com", "googleapis.com",
               "gstatic.com", "goo.gl", "googleusercontent.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.co.jp"),
    "facebook": ("facebook.com", "fb.com", "messenger.com", "fbcdn.net"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "meta": ("meta.com",),
    "netflix": ("netflix.com",),
    "spotify": ("spotify.com",),
    "steam": ("steampowered.com", "steamcommunity.com", "steamstatic.com"),
    "roblox": ("roblox.com", "rbxcdn.com"),
    "epicgames": ("epicgames.com",),
    "discord": ("discord.com", "discord.gg", "discordapp.com"),
    "telegram": ("telegram.org", "t.me"),
    "twitter": ("twitter.com", "x.com", "t.co"),
    "linkedin": ("linkedin.com",),
    "tiktok": ("tiktok.com",),
    "dropbox": ("dropbox.com",),
    "adobe": ("adobe.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "ebay": ("ebay.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "blockchain": ("blockchain.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "citibank": ("citibank.com", "citi.com"),
    "hsbc": ("hsbc.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "usps": ("usps.com",),
    "zoom": ("zoom.us", "zoom.com"),
    "github": ("github.com", "githubusercontent.com"),
    "walmart": ("walmart.com",),
    "samsung": ("samsung.com",),
    "icloud": ("icloud.com",),
    "outlook": ("outlook.com", "office.com", "live.com"),
    "office365": ("office365.com", "office.com", "microsoftonline.com"),
    # added: other commonly impersonated brands
    "onedrive": ("onedrive.com", "onedrive.live.com"),
    "gmail": ("gmail.com",),
    "youtube": ("youtube.com", "youtu.be", "youtube-nocookie.com"),
    "wetransfer": ("wetransfer.com",),
    "venmo": ("venmo.com",),
    "cashapp": ("cash.app",),
    "trustwallet": ("trustwallet.com",),
    "aliexpress": ("aliexpress.com",),
    "alibaba": ("alibaba.com",),
    "capitalone": ("capitalone.com",),
    "americanexpress": ("americanexpress.com", "aexp.com"),
    "revolut": ("revolut.com",),
    "yahoo": ("yahoo.com",),
    "disneyplus": ("disneyplus.com",),
}

LEGIT_DOMAINS = {d for v in BRANDS.values() for d in v}
# main labels of real brand domains (>=7 chars) used for typosquat detection in any label
LEGIT_MAIN_LABELS = {d.split(".")[0] for d in LEGIT_DOMAINS if len(d.split(".")[0]) >= 7}
FREENOM_TLDS = {"tk", "ml", "ga", "cf", "gq"}   # free TLDs with overwhelming abuse rates
COMMON_SLDS = {"com", "net", "org", "co", "gov", "edu", "info"}

REGIONAL_CC = {"uk", "de", "fr", "it", "es", "nl", "ca", "au", "jp", "in", "br", "mx",
               "ae", "sa", "om", "sg", "se", "no", "dk", "fi", "pl", "ie", "nz", "za",
               "kr", "tr", "eg", "qa", "kw", "bh", "pt", "be", "ch", "at", "gr", "cz",
               "hu", "ro", "ar", "cl", "pe", "ph", "id", "my", "th", "vn", "tw", "hk",
               "il", "ru", "ua"}

MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au",
    "co.jp", "or.jp", "ne.jp", "co.in", "net.in", "org.in", "com.br", "net.br",
    "com.mx", "co.nz", "co.za", "com.cn", "net.cn", "org.cn", "com.tr", "com.sg",
    "com.hk", "co.kr", "com.tw", "com.ar", "com.co", "com.pe", "com.ph", "com.my",
    "com.sa", "com.eg", "com.om", "co.om", "com.qa", "com.kw", "com.ua", "co.il",
    "co.id", "co.th", "com.vn", "com.pk", "com.ng", "co.ke",
}

PRIVATE_SUFFIX = {
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
    "herokuapp.com", "blogspot.com", "weebly.com", "wixsite.com", "web.app",
    "firebaseapp.com", "glitch.me", "repl.co", "replit.app", "onrender.com",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "loca.lt", "serveo.net",
    "duckdns.org", "ddns.net", "hopto.org", "no-ip.org", "no-ip.biz", "zapto.org",
    "sytes.net", "myftp.org", "000webhostapp.com", "infinityfreeapp.com",
    "s3.amazonaws.com", "r2.dev", "azurewebsites.net", "cloudfront.net",
    "framer.app", "carrd.co", "webflow.io", "strikingly.com", "mystrikingly.com",
    "yolasite.com", "square.site", "godaddysites.com", "sites.google.com",
}

TUNNEL_DYNDNS = {"ngrok.io", "ngrok-free.app", "trycloudflare.com", "loca.lt",
                 "serveo.net", "duckdns.org", "ddns.net", "hopto.org", "no-ip.org",
                 "no-ip.biz", "zapto.org", "sytes.net", "myftp.org"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
    "rb.gy", "tiny.cc", "shorturl.at", "t.ly", "v.gd", "s.id", "shorte.st", "bl.ink",
    "rebrand.ly", "lnkd.in", "adf.ly", "bc.vc", "clck.ru", "qr.ae", "urlz.fr",
    "x.co", "soo.gd", "trib.al", "mcaf.ee", "snip.ly", "short.io", "tr.ee",
}

HIGH_RISK_TLDS = {"zip", "mov", "tk", "gq", "ml", "cf", "ga", "top", "click", "country",
                  "work", "support", "loan", "men", "download", "review", "racing", "win",
                  "bid", "stream", "accountant", "science", "party", "trade", "date",
                  "faith", "cricket", "kim", "gdn", "zone", "rest", "cyou", "sbs", "cfd"}

MED_RISK_TLDS = {"xyz", "icu", "buzz", "monster", "lol", "bond", "shop", "site", "online",
                 "store", "vip", "fit", "cam", "uno", "link", "club", "rocks", "world",
                 "space", "pw", "ws", "cc", "info", "biz", "live", "tech", "digital"}

EXEC_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "msi", "msp", "vbs", "vbe", "js",
            "jse", "wsf", "wsh", "ps1", "psm1", "hta", "jar", "apk", "dmg", "pkg", "sh",
            "lnk", "reg", "cpl", "dll", "app", "appx", "msix", "iso", "img", "vhd",
            "crx", "deb", "rpm", "run", "bin", "chm", "gadget", "inf", "url"}

ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "tgz", "cab", "ace", "z", "xz", "bz2"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg",
           "png", "gif", "mp3", "mp4", "rtf", "csv", "html", "htm"}

HOST_KEYWORDS = ("login", "signin", "sign-in", "secure", "verify", "verification",
                 "account", "update", "wallet", "support", "billing", "confirm",
                 "unlock", "recover", "suspend", "alert", "bonus", "prize", "free",
                 "gift", "claim", "airdrop", "giveaway", "helpdesk", "webmail",
                 "auth", "password", "security", "invoice", "refund", "banking",
                 "customer", "service", "validate", "restore", "limited")

STRONG_PATH_PATTERNS = ("/verify-account", "/confirm-password", "/webscr", "/signin-verify",
                        "/recover-account", "/update-payment", "/unlock-account",
                        "/account-verification", "/secure-login", "/cmd=_login",
                        "/validate-account", "/restore-access", "/billing-update",
                        "/login.php?", "/signin.php", "/verify.php", "/auth.php")

REDIRECT_PARAMS = {"redirect", "redirect_uri", "redirect_url", "redirecturl", "url", "next",
                   "continue", "return", "return_to", "returnurl", "dest", "destination",
                   "goto", "target", "link", "out", "r", "u", "q", "to", "forward"}

CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ѵ": "v",
    "ɡ": "g", "ɑ": "a", "ο": "o", "ν": "v", "α": "a", "ρ": "p", "ι": "i", "κ": "k",
    "τ": "t", "υ": "u", "ɩ": "i", "ӕ": "ae", "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d",
    "ᴇ": "e", "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l", "ᴍ": "m",
    "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v",
    "ᴡ": "w", "ʏ": "y", "ᴢ": "z", "ǀ": "l", "Ι": "i", "І": "i", "О": "o", "Р": "p",
    "А": "a", "Е": "e", "С": "c", "Н": "h", "К": "k", "М": "m", "Т": "t", "Х": "x",
    "０": "0", "１": "1", "ⅼ": "l", "ⅰ": "i",
}

AD_DOMAINS = {
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "adservice.google.com", "pagead2.googlesyndication.com", "2mdn.net",
    "admob.com", "app-measurement.com", "analytics.google.com",
    "adnxs.com", "adsrvr.org", "advertising.com", "taboola.com", "outbrain.com",
    "criteo.com", "criteo.net", "rubiconproject.com", "pubmatic.com", "openx.net",
    "casalemedia.com", "indexww.com", "amazon-adsystem.com", "moatads.com",
    "adsafeprotected.com", "33across.com", "bidswitch.net", "smartadserver.com",
    "media.net", "revcontent.com", "mgid.com", "zedo.com", "yieldmo.com",
    "sharethrough.com", "teads.tv", "adform.net", "adtech.de", "adtechus.com",
    "lijit.com", "sovrn.com", "contextweb.com", "districtm.io", "gumgum.com",
    "triplelift.com", "spotxchange.com", "springserve.com", "tremorhub.com",
    "undertone.com", "yieldlab.net", "smaato.net", "stickyadstv.com", "everesttech.net",
    "serving-sys.com", "flashtalking.com", "mathtag.com", "turn.com", "bluekai.com",
    "demdex.net", "krxd.net", "rlcdn.com", "adition.com", "adscale.de",
    "ads.yahoo.com", "advertising.yahoo.com", "gemini.yahoo.com",
    "scorecardresearch.com", "quantserve.com", "quantcount.com", "hotjar.com",
    "hotjar.io", "mouseflow.com", "crazyegg.com", "fullstory.com", "luckyorange.com",
    "inspectlet.com", "mixpanel.com", "api.segment.io", "segment.io", "amplitude.com",
    "heapanalytics.com", "newrelic.com", "nr-data.net", "bugsnag.com", "chartbeat.com",
    "chartbeat.net", "parsely.com", "comscore.com", "imrworldwide.com", "omtrdc.net",
    "2o7.net", "adobedtm.com", "bat.bing.com", "clarity.ms", "optimizely.com",
    "pingdom.net", "statcounter.com", "histats.com", "addthis.com", "sharethis.com",
    "pixel.facebook.com", "an.facebook.com", "ads.linkedin.com", "px.ads.linkedin.com",
    "ads.twitter.com", "analytics.twitter.com", "static.ads-twitter.com",
    "ads.tiktok.com", "analytics.tiktok.com", "business-api.tiktok.com",
    "ads.pinterest.com", "ct.pinterest.com", "ads.reddit.com", "events.redditmedia.com",
    "snap.licdn.com", "sc-static.net", "tr.snapchat.com",
    "appsflyer.com", "adjust.com", "kochava.com", "flurry.com", "branch.io",
    "applovin.com", "unityads.unity3d.com", "adcolony.com", "mopub.com", "inmobi.com",
    "chartboost.com", "vungle.com", "ironsrc.com", "supersonicads.com", "tapjoy.com",
    "startapp.com", "fyber.com", "mintegral.com", "pangleglobal.com", "ads.vungle.com",
    "popads.net", "popcash.net", "propellerads.com", "adsterra.com", "exoclick.com",
    "juicyads.com", "trafficjunky.net", "clickadu.com", "hilltopads.net",
    "onclickads.net", "adcash.com", "bidvertiser.com", "clicksor.com", "adnium.com",
    "richpush.co", "pushwoosh.com", "evadav.com", "monetag.com", "a-ads.com",
    "adskeeper.com", "admaven.com", "ad-maven.com", "trafficstars.com",
    "trafficfactory.biz", "realsrv.com", "syndication.exdynsrv.com", "exdynsrv.com",
    "clickaine.com", "popunderjs.com", "adxpansion.com", "yllix.com", "zeropark.com",
    "mobidea.com", "revenuehits.com", "adspyglass.com", "ero-advertising.com",
}

AGGRESSIVE_AD_DOMAINS = {
    "popads.net", "popcash.net", "propellerads.com", "adsterra.com", "exoclick.com",
    "juicyads.com", "trafficjunky.net", "clickadu.com", "hilltopads.net",
    "onclickads.net", "adcash.com", "bidvertiser.com", "clicksor.com", "adnium.com",
    "richpush.co", "evadav.com", "monetag.com", "admaven.com", "ad-maven.com",
    "trafficstars.com", "realsrv.com", "exdynsrv.com", "syndication.exdynsrv.com",
    "clickaine.com", "popunderjs.com", "yllix.com", "zeropark.com", "adskeeper.com",
}

EXTRA_AD_DOMAINS = {
    "adsymptotic.com", "betweendigital.com", "adkernel.com", "atdmt.com", "360yield.com",
    "mxpnl.com", "ads.youtube.com", "ads-api.tiktok.com", "ads-api.twitter.com", "trk.pinterest.com",
    "analytics.yahoo.com", "pixel.wp.com", "stats.wp.com", "pi.pardot.com", "munchkin.marketo.net",
    "en25.com", "hs-analytics.net", "hsadspixel.net", "hs-banner.com", "mktoresp.com",
    "taboolasyndication.com", "adnxs-simple.com", "agkn.com", "alexametrics.com", "adblade.com",
    "adbrite.com", "adbureau.net", "adcentriconline.com", "addthisedge.com", "adgrx.com",
    "adhigh.net", "admixer.net", "adotmob.com", "adpushup.com", "adroll.com", "adsco.re",
    "adtelligent.com", "adyoulike.com", "aniview.com", "bidr.io", "bttrack.com", "carbonads.com",
    "carbonads.net", "conversantmedia.com", "cpmstar.com", "crwdcntrl.net", "dotomi.com",
    "doubleverify.com", "exelator.com", "eyeota.net", "fastclick.net", "id5-sync.com",
    "intergi.com", "ipredictive.com", "lkqd.net", "liadm.com", "liveintent.com", "marinsm.com",
    "media6degrees.com", "moatpixel.com", "mookie1.com", "nexac.com", "nativo.com", "ntv.io",
    "onaudience.com", "owneriq.net", "pippio.com", "plista.com", "pubmine.com", "revjet.com",
    "richaudience.com", "rfihub.com", "rtbhouse.com", "semasio.net", "serverbid.com", "simpli.fi",
    "sitescout.com", "skimresources.com", "smartclip.net", "sonobi.com", "tapad.com", "tidaltv.com",
    "tribalfusion.com", "tubemogul.com", "tynt.com", "viglink.com", "vibrantmedia.com", "w55c.net",
    "yandexadexchange.net", "yieldmanager.com", "zemanta.com", "zqtk.net", "ad.gt", "adtng.com",
    "tsyndicate.com", "trafficforce.com", "kissmetrics.com", "kissmetrics.io", "tiqcdn.com",
    "tealiumiq.com", "ensighten.com", "singular.net", "tenjin.io", "mc.yandex.ru", "mc.yandex.com",
    "an.yandex.ru", "adfox.ru", "counter.yadro.ru", "top-fwz1.mail.ru", "cxense.com", "cxpublic.com",
    "dianomi.com", "disqusads.com", "emjcd.com", "gemius.pl", "gemius.com", "lfeeder.com",
    "mmtro.com", "pbstck.com", "permutive.com", "sddan.com", "snigelweb.com", "tvsquared.com",
    "venatus.com", "xad.com", "zeotap.com", "bidtheatre.com", "ml314.com", "bouncex.net",
    "convertro.com", "extreme-dm.com", "adsnative.com", "ads.nexage.com", "ybp.yahoo.com",
    "bkrtx.com", "visualwebsiteoptimizer.com", "js.hs-scripts.com", "exosrv.com", "oclasrv.com",
}
_GOOGLE_CC = ("co.uk", "de", "fr", "it", "es", "nl", "ca", "com.au", "co.jp", "co.in", "com.br",
              "com.mx", "ru", "pl", "se", "no", "dk", "fi", "ie", "co.nz", "co.za", "com.tr",
              "com.sg", "com.hk", "co.kr", "com.tw", "com.ar", "at", "ch", "be", "pt", "gr", "cz",
              "hu", "ro", "com.eg", "com.sa", "ae", "com.om", "com.qa", "com.kw", "co.id", "co.th",
              "com.vn", "com.ph", "com.my", "com.pk", "com.ng", "co.ke", "cl", "pe", "com.co",
              "co.il", "com.ua")
EXTRA_AD_DOMAINS |= {f"adservice.google.{c}" for c in _GOOGLE_CC}
AD_DOMAINS |= EXTRA_AD_DOMAINS
# second batch: SSPs/DSPs, ad servers, session-replay, affiliate click trackers, mobile SDKs,
# pop/push/native networks, regional telemetry, in-browser crypto-miners.
# Where a vendor's root domain is also a real website, only the tracker HOSTNAMES are listed.
EXTRA_AD_DOMAINS |= {
    "improvedigital.com", "unrulymedia.com", "loopme.me", "content.ad", "ligatus.com", "amobee.com",
    "zetaglobal.net", "centro.net", "spotx.tv", "brightroll.com", "adaptv.tv", "yumenetworks.com",
    "videologygroup.com", "brealtime.com", "innovid.com", "celtra.com", "sizmek.com", "pointroll.com",
    "pubnative.net", "adzerk.net", "dvtps.com", "awin1.com", "zenaps.com", "shareasale-analytics.com",
    "dpbolvw.net", "jdoqocy.com", "tkqlhce.com", "anrdoezrs.net", "kqzyfj.com", "prf.hn", "pntra.com",
    "pntrs.com", "pjtra.com", "pjatr.com", "7eer.net", "sjv.io", "impactradius-go.com", "ojrq.net",
    "tracking.pepperjam.com", "clk.tradedoubler.com", "track.webgains.com", "click.linksynergy.com",
    "cdn.abtasty.com", "cdn.smartlook.com", "rec.smartlook.com", "web-sdk.smartlook.com",
    "contentsquare.net", "clicktale.net", "decibelinsight.net", "cdn.quantummetric.com",
    "ingest.quantummetric.com", "lr-in.com", "mintegral.net", "plugrush.com", "richads.com",
    "coinzilla.io", "bitmedia.io", "cointraffic.io", "galaksion.com", "ad4game.com", "fimserve.com",
    "flite.com", "interclick.com", "invitemedia.com", "jivox.com", "kontera.com", "mediaplex.com",
    "specificclick.net", "valueclick.com", "tacoda.net", "atwola.com", "bluelithium.com", "fwmrm.com",
    "q.quora.com", "cdn.segment.com", "api.segment.com", "static.getclicky.com", "in.getclicky.com",
    "ak.sail-horizon.com", "analytics.snapchat.com", "alb.reddit.com", "events.reddit.com",
    "analytics-sg.tiktok.com", "bat.r.msn.com", "ads.msn.com", "c.msn.com", "mads.amazon.com",
    "fls-na.amazon.com", "unagi.amazon.com", "unagi-na.amazon.com", "ad.mail.ru", "rs.mail.ru",
    "top.mail.ru", "tns-counter.ru", "yabs.yandex.ru", "geo.yahoo.com", "iadsdk.apple.com",
    "samsungads.com", "ad.xiaomi.com", "tracking.miui.com", "data.mistat.xiaomi.com",
    "metrics.data.hicloud.com", "logservice.hicloud.com",
    "coinhive.com", "coin-hive.com", "authedmine.com", "crypto-loot.com", "cryptoloot.pro",
    "coinimp.com", "jsecoin.com", "webminepool.com", "minero.cc",
}
# third batch: more ad exchanges, native/pop networks, mobile ad SDKs, RUM/analytics, regional trackers
EXTRA_AD_DOMAINS |= {
    "stackadapt.com", "heias.com", "exponential.com", "keywee.co", "afy11.net", "vidible.tv",
    "insightexpressai.com", "postrelease.com", "betrad.com", "creativecdn.com", "kargo.com",
    "connatix.com", "3lift.com", "ad-delivery.net", "triplelift.com", "emxdgt.com", "supersonicads.com",
    "ironsrc.com", "chartboost.com", "startappservice.com", "inmobi.com", "popcash.net",
    "propellerads.com", "revenuehits.com", "clicksor.com", "yllix.com", "dable.io", "adagio.io",
    "onetag-sys.com", "yieldlove-ad-serving.net", "adnami.io", "iasds01.com", "indexww.com",
    "everesttech.net", "2o7.net", "omtrdc.net", "go-mpulse.net", "rum-static.pingdom.net",
    "cdn.inspectlet.com", "sessioncam.com", "webtrendslive.com", "coremetrics.com",
    "atinternet-solutions.com", "xiti.com", "etracker.com", "etracker.de", "econda-monitor.de",
    "ioam.de", "wemfbox.ch",
    # ad/analytics trackers from Chinese, Russian and Korean ecosystems
    "cnzz.com", "mmstat.com", "umeng.com", "hm.baidu.com", "pos.baidu.com", "cbjs.baidu.com",
    "dup.baidustatic.com", "adriver.ru", "rambler-co.ru", "top100.rambler.ru",
    # more programmatic / native vendors
    "admedo.com", "adverline.com", "admarketplace.net", "underdog.media", "adspirit.de",
    "admaster.com.cn", "adscale.de", "contextual.media.net", "warp.media.net", "revcontent.com",
    "adbutler.com", "bidvertiser.com", "buysellads.com", "buysellads.net", "adsonar.com",
    "ad.admitad.com", "vrtcal.com", "condenastdigital.com", "dtscout.com", "tag.demandbase.com",
    "adskeeper.com", "digitru.st", "trackcmp.net", "impactradius-event.com",
}
AD_DOMAINS.discard("doubleverify.com")      # vendor homepage: keep its trackers (dvtps.com), not the site
EXTRA_AD_DOMAINS.discard("doubleverify.com")
# found missing when the built-in list was tested against less-common ad networks
EXTRA_AD_DOMAINS |= {"bounceexchange.com", "crwdcntrl.com", "ay.delivery", "primis.tech", "vidazoo.com",
                     "region1.analytics.google.com"}
AD_DOMAINS |= EXTRA_AD_DOMAINS

# Web dashboards that sit on a tracker-style hostname. Pages on these exact hosts are never
# blocked or interrupted (the Chrome extension also lets the page's own requests through),
# while OTHER sites' requests to them are still blocked as before.
NAV_SAFE_HOSTS = frozenset({
    "analytics.google.com",     # Google Analytics dashboard (GA4 beacons go to region1.analytics.google.com)
    "ads.twitter.com", "ads.x.com", "ads.linkedin.com", "ads.youtube.com",
    "ads.reddit.com", "ads.pinterest.com", "ads.tiktok.com",
    "ads.yahoo.com", "advertising.yahoo.com", "gemini.yahoo.com",
})


DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


# =============================================================================
#  SCAN RESULT
# =============================================================================
class ScanResult:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.host = ""
        self.registered_domain = ""
        self.error = None
        self.ad_network = False
        self._seen = set()
        self.sources = {}
        self.normalized = ""
        self.final_url = ""
        self.kind = "link"
        self.sha256 = ""
        self.size = 0
        self.official = False

    def add(self, points, reason, source="Local"):
        if reason in self._seen:
            return
        self._seen.add(reason)
        self.sources[reason] = source
        self.findings.append((points, reason))

    @property
    def score(self):
        return min(100, sum(p for p, _ in self.findings))

    @property
    def level(self):
        s = self.score
        if s >= 70:
            return "danger"
        if s >= 40:
            return "warn"
        if s >= 15:
            return "caution"
        return "info"

    @property
    def has_unwanted_ads(self):
        return self.ad_network or any(
            "ad" in r.lower() and p >= 8 for p, r in self.findings
        )

    @property
    def verdict(self):
        if self.kind == "file":
            return {"danger": "DANGEROUS — do not open",
                    "warn": "SUSPICIOUS — multiple red flags",
                    "caution": "CAUTION — some red flags",
                    "info": "NO KNOWN THREAT PATTERNS (not a guarantee)"}[self.level]
        return {
            "danger": "DANGEROUS — do not open",
            "warn": "SUSPICIOUS — multiple red flags",
            "caution": "CAUTION — some red flags",
            "info": "NO RED FLAGS FOUND (not a guarantee)",
        }[self.level]

    def report(self):
        lines = [f"URL: {self.url}",
                 f"Verdict: {self.verdict}   Risk score: {self.score}/100"]
        if self.host:
            lines.append(f"Host: {self.host}   Registered domain: {self.registered_domain}")
        for pts, reason in sorted(self.findings, key=lambda f: -f[0]):
            lines.append(f"  [{pts:+d}] ({self.sources.get(reason, 'Local')}) {reason}")
        if self.error:
            lines.append(self.error)
        lines.append("Offline heuristic check only — it cannot confirm a link is safe.")
        return "\n".join(lines)


# =============================================================================
#  HELPERS
# =============================================================================
def shannon_entropy(s):
    if not s:
        return 0.0
    c, n = Counter(s), len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def levenshtein(a, b):
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 3:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_LEET = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a"}


def leet_variants(label):
    base = label.replace("rn", "m").replace("vv", "w")
    base = "".join(_LEET.get(ch, ch) for ch in base)
    return {base.replace("1", "l"), base.replace("1", "i")}


def parse_ip_host(host):
    try:
        h = (host or "").strip("[]")
    except Exception:
        return None
    if not h:
        return None
    try:
        return ipaddress.ip_address(h), False
    except ValueError:
        pass
    parts = h.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        if not p:
            return None
        try:
            if re.fullmatch(r"0[xX][0-9a-fA-F]*", p):
                v = int(p, 16) if len(p) > 2 else 0
            elif re.fullmatch(r"0[0-7]+", p):
                v = int(p, 8)
            elif p.isdigit():
                v = int(p)
            else:
                return None
        except (ValueError, TypeError):
            return None
        nums.append(v)
    head, last = nums[:-1], nums[-1]
    try:
        if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
            return None
        value = last
        for i, n in enumerate(head):
            value |= n << (24 - 8 * i)
        return ipaddress.IPv4Address(value), True
    except (ValueError, OverflowError):
        return None


def split_domain(host):
    labels = (host or "").split(".")
    if len(labels) < 2:
        return host or "", "", "", host or ""
    last2 = ".".join(labels[-2:])
    if last2 in PRIVATE_SUFFIX or last2 in MULTI_SUFFIX:
        suffix = last2
        if len(labels) >= 3:
            reg, sub = ".".join(labels[-3:]), ".".join(labels[:-3])
        else:
            reg, sub = host, ""
    else:
        suffix, reg, sub = labels[-1], last2, ".".join(labels[:-2])
    return reg, sub, suffix, reg.split(".")[0]


def decode_idn(host):
    if all(ord(c) < 128 for c in host) and "xn--" not in host:
        return host
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(codecs.decode(label[4:].encode("ascii"), "punycode"))
                continue
            except Exception:
                log_swallowed("decode_idn")
        out.append(label)
    return ".".join(out)


def script_of(ch):
    try:
        return unicodedata.name(ch).split(" ")[0]
    except (ValueError, TypeError):
        return "UNKNOWN"


# =============================================================================
#  LINK SCANNER
# =============================================================================
def _scan_url_impl(url):
    res = ScanResult(url)
    raw = (url or "").strip()
    if not raw:
        res.error = "Enter a website URL."
        return res

    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        res.add(30, "Contains control characters (used to smuggle or hide parts of a link).")
    if any(c.isspace() for c in raw):
        res.add(15, "Contains whitespace inside the link.")
    candidate = re.sub(r"\s+", "", raw)
    if "\\" in candidate:
        res.add(15, "Uses backslashes; browsers treat them as '/', a known filter-evasion trick.")
        candidate = candidate.replace("\\", "/")

    low = candidate.lower()
    for bad in ("javascript:", "vbscript:", "data:", "blob:"):
        if low.startswith(bad):
            res.add(100, f"'{bad}' link runs code or embeds content instead of opening a website.")
            return res
    if "://" not in candidate:
        if low.startswith(("file:", "ftp:", "about:", "mailto:", "tel:", "sms:")):
            res.add(40, "Not a web (http/https) link; this scanner only analyzes websites.")
            return res
        candidate = "https://" + candidate
    scheme = candidate.split("://", 1)[0].lower()
    if scheme not in ("http", "https"):
        res.add(40, f"Unusual scheme '{scheme}://'; only http/https links are supported.")
        return res

    res.normalized = candidate
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname
        port = parsed.port
    except (ValueError, UnicodeError):
        res.add(50, "Malformed URL or invalid port number.")
        return res
    if not host:
        res.add(40, "No website hostname was found.")
        return res
    host = host.lower().rstrip(".")
    if parsed.hostname and parsed.hostname.endswith("."):
        res.add(4, "Hostname ends with a trailing dot (can bypass naive filters).")
    res.host = host

    path = unquote(parsed.path or "").lower()
    query = unquote(parsed.query or "").lower()
    path_query = path + ("?" + query if query else "")
    full_decoded = unquote(candidate).lower()

    if len(raw) > 2048:
        res.add(15, "Extremely long URL; long links often hide the real destination.")
    elif len(raw) > 200:
        res.add(8, "Very long URL.")
    elif len(raw) > 100:
        res.add(3, "Long URL.")
    n_enc = len(re.findall(r"%[0-9a-fA-F]{2}", candidate))
    if "%25" in candidate:
        res.add(15, "Double-encoded characters (%25) — classic filter-evasion technique.")
    if n_enc >= 8:
        res.add(8, f"Contains {n_enc} percent-encoded characters that can conceal content.")
    if re.search(r"%(2e|2f|5c|40|00)", parsed.netloc.lower()):
        res.add(40, "Encoded dot/slash/@ inside the host portion — deliberate obfuscation.")

    if parsed.username is not None or parsed.password is not None:
        ui = unquote(parsed.username or "")
        if "." in ui or "/" in ui or ":" in ui:
            res.add(55, "A fake domain appears before the '@'; the real destination is the part after it.")
        else:
            res.add(40, "Contains user-info before '@' — a common phishing disguise.")

    ip_info = parse_ip_host(host)
    if host == "localhost" or host.endswith(".localhost"):
        res.add(25, "Points at your own computer (localhost); only open if you started that service.")
        res.registered_domain = host
        return res
    elif ip_info:
        ip_obj, obfuscated = ip_info
        res.registered_domain = str(ip_obj)
        if obfuscated:
            res.add(60, f"IP address written in disguised form (decimal/hex/octal) -> {ip_obj}.")
        else:
            res.add(35, "Uses a raw IP address instead of a domain name.")
        if not ip_obj.is_global:
            res.add(25, "Points to a private/loopback/non-public IP address.")
        if parsed.scheme == "http":
            res.add(5, "Unencrypted HTTP.")
        if port not in (None, 80, 443):
            res.add(10, f"Unusual web port {port}.")
        # LAN / loopback devices (router admin pages, local servers) are not phishing sites:
        # the extra path rules below only apply to addresses outside the user's own network.
        on_lan = (ip_obj.is_loopback or ip_obj.is_link_local or
                  any(ip_obj in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
        if not on_lan:
            pq_ip = path + ("?" + query if query else "")
            if any(k in pq_ip for k in ("login", "signin", "password", "account", "verify",
                                        "update", "payment", "billing", "secure", "webscr")):
                res.add(15, "Raw-IP address serving a login/payment-style page.")
            if any(b in pq_ip for b in BRANDS if len(b) >= 5):
                res.add(10, "Path mentions a well-known brand on a raw IP address.")
            last_ip = path.rsplit("/", 1)[-1]
            ext_ip = last_ip.rsplit(".", 1)[-1] if "." in last_ip else ""
            if ext_ip in EXEC_EXT:
                res.add(35, f"Link points straight to a downloadable program/script (.{ext_ip}).")
        return res

    labels = host.split(".")
    if len(host) > 253 or "." not in host or ".." in host or host.startswith("."):
        res.add(40, "Hostname format looks invalid or unusual.")
        return res
    unicode_host = decode_idn(host)
    is_idn = unicode_host != host or any(ord(c) > 127 for c in host)
    ascii_labels_ok = all(re.fullmatch(r"[a-z0-9-]{1,63}", l) and not l.startswith("-")
                          and not l.endswith("-") for l in labels)
    if not is_idn and not ascii_labels_ok:
        res.add(30, "Hostname contains invalid characters or malformed labels.")

    reg, sub, suffix, main_label = split_domain(host)
    res.registered_domain = reg
    tld = suffix.split(".")[-1]
    sub_labels = [l for l in sub.split(".") if l]

    reg_is_official = reg in LEGIT_DOMAINS
    if not reg_is_official and main_label in BRANDS and tld in REGIONAL_CC \
            and tld not in HIGH_RISK_TLDS and suffix not in PRIVATE_SUFFIX:
        reg_is_official = True
    res.official = reg_is_official
    official_brand = None
    if reg_is_official:
        official_brand = next((b for b, ds in BRANDS.items() if reg in ds or b == main_label),
                              "a known brand")
        res.add(0, f"Domain matches the official {official_brand.title()} domain (checked by name only — "
                   "cannot detect hacked pages or malicious content on it).")

    if is_idn:
        res.add(8, "Internationalized (non-ASCII/punycode) domain name.")
        for lab in unicode_host.split("."):
            scripts = {script_of(c) for c in lab if c.isalpha()}
            if len(scripts) > 1 and "LATIN" in scripts:
                res.add(55, "A single domain label mixes scripts (e.g. Latin + Cyrillic) — lookalike-character attack.")
        skeleton = "".join(CONFUSABLES.get(c, c) for c in unicode_host)
        skel_reg, _, _, skel_main = split_domain(skeleton)
        if skeleton != unicode_host and skeleton.isascii():
            for brand, legit in BRANDS.items():
                if brand == skel_main or skel_reg in legit:
                    res.add(70, f"Lookalike characters spell '{brand}' — impersonation of {brand.title()}.")
                    break

    if not reg_is_official and reg not in PRIVATE_SUFFIX and reg not in SHORTENERS:
        cands = []
        tokens_main = [t for t in re.split(r"[-_]", main_label) if t]
        tokens_sub = [t for t in re.split(r"[.\-_]", sub) if t]
        variants = leet_variants(main_label) | leet_variants(main_label.replace("-", ""))
        for lab in sub_labels + [main_label]:          # typosquat of a real brand domain in ANY label
            if len(lab) >= 7 and lab not in LEGIT_MAIN_LABELS:
                hit = next((lm for lm in LEGIT_MAIN_LABELS
                            if abs(len(lab) - len(lm)) <= 1 and levenshtein(lab, lm) == 1), None)
                if hit:
                    cands.append((45, f"'{lab}' is a near-miss of the real '{hit}' (typosquatting)."))
                    break
        for brand, legit in BRANDS.items():
            inner = next((d for d in legit if re.search(r"(^|[.\-_])" + re.escape(d) + r"(\.|$)", host)), None)
            if inner:
                cands.append((60, f"The official domain '{inner}' appears inside a "
                                  f"different domain ('{reg}') — classic {brand.title()} lookalike."))
                continue
            if brand in tokens_main or brand in tokens_sub:
                cands.append((50, f"Brand name '{brand}' used on an unrelated domain ('{reg}')."))
            elif len(brand) >= 6 and (main_label.startswith(brand) or main_label.endswith(brand)):
                cands.append((45, f"Domain wraps the {brand.title()} brand name but is not {brand.title()}'s domain."))
            elif len(brand) >= 7 and brand in main_label:
                cands.append((40, f"Domain embeds the {brand.title()} brand name but is not {brand.title()}'s domain."))
            else:
                flat = main_label.replace("-", "")
                if flat == brand and flat != main_label:
                    cands.append((45, f"Hyphenated spelling of '{brand}' — lookalike of {brand.title()}."))
                elif any(v == brand or brand in re.split(r"[-_]", v) or
                         (len(brand) >= 6 and (v.startswith(brand) or v.endswith(brand)))
                         for v in variants) and brand not in main_label:
                    cands.append((50, f"Character substitution (e.g. 0->o, 1->l) spells '{brand}' — impersonation of {brand.title()}."))
                elif len(brand) >= 6:
                    d = levenshtein(main_label, brand)
                    allowed = 2 if len(brand) >= 9 else 1
                    if 0 < d <= allowed:
                        cands.append((45, f"'{main_label}' is a near-miss of '{brand}' (typosquatting)."))
        if cands:
            pts, reason = max(cands)
            res.add(pts, reason)
        elif any(b in path_query.replace("-", "/").split("/") or
                 (len(b) >= 6 and b in path_query) for b in BRANDS if len(b) >= 5):
            res.add(10, "Path mentions a well-known brand on an unrelated domain.")

    if not reg_is_official:
        if any(l in COMMON_SLDS for l in sub_labels[1:]):
            res.add(20, "A domain-looking name (e.g. '...com') sits in the subdomain part — the real site is the last part of the address.")
        if len(sub_labels) >= 4:
            res.add(18, f"{len(sub_labels)} subdomain levels — the real domain may be obscured.")
        elif len(sub_labels) == 3:
            res.add(10, "Many subdomain levels.")
        if host.count("-") >= 3:
            res.add(10, "Many hyphens in the hostname (typical of phishing domains).")
        elif main_label.count("-") >= 2:
            res.add(6, "Multiple hyphens in the main domain name.")
        if len(host) > 40:
            res.add(6, "Unusually long hostname.")
        alpha = [c for c in main_label if c.isalpha()]
        if len(main_label) >= 10 and not is_idn:
            vowels = sum(c in "aeiou" for c in alpha) / max(1, len(alpha))
            if shannon_entropy(main_label) >= 3.4 and vowels < 0.25:
                res.add(15, "Domain name looks randomly generated (high entropy, few vowels).")
        if len(main_label) >= 8 and sum(c.isdigit() for c in main_label) / len(main_label) >= 0.3:
            res.add(8, "Domain name is heavy with digits.")
        if "www" in sub_labels[1:] or re.search(r"(^|\.)www\d+\.", host) or \
                ("www" in main_label and main_label != "www"):
            res.add(6, "Odd 'www' placement in hostname.")

        kws = {k for k in HOST_KEYWORDS if k in (main_label + "." + sub)}
        if len(kws) >= 3:
            res.add(35 if len(kws) >= 4 else 25,
                    f"Host stacks several credential/prize-bait words ({', '.join(sorted(kws)[:4])}).")
        elif len(kws) == 2:
            res.add(15, f"Host contains credential-bait words ({', '.join(sorted(kws))}).")
        elif len(kws) == 1 and (official_brand or any(b in host for b in BRANDS)):
            res.add(8, f"Host pairs a brand name with '{next(iter(kws))}'.")

    if tld in HIGH_RISK_TLDS:
        res.add(24 if tld in FREENOM_TLDS else 14,
                f"'.{tld}' is a TLD heavily abused for spam, phishing and malware.")
    elif tld in MED_RISK_TLDS and not reg_is_official:
        res.add(5, f"'.{tld}' is a TLD with an above-average abuse rate.")
    if suffix in PRIVATE_SUFFIX and not reg_is_official:
        res.add(6, f"Hosted on free/shared platform '{suffix}' (anyone can publish here).")
    if suffix in TUNNEL_DYNDNS:
        res.add(20, f"'{suffix}' is a tunnel/dynamic-DNS service often used for short-lived attack pages.")
    if reg in SHORTENERS or host in SHORTENERS:
        res.add(20, "URL shortener: the final destination is hidden.")

    if port not in (None, 80, 443):
        res.add(12, f"Unusual web port {port}.")
    if parsed.scheme.lower() == "http":
        login_like = any(k in path_query for k in ("login", "signin", "password",
                                                    "account", "verify", "pay"))
        res.add(15 if login_like else 5,
                "Unencrypted HTTP on a page that looks like it asks for credentials/payment."
                if login_like else "Unencrypted HTTP connection.")

    last = path.rsplit("/", 1)[-1]
    exts = [e for e in last.split(".")[1:]] if "." in last else []
    ext = exts[-1] if exts else ""
    if len(exts) >= 2 and exts[-1] in EXEC_EXT and exts[-2] in DOC_EXT:
        res.add(55, f"Double extension '.{exts[-2]}.{exts[-1]}' disguises an executable as a document.")
    elif ext in EXEC_EXT:
        res.add(35, f"Link points straight to a downloadable program/script (.{ext}).")
    elif ext in MACRO_EXT:
        res.add(35, f"Macro-enabled Office file (.{ext}) — a common malware vector.")
    elif ext in ARCHIVE_EXT:
        res.add(12, f"Direct archive download (.{ext}) — contents can't be inspected.")
    if not reg_is_official:
        if any(p in path_query for p in STRONG_PATH_PATTERNS):
            res.add(25, "Path matches a known credential-harvesting pattern.")
        elif re.search(r"/(login|signin|sign-in|log-in|password|verify|account)\b", path):
            res.add(6, "Path asks for login/verification on an unrelated domain.")
        if re.search(r"/wp-(content|includes|admin)/", path) and re.search(
                r"(login|verify|secure|account|update|office|drive|dropbox|docu)", path):
            res.add(18, "Credential-themed page inside a WordPress folder (typical of hacked-site phishing).")
        if path.count("/") >= 8:
            res.add(4, "Very deep path.")

    try:
        params = parse_qsl(parsed.query, keep_blank_values=True)
    except Exception:
        params = []
    for key, val in params:
        try:
            v = unquote(val)
        except Exception:
            v = val
        if re.match(r"^(https?:)?//", v.lower()) or re.search(r"https?://", v.lower()):
            try:
                tgt = urlparse(v if "://" in v else "https:" + v if v.startswith("//") else "https://" + v).hostname or ""
            except Exception:
                tgt = ""
            res.add(15, f"Parameter '{key}' embeds another URL (possible open redirect).")
            if tgt and split_domain(tgt.lower())[0] != reg:
                res.add(10, f"...and it leads to a different site ({tgt.lower()}).")
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", v.lower()):
            res.add(6, "Query contains an email address (phishing links often pre-fill the victim's address).")
        if len(v) >= 120 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", v):
            res.add(8, "Very long encoded/base64-like parameter value.")
    if re.search(r"(base64,|eval\(|<script|onerror=|onload=|document\.cookie)", full_decoded):
        res.add(40, "Query/path contains script-injection style content.")

    if any(host == d or host.endswith("." + d) for d in AGGRESSIVE_AD_DOMAINS):
        res.ad_network = True
        res.add(25, "Aggressive ad/pop-under network, frequently abused for malvertising and scam redirects.")
    elif any(host == d or host.endswith("." + d) for d in AD_DOMAINS):
        res.ad_network = True
        res.add(8, "Known ad/tracking domain (blockable with the Ad Blocker tab).")

    return res


_COMBO_CATS = tuple((n, re.compile(p, re.I)) for n, p in (
    ("impersonation", r"impersonation|lookalike|Brand name '|wraps the|embeds the|near-miss|Hyphenated spelling|fake domain appears"),
    ("bait", r"credential/prize|credential-bait|credential-harvesting|asks for login|login/payment|pairs a brand|Credential-themed|asks for credentials"),
    ("risky-infrastructure", r"TLD heavily abused|above-average abuse|raw IP|disguised form|tunnel/dynamic|Unusual web port|private/loopback|URL shortener"),
    ("payload", r"downloadable program|Double extension|Macro-enabled|script-injection|archive download"),
    ("obfuscation", r"randomly generated|heavy with digits|Many hyphens|Multiple hyphens|subdomain levels|Many subdomain|Odd 'www'|domain-looking|percent-encoded|Double-encoded|Encoded dot"),
))


def _apply_combo(res):
    """Independent kinds of evidence compound: phishing links rarely trip just one heuristic."""
    if res.kind != "link" or res.official or res.error:
        return
    cats = set()
    for pts, reason in res.findings:
        if pts > 0:
            for name, pat in _COMBO_CATS:
                if pat.search(reason):
                    cats.add(name)
    if len(cats) >= 2:
        bonus = 14 * (len(cats) - 1) + (6 if "payload" in cats else 0)
        res.add(min(bonus, 40), "Several independent red flags combine ("
                + ", ".join(sorted(cats)) + ") — typical of real phishing/malware links.")


def scan_url(url):
    try:
        r = _scan_url_impl(url)
        _apply_combo(r)
        return r
    except Exception as e:
        res = ScanResult(url if isinstance(url, str) else str(url))
        res.error = f"Could not analyze the link ({type(e).__name__}: {e})."
        return res


def check_link_threat(url):
    r = scan_url(url)
    if r.error:
        return None, r.error
    top = max(r.findings, key=lambda f: f[0])[1] if r.findings else "No red flags found."
    return (False if r.score >= 40 else None), f"{r.verdict} (score {r.score}/100) — {top}"


# =============================================================================
#  FILE ANALYZER
# =============================================================================
PDF_RULES = (
    (r"/Launch\b", 55, "PDF can launch an external program."),
    (r"/JavaScript\b|/JS(?=[\s(<\[/>])", 30, "PDF contains embedded JavaScript."),
    (r"/OpenAction\b|/AA\b", 20, "PDF runs an action automatically when opened."),
    (r"/EmbeddedFile\b", 15, "PDF carries an embedded file."),
    (r"/RichMedia\b|/XFA\b", 12, "PDF uses rich-media/XFA content (frequent exploit surface)."),
)

SCRIPT_EXT = {"js", "jse", "vbs", "vbe", "ps1", "psm1", "bat", "cmd", "hta", "wsf", "sh",
              "html", "htm", "svg", "py", "php", "jar"}

SCRIPT_RULES = (
    (r"powershell(\.exe)?\s+[^\n]*-e(nc|ncodedcommand)?\s", 35, "Encoded PowerShell command."),
    (r"frombase64string", 20, "Decodes base64 payloads at runtime."),
    (r"\beval\s*\(", 12, "Uses eval() on dynamic content."),
    (r"unescape\s*\(", 15, "Uses unescape() (common obfuscation)."),
    (r"activexobject|wscript\.shell|shell\.application", 30, "Uses Windows scripting-host objects."),
    (r"downloadstring|downloadfile|invoke-webrequest|invoke-expression|\biex\b", 30,
     "Downloads and executes remote content."),
    (r"certutil\s+[^\n]*-urlcache|bitsadmin\s+/transfer", 35, "Living-off-the-land download technique."),
    (r"cmd(\.exe)?\s+/c", 12, "Spawns cmd.exe."),
    (r"document\.write\s*\(\s*unescape", 25, "document.write(unescape(...)) obfuscation."),
    (r"chr\(\d+\)\s*&\s*chr\(", 20, "VBScript char-code obfuscation."),
    (r"(curl|wget)\s[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", 40, "Pipes a downloaded script straight into a shell."),
    (r"/dev/tcp/|\bnc(\.exe)?\s+[^\n]*-e\s|\bncat\b[^\n]*-e", 45, "Opens a reverse shell."),
    (r"-(ep|executionpolicy)\s+bypass|-w(indowstyle)?\s+hidden|-nop\b|-noprofile", 20,
     "Runs PowerShell hidden or bypassing the execution policy."),
    (r"new-object\s+net\.webclient|system\.net\.webclient|invoke-restmethod", 25, "Downloads content over the network."),
    (r"mshta(\.exe)?\s|rundll32(\.exe)?\s[^\n]*javascript|regsvr32[^\n]*(/i:|scrobj)", 35,
     "Uses a trusted Windows binary to run remote/script code."),
    (r"vssadmin[^\n]*delete\s+shadows|bcdedit[^\n]*recoveryenabled\s+no|wbadmin\s+delete", 55,
     "Deletes backups/shadow copies (ransomware behaviour)."),
    (r"schtasks\s+/create|reg(\.exe)?\s+add\s+[^\n]*\\run\b|currentversion\\run", 25,
     "Creates persistence (scheduled task / Run key)."),
    (r"set-mppreference[^\n]*disable|netsh\s+advfirewall[^\n]*off", 40, "Disables security protection."),
    (r"runtime\.getruntime\(\)\.exec|processbuilder\s*\(", 25, "Executes system commands from code."),
    (r"(wscript\.shell|shell\.application|activexobject)[\s\S]{0,300}(\.run\b|\.exec\b|\.shellexecute|cmd(\.exe)?\s+/c|powershell)", 35,
     "Scripting-host object used to run commands."),
    (r"string\.fromcharcode\s*\([^)]{20,}\)", 15, "Decodes obfuscated content at runtime."),
)


def analyze_file(path):
    res = ScanResult(path)
    res.kind = "file"
    body = bytearray()
    head = b""
    h = hashlib.sha256()
    try:
        res.size = os.path.getsize(path)
        with open(path, "rb") as f:
            first = True
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                if first:
                    head, first = chunk[:4096], False
                if len(body) < 25 * 1024 * 1024:
                    body += chunk
        res.sha256 = h.hexdigest()
    except OSError as e:
        res.error = f"Error reading file: {e}"
        return res

    try:
        name = os.path.basename(path).lower()
    except Exception:
        name = str(path).lower()
    parts = name.split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    if res.size == 0:
        res.add(0, "File is empty.")
        return res

    if len(parts) >= 3 and parts[-1] in EXEC_EXT and parts[-2] in DOC_EXT:
        res.add(75, f"Double extension '.{parts[-2]}.{parts[-1]}' disguises a program as a document.")
    elif ext in EXEC_EXT:
        res.add(12, f"Program/script file type (.{ext}) — run only if it comes from a source you trust.")
    elif ext in MACRO_EXT:
        res.add(20, f"Macro-enabled Office file (.{ext}).")

    if head.startswith(b"MZ") and ext not in {"exe", "dll", "scr", "sys", "ocx", "cpl",
                                              "drv", "efi", "mui", "msi"}:
        res.add(75, f"Windows executable disguised as '.{ext or 'unknown'}'.")
    if head.startswith(b"\x7fELF") and ext not in {"", "so", "bin", "elf", "o", "out", "ko"}:
        res.add(70, f"Linux executable disguised as '.{ext}'.")
    if (head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")) and ext not in {"", "dylib", "bin", "app"}:
        res.add(70, f"macOS executable disguised as '.{ext}'.")

    data = bytes(body)
    try:
        if b"%PDF" in head[:1024]:
            text = data.decode("latin-1", errors="ignore")
            hit = set()
            for pat, pts, why in PDF_RULES:
                if re.search(pat, text):
                    res.add(pts, why)
                    hit.add(pat)
            if r"/JavaScript\b|/JS(?=[\s(<\[/>])" in hit and r"/OpenAction\b|/AA\b" in hit:
                res.add(20, "PDF combines automatic actions with JavaScript — typical exploit pattern.")
            if r"/Launch\b" in hit and r"/OpenAction\b|/AA\b" in hit:
                res.add(20, "PDF launches a program automatically when opened.")
        if ext in SCRIPT_EXT or head.startswith(b"#!"):
            text = data[:5 * 1024 * 1024].decode("latin-1", errors="ignore")
            hits = 0
            for pat, pts, why in SCRIPT_RULES:
                if re.search(pat, text, re.I):
                    res.add(pts, why)
                    hits += 1
            if hits >= 3:
                res.add(30, "Several independent suspicious behaviours in one script.")
            elif hits == 2:
                res.add(15, "Two independent suspicious behaviours in one script.")
        if head[:2] == b"PK" and b"vbaProject.bin" in data:
            res.add(30, "Office document contains VBA macros.")
            if ext not in MACRO_EXT:
                res.add(40, f"A macro project is hidden inside a file named '.{ext or 'unknown'}' (not a macro file type).")
        if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and (b"V\x00B\x00A\x00" in data or b"Macros" in data):
            res.add(40, "Legacy Office document contains macros.")
            if re.search(rb"autoopen|auto_open|document_open|workbook_open|autoexec", data, re.I):
                res.add(20, "Macro runs automatically when the document is opened.")
    except Exception as e:
        res.add(0, f"Content analysis partially failed ({type(e).__name__}).")
    return res


# =============================================================================
#  QR CODE SAFETY CHECKER
# =============================================================================
def looks_like_url(text):
    t = (text or "").strip().lower()
    if not t:
        return False
    if t.startswith(("http://", "https://", "www.", "ftp://")):
        return True
    # bare domain-ish
    if re.match(r"^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}(/|$|\?)", t):
        return True
    return False




# =============================================================================
#  CONFIG
# =============================================================================
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".ironclados.json")


_CFG_LOCK = threading.Lock()


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        # A damaged file used to be silently replaced by defaults on the next save, which also lost
        # the saved Windows proxy settings. Keep a copy so nothing is destroyed.
        log.error("could not read %s (%s: %s); keeping a copy as .bad", CONFIG_PATH, type(e).__name__, e)
        try:
            os.replace(CONFIG_PATH, CONFIG_PATH + ".bad")
        except OSError:
            return {}
        return {}


def save_config(cfg):
    """Write the config atomically: a crash or full disk can no longer leave a half-written file."""
    tmp = CONFIG_PATH + ".tmp"
    with _CFG_LOCK:
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, CONFIG_PATH)
        except (OSError, TypeError, ValueError):
            log.exception("could not save %s", CONFIG_PATH)
            try:
                os.remove(tmp)
            except OSError:
                return


_LOCAL_NAMES = ("localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0")
# Rule options that do not narrow a rule. Anything else ($domain=, $image, $script, ~third-party,
# $badfilter, $dnsrewrite ...) means "only in some situations", so a domain-level blocker must
# skip it rather than block the whole domain.
_BLOCK_OPTS_OK = frozenset({"important", "third-party", "3p", "all"})
_EXCEPTION_OPTS_OK = frozenset({"important"})
_ABP_RULE_RE = re.compile(r"([a-z0-9.-]+)\^?(\$.*)?$")


def _options_ok(opts, allowed):
    if not opts:
        return True
    return all(o.strip() in allowed for o in opts[1:].split(","))


def parse_blocklist_ex(text):
    """Parse a hosts file / adblock-style list into (blocked, exceptions).

    blocked     domains to block (hosts lines, bare domains, ||domain^ rules)
    exceptions  domains from @@||domain^ rules; they win over the blocklists (not over malware feeds)
    Rules that only apply in some situations are skipped instead of being widened to a full block."""
    blocked, exceptions = set(), set()
    if not isinstance(text, str):
        return blocked, exceptions
    for line in text.splitlines():
        try:
            line = line.strip().lower()
            if (not line or line[0] in "#!" or line.startswith("[") or "##" in line
                    or "#@#" in line or "#?#" in line or "#$#" in line or "#%#" in line):
                continue
            line = line.split("#", 1)[0].strip()
            is_exception = line.startswith("@@")
            if is_exception:
                line = line[2:]
                if not line.startswith("||"):
                    continue
            if line.startswith("||"):
                m = _ABP_RULE_RE.match(line[2:])
                if not m or not _options_ok(m.group(2), _EXCEPTION_OPTS_OK if is_exception
                                            else _BLOCK_OPTS_OK):
                    continue
                d = m.group(1)
            elif line.startswith(("0.0.0.0", "127.0.0.1")):
                parts = line.split()
                d = parts[1] if len(parts) > 1 else ""
            elif " " in line or "\t" in line:
                continue
            else:
                d = line
            d = d.strip(".")
            if d in _LOCAL_NAMES or not DOMAIN_RE.match(d) or d.rsplit(".", 1)[-1].isdigit():
                continue          # not a hostname (a numeric last label means an IP address)
            (exceptions if is_exception else blocked).add(d)
            if len(blocked) > 2_000_000:
                break
        except Exception:
            continue
    return blocked, exceptions


def parse_blocklist(text):
    """Blocked domains only (kept for callers that do not care about exceptions)."""
    return parse_blocklist_ex(text)[0]


# =============================================================================
#  AD BLOCK ENGINE
# =============================================================================
class AdBlockEngine:
    SCAN_CACHE_MAX = 10_000
    RECENT_MAX = 500

    def __init__(self):
        self.blocked = set(AD_DOMAINS)
        self.security = set()
        self.exceptions = set()      # @@|| exceptions from the lists (never applied to malware feeds)
        self.allow = set()
        self.scan_block = False
        self.lock = threading.RLock()
        self.version = 0             # bumped whenever the effective lists change
        self._lists = {}
        self.blocked_count = 0
        self.allowed_count = 0
        self.recent = deque(maxlen=self.RECENT_MAX)
        self.top = Counter()
        self._host_stats = defaultdict(lambda: {"blocked": 0, "allowed": 0})
        self._scan_cache = OrderedDict()
        self._cache_lock = threading.Lock()
        self.on_block = None         # callback(host, reason, source) fired for every blocked request

    def _rebuild_locked(self):
        b, sec, exc = set(AD_DOMAINS), set(), set()
        for cat, doms, exs in self._lists.values():
            b |= doms
            if cat == "security":
                sec |= doms
            else:
                exc |= exs
        self.blocked, self.security, self.exceptions = b, sec, exc
        self.version += 1

    def set_list(self, key, domains, category="ads", exceptions=()):
        with self.lock:
            self._lists[key] = (category, set(domains),
                                set(exceptions) if category != "security" else set())
            self._rebuild_locked()

    def remove_list(self, key):
        with self.lock:
            if self._lists.pop(key, None) is not None:
                self._rebuild_locked()

    def list_count(self, key):
        with self.lock:
            item = self._lists.get(key)
            return len(item[1]) if item else None

    @property
    def sources(self):
        with self.lock:
            return [k[5:] for k in self._lists if k.startswith("file:")]

    def load_file(self, path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            domains, exceptions = parse_blocklist_ex(f.read())
        self.set_list("file:" + path, domains, "ads", exceptions)
        return len(domains)

    def apply_config(self, cfg):
        self.allow = set(cfg.get("allow", []) or [])
        self.scan_block = bool(cfg.get("scan_block", False))
        for p in cfg.get("sources", []) or []:
            try:
                self.load_file(p)
            except OSError:
                pass

    def export_config(self, cfg):
        cfg["allow"] = sorted(self.allow)
        cfg["sources"] = self.sources
        cfg["scan_block"] = self.scan_block
        return cfg

    def export_hosts(self, path):
        with self.lock:
            exc = self.exceptions
            domains = sorted(d for d in self.blocked - self.allow
                             if d not in NAV_SAFE_HOSTS
                             and not any(c in exc for c in self._candidates(d)))
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Generated by IronCladOS\n")
            f.write("# Merge into your system hosts file (requires admin)\n\n")
            for d in domains:
                f.write(f"0.0.0.0 {d}\n")
        return len(domains)

    @staticmethod
    def _candidates(host):
        if not host:
            return []
        labels = host.split(".")
        if len(labels) < 2:
            return [host]
        return [".".join(labels[i:]) for i in range(len(labels) - 1)]

    def lookup(self, host):
        if not host:
            return None
        host = host.lower().rstrip(".")
        cands = self._candidates(host)
        with self.lock:
            sec, blk, exc = self.security, self.blocked, self.exceptions
        if any(c in sec for c in cands):
            return "security"
        if host in NAV_SAFE_HOSTS or any(c in exc for c in cands):
            return None
        if any(c in blk for c in cands):
            return "ads"
        return None

    def _scan_score(self, host):
        with self._cache_lock:
            score = self._scan_cache.get(host)
            if score is not None:
                self._scan_cache.move_to_end(host)
                return score
        try:
            score = scan_url("http://" + host).score
        except Exception:
            score = 0
        with self._cache_lock:
            self._scan_cache[host] = score
            self._scan_cache.move_to_end(host)
            while len(self._scan_cache) > self.SCAN_CACHE_MAX:
                self._scan_cache.popitem(last=False)
        return score

    def is_blocked(self, host):
        if not host:
            return False, ""
        host = host.lower().strip("[]").rstrip(".")
        cands = self._candidates(host)
        with self.lock:
            allow, sec, blk, exc = self.allow, self.security, self.blocked, self.exceptions
            scan_enabled = self.scan_block
        if any(c in allow for c in cands):
            return False, "allowlisted"
        if any(c in sec for c in cands):
            return True, "malware/phishing feed"
        if host in NAV_SAFE_HOSTS:
            return False, "ad dashboard (exempt)"
        if any(c in exc for c in cands):
            return False, "list exception"
        if any(c in blk for c in cands):
            return True, "ad/tracker list"
        if scan_enabled:
            score = self._scan_score(host)
            if score >= 70:
                return True, f"threat scanner score: {score}"
        return False, ""

    def record(self, host, blocked, reason="", source=""):
        with self.lock:
            if blocked:
                self.blocked_count += 1
                self.top[host] += 1
                self.recent.appendleft((time.strftime("%H:%M:%S"), host, reason))
                self._host_stats[host]["blocked"] += 1
            else:
                self.allowed_count += 1
                self._host_stats[host]["allowed"] += 1
        cb = self.on_block               # outside the lock: the callback must never stall the proxy
        if blocked and cb is not None:
            try:
                cb(host, reason, source)
            except Exception:
                log_swallowed("AdBlockEngine.record")

    def get_host_stats(self, host):
        with self.lock:
            return dict(self._host_stats.get(host, {"blocked": 0, "allowed": 0}))

    def get_top_blocked(self, n=10):
        with self.lock:
            return self.top.most_common(n)

    def reset_stats(self):
        with self.lock:
            self.blocked_count = 0
            self.allowed_count = 0
            self.recent.clear()
            self.top.clear()
            self._host_stats.clear()

    def snapshot(self):
        with self.lock:
            return (self.blocked_count, self.allowed_count,
                    len(self.blocked), list(self.recent))


def augment_with_lists(res, engine):
    if not res.host or parse_ip_host(res.host):
        return
    try:
        kind = engine.lookup(res.host)
    except Exception:
        return
    if kind == "security":
        res.add(85, "Listed in a malware/phishing domain feed you have loaded (e.g. URLhaus).",
                "Blocklist")
    elif kind == "ads" and not res.ad_network:
        res.ad_network = True
        res.add(8, "Domain is on your ad/tracker blocklists.", "Blocklist")


# =============================================================================
#  YOUTUBE AD SKIPPER (HTML injection via proxy)
# =============================================================================
YOUTUBE_HOSTS = {"youtube.com", "www.youtube.com", "m.youtube.com",
                 "music.youtube.com", "youtu.be"}

YT_AD_SKIPPER_JS = r"""
(function(){
  if (window.__icAdSkip) return; window.__icAdSkip = true;
  const css = document.createElement('style');
  css.textContent = `
    .video-ads, .ytp-ad-module, .ytp-ad-overlay-container,
    .ytp-ad-progress-list, .ytp-ad-text, .ytp-ad-image-overlay,
    ytd-promoted-sparkles-web-renderer, ytd-ad-slot-renderer,
    ytd-in-feed-ad-layout-renderer, #player-ads, #masthead-ad,
    .ytp-ad-player-overlay, .ytp-ad-player-overlay-layout {
      display: none !important; visibility: hidden !important;
      opacity: 0 !important; pointer-events: none !important;
    }`;
  (document.head || document.documentElement).appendChild(css);
  function clickIf(el){ try { el && el.click(); } catch(e){} }
  function nukeAdState(){
    const p = document.querySelector('#movie_player');
    if (!p) return;
    if (p.classList.contains('ad-showing') ||
        p.classList.contains('ad-interrupting')) {
      const vid = document.querySelector('video');
      if (vid) {
        try {
          vid.muted = true;
          vid.playbackRate = 16;
          if (vid.duration && isFinite(vid.duration)) {
            vid.currentTime = Math.max(0, vid.duration - 0.1);
          }
        } catch(e){}
      }
      clickIf(document.querySelector('.ytp-ad-skip-button'));
      clickIf(document.querySelector('.ytp-ad-skip-button-modern'));
      clickIf(document.querySelector('.ytp-skip-ad-button'));
      clickIf(document.querySelector('.ytp-ad-overlay-close-button'));
      clickIf(document.querySelector('.ytp-ad-survey-answer-option'));
    }
  }
  setInterval(nukeAdState, 250);
  const mo = new MutationObserver(nukeAdState);
  mo.observe(document.documentElement, {
    childList:true, subtree:true, attributes:true,
    attributeFilter:['class']
  });
  document.addEventListener('loadeddata', nukeAdState, true);
})();
"""


def _inject_youtube_skipper(body: bytes) -> bytes:
    try:
        text = body.decode("utf-8", "ignore")
    except Exception:
        return body
    if "__icAdSkip" in text:
        return body
    snippet = f"<script>{YT_AD_SKIPPER_JS}</script>"
    if "</head>" in text:
        text = text.replace("</head>", snippet + "</head>", 1)
    elif "<body" in text:
        text = text.replace("<body", snippet + "<body", 1)
    else:
        text = snippet + text
    return text.encode("utf-8", "ignore")


# =============================================================================
#  FILTERING PROXY
# =============================================================================
class FilteringProxy:
    MAX_CONNECTIONS = 512
    POOL_TTL = 60
    READ_TIMEOUT = 30

    def __init__(self, engine, host="127.0.0.1", port=8899, yt_skip=True):
        self.engine = engine
        self.host = host
        self.port = port
        self.yt_skip = yt_skip
        self.running = False
        self._sock = None
        self._slots = threading.BoundedSemaphore(self.MAX_CONNECTIONS)
        self._pool = {}
        self._pool_lock = threading.Lock()
        self.bytes_blocked = 0
        self.requests_processed = 0
        self._shutdown = threading.Event()

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(256)
        s.settimeout(0.5)
        self._sock, self.running = s, True
        self._shutdown.clear()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self.running = False
        self._shutdown.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            log_swallowed("FilteringProxy.stop")
        with self._pool_lock:
            for conn, _ in self._pool.values():
                try:
                    conn.close()
                except Exception:
                    log_swallowed("FilteringProxy.stop")
            self._pool.clear()

    def _cleanup_loop(self):
        while not self._shutdown.is_set():
            self._shutdown.wait(30)
            if self._shutdown.is_set():
                break
            now = time.time()
            with self._pool_lock:
                stale = [k for k, (_, ts) in self._pool.items()
                         if now - ts > self.POOL_TTL]
                for k in stale:
                    try:
                        self._pool[k][0].close()
                    except Exception:
                        log_swallowed("FilteringProxy._cleanup_loop")
                    del self._pool[k]

    def _accept_loop(self):
        while self.running:
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                break
            client.settimeout(self.READ_TIMEOUT)
            if not self._slots.acquire(blocking=False):
                try:
                    client.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        try:
            self._handle(client)
        except Exception:
            log_swallowed("FilteringProxy._serve")
        finally:
            try:
                client.close()
            except OSError:
                pass
            self._slots.release()

    @staticmethod
    def _reply(client, code, text, content_type="text/plain"):
        try:
            body = text.encode()
            head = (
                f"HTTP/1.1 {code} {text}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Connection: close\r\n"
                f"X-Blocked-By: IronCladOS\r\n\r\n"
            ).encode()
            client.sendall(head + body)
        except OSError:
            pass

    @staticmethod
    def _parse_hostport(target, default_port):
        try:
            if target.startswith("["):
                host, _, rest = target[1:].partition("]")
                if rest.startswith(":"):
                    try:
                        return host, int(rest[1:])
                    except ValueError:
                        return host, default_port
                return host, default_port
            host, _, port = target.rpartition(":")
            if not host:
                return port, default_port
            if port.isdigit():
                return host, int(port)
            return host, default_port
        except Exception:
            return "", default_port

    def _acquire_upstream(self, host, port):
        key = (host, port)
        with self._pool_lock:
            entry = self._pool.pop(key, None)
        if entry:
            sock, _ = entry
            try:
                sock.settimeout(self.READ_TIMEOUT)
                sock.setblocking(False)
                try:
                    peek = sock.recv(1, socket.MSG_PEEK)
                    if peek == b"":
                        raise OSError("closed")
                except BlockingIOError:
                    pass
                except OSError:
                    raise
                sock.setblocking(True)
                return sock
            except Exception:
                try:
                    sock.close()
                except Exception:
                    log_swallowed("FilteringProxy._acquire_upstream")
        s = socket.create_connection((host, port), timeout=10)
        s.settimeout(self.READ_TIMEOUT)
        return s

    def _release_upstream(self, host, port, sock):
        key = (host, port)
        with self._pool_lock:
            if key in self._pool:
                try:
                    self._pool[key][0].close()
                except Exception:
                    log_swallowed("FilteringProxy._release_upstream")
            self._pool[key] = (sock, time.time())

    def _handle(self, client):
        data = b""
        while b"\r\n\r\n" not in data:
            try:
                chunk = client.recv(16384)
            except (socket.timeout, OSError):
                return
            if not chunk:
                return
            data += chunk
            if len(data) > 65536:
                return

        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if not lines:
            return
        try:
            method, target, version = lines[0].decode("latin-1").split(" ", 2)
        except (ValueError, UnicodeDecodeError):
            return self._reply(client, 400, "Bad Request")

        method_u = method.upper()
        self.requests_processed += 1

        if method_u == "CONNECT":
            host, port = self._parse_hostport(target, 443)
            if not host:
                return self._reply(client, 400, "Bad Request")
            try:
                blocked, why = self.engine.is_blocked(host)
            except Exception:
                blocked, why = False, ""
            self.engine.record(host, blocked, why, "proxy")
            if blocked:
                self.bytes_blocked += 1
                return self._reply(client, 403, "Blocked by IronCladOS")
            try:
                upstream = self._acquire_upstream(host, port)
            except OSError:
                return self._reply(client, 502, "Bad Gateway")
            try:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if rest:
                    upstream.sendall(rest)
            except OSError:
                try:
                    upstream.close()
                except Exception:
                    log_swallowed("FilteringProxy._handle")
                return
            self._pipe(client, upstream)
            try:
                upstream.close()
            except Exception:
                log_swallowed("FilteringProxy._handle")
            return

        parsed = None
        try:
            parsed = urlparse(target)
        except Exception:
            parsed = None

        if parsed and parsed.scheme in ("http", "https") and parsed.hostname:
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        else:
            host = ""
            port = 80
            for line in lines[1:]:
                if line.lower().startswith(b"host:"):
                    host, port = self._parse_hostport(
                        line.split(b":", 1)[-1].decode("latin-1").strip(), 80
                    )
                    break
            path = target

        if not host:
            return self._reply(client, 400, "Bad Request")

        try:
            blocked, why = self.engine.is_blocked(host)
        except Exception:
            blocked, why = False, ""
        self.engine.record(host, blocked, why, "proxy")
        if blocked:
            self.bytes_blocked += 1
            return self._reply(client, 403, "Blocked by IronCladOS")

        try:
            upstream = self._acquire_upstream(host, port)
        except OSError:
            return self._reply(client, 502, "Bad Gateway")

        drop_prefixes = (b"proxy-connection:", b"proxy-authorization:", b"keep-alive:")
        new_lines = [f"{method} {path} {version}".encode("latin-1", "replace")]
        for line in lines[1:]:
            ll = line.lower()
            if any(ll.startswith(p) for p in drop_prefixes):
                continue
            new_lines.append(line)
        new_lines.append(b"Connection: close")
        try:
            upstream.sendall(b"\r\n".join(new_lines) + b"\r\n\r\n" + rest)
        except OSError:
            try:
                upstream.close()
            except Exception:
                log_swallowed("FilteringProxy._handle")
            return

        host_key = host.lower()
        is_yt = self.yt_skip and any(
            host_key == h or host_key.endswith("." + h) for h in YOUTUBE_HOSTS
        )
        if is_yt:
            self._pipe_yt(client, upstream)
        else:
            self._pipe(client, upstream)
        try:
            upstream.close()
        except Exception:
            log_swallowed("FilteringProxy._handle")

    def _pipe_yt(self, client, upstream):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = upstream.recv(16384)
                if not chunk:
                    return
                data += chunk
                if len(data) > 262144:
                    break
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            status = lines[0] if lines else b"HTTP/1.1 200 OK"

            headers, chunked, content_length, ctype = [], False, None, ""
            for line in lines[1:]:
                low = line.lower()
                if low.startswith(b"content-length:"):
                    try:
                        content_length = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        content_length = None
                    continue
                if low.startswith(b"transfer-encoding:") and b"chunked" in low:
                    chunked = True
                    headers.append(line)
                    continue
                if low.startswith(b"content-type:"):
                    ctype = line.split(b":", 1)[1].strip().decode(
                        "latin-1", "ignore").lower()
                headers.append(line)

            if chunked:
                try:
                    client.sendall(status + b"\r\n" + b"\r\n".join(headers)
                                   + b"\r\n\r\n" + body)
                except OSError:
                    return
                self._pipe(client, upstream)
                return

            is_html = "text/html" in ctype or "application/xhtml" in ctype

            if content_length is not None:
                want = content_length
                while len(body) < want:
                    chunk = upstream.recv(min(65536, want - len(body)))
                    if not chunk:
                        break
                    body += chunk
            else:
                while True:
                    chunk = upstream.recv(65536)
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > 8 * 1024 * 1024:
                        break

            if is_html:
                body = _inject_youtube_skipper(body)

            out_headers = [h for h in headers
                           if not h.lower().startswith(b"content-length:")]
            out_headers.append(f"Content-Length: {len(body)}".encode())

            try:
                client.sendall(status + b"\r\n"
                               + b"\r\n".join(out_headers)
                               + b"\r\n\r\n" + body)
            except OSError:
                pass
        except Exception:
            log_exc()

    @staticmethod
    def _pipe(a, b):
        try:
            while True:
                r, _, x = select.select([a, b], [], [a, b], 60)
                if x or not r:
                    return
                for s in r:
                    try:
                        data = s.recv(65536)
                    except (socket.timeout, OSError):
                        return
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            return


# =============================================================================
#  ONLINE BLOCKLISTS
# =============================================================================
UA = "IronCladOS/3.1 (+https://example.invalid/ironclados)"
LISTS_DIR = os.path.join(os.path.expanduser("~"), ".ironclados_lists")

LIST_CATALOG = [
    {"id": "stevenblack", "name": "StevenBlack Unified (ads + malware)",
     "category": "ads", "default": True,
     "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
    {"id": "pgl", "name": "Peter Lowe's Ad Servers",
     "category": "ads", "default": True,
     "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"},
    {"id": "adguard", "name": "AdGuard DNS Filter",
     "category": "ads", "default": False,
     "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
    {"id": "urlhaus", "name": "URLhaus Malware Domains",
     "category": "security", "default": True,
     "url": "https://urlhaus.abuse.ch/downloads/hostfile/"},
]


def _http(url, headers=None, data=None, timeout=10, limit=2_000_000):
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(limit)


def _json(url, headers=None, data=None, timeout=10):
    return json.loads(_http(url, headers, data, timeout).decode("utf-8", "replace"))


class ListManager:
    def __init__(self, engine, cfg, persist):
        self.engine, self.cfg, self.persist = engine, cfg, persist
        cfg.setdefault("lists", {})
        cfg.setdefault("custom_lists", [])
        for item in LIST_CATALOG:
            cfg["lists"].setdefault(item["id"], {"enabled": item["default"],
                                                 "updated": 0, "count": 0})

    def catalog(self):
        out = [dict(x) for x in LIST_CATALOG]
        for c in list(self.cfg.get("custom_lists", [])):
            out.append({"id": c["id"], "name": c["name"], "url": c["url"],
                        "category": c.get("category", "ads"),
                        "default": True, "custom": True})
        for c in list(self.cfg.get("custom_lists", [])):
            self.cfg["lists"].setdefault(c["id"],
                                         {"enabled": True, "updated": 0, "count": 0})
        return out

    def path(self, lid):
        return os.path.join(LISTS_DIR,
                            re.sub(r"[^a-z0-9_-]", "_", lid.lower()) + ".txt")

    def item(self, lid):
        return next((i for i in self.catalog() if i["id"] == lid), None)

    def load_cached(self):
        for item in self.catalog():
            try:
                if self.cfg["lists"][item["id"]]["enabled"] and \
                        os.path.exists(self.path(item["id"])):
                    with open(self.path(item["id"]), "r",
                              encoding="utf-8", errors="ignore") as f:
                        doms, exs = parse_blocklist_ex(f.read())
                    self.engine.set_list(item["id"], doms, item["category"], exs)
            except (OSError, KeyError):
                pass

    def update(self, lid):
        item = self.item(lid)
        if not item:
            raise KeyError(lid)
        limit = 80 * 1024 * 1024
        raw = _http(item["url"], timeout=30, limit=limit)
        if len(raw) >= limit:
            raise ValueError("the list is larger than 80 MB; refusing a truncated copy")
        # Parse BEFORE touching the cached copy: an error page or an empty download must not
        # replace a good list (it used to wipe the list and save the junk to disk).
        domains, exceptions = parse_blocklist_ex(raw.decode("utf-8", "ignore"))
        if not domains:
            raise ValueError("no domains found in the download; kept the previous copy")
        os.makedirs(LISTS_DIR, exist_ok=True)
        tmp = self.path(lid) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(raw)
        os.replace(tmp, self.path(lid))
        self.engine.set_list(lid, domains, item["category"], exceptions)
        self.cfg["lists"].setdefault(lid,
                                     {"enabled": True, "updated": 0, "count": 0})
        self.cfg["lists"][lid].update(updated=int(time.time()),
                                      count=len(domains))
        self.persist()
        return len(domains)

    def set_enabled(self, lid, on):
        self.cfg["lists"].setdefault(lid, {"enabled": False, "updated": 0,
                                           "count": 0})
        self.cfg["lists"][lid]["enabled"] = on
        if not on:
            self.engine.remove_list(lid)
        self.persist()

    def stale(self, max_age=24 * 3600):
        now = time.time()
        out = []
        for i in self.catalog():
            try:
                st = self.cfg["lists"].get(i["id"], {})
                if st.get("enabled") and now - st.get("updated", 0) > max_age:
                    out.append(i["id"])
            except Exception:
                continue
        return out


# =============================================================================
#  BROWSER EXTENSION BRIDGE  (local API for the IronClad Chrome extension)
# =============================================================================
# Compatible with ironclad-adblock-chrome 1.2.0 (link.js protocol):
#   POST /api/pair      – approval dialog, returns a per-browser token
#   GET  /api/sync      – push blocklists + allowlist + policy (incl. protection)
#   POST /api/events    – Chrome reports domains it just blocked
#   POST /api/unpair    – forget this browser
#   POST /api/scan      – scan a URL with the app's engine
#   POST /api/allow     – bulk / single allowlist changes
# When "Start protection" is ON, the policy.enabled flag is true so the
# extension blocks; when protection is OFF, the extension is told to stop.
# =============================================================================
BRIDGE_DEFAULT_PORT = 8898
BRIDGE_MAX_BODY = 256 * 1024


class ExtensionBridge:
    """Tiny HTTP API on 127.0.0.1 so the Chrome extension can share the
    allowlist / domain lists with this app and use its link scanner.

    Security model: loopback only, Host header check (anti DNS-rebinding),
    Origin must be a chrome-extension:// page (web pages are refused), and
    every call (except /api/pair) needs a paired bearer token."""

    def __init__(self, app):
        self.app = app
        self.server = None
        self.thread = None
        self.error = ""
        self.port = BRIDGE_DEFAULT_PORT
        self.last_seen = 0.0
        self._pair_lock = threading.Lock()
        self._pending_pair = None          # (event, result_box)
        self._domains_rev = ""
        self._domains_key = None
        self._domains_cache = None         # (rev, ads, security, exceptions)

    # ---- token / paired browsers ------------------------------------------
    def _paired(self):
        """List of {token, name, last_seen} dicts stored in config."""
        lst = self.app.cfg.setdefault("paired_browsers", [])
        if not isinstance(lst, list):
            lst = []
            self.app.cfg["paired_browsers"] = lst
        return lst

    def token(self):
        """Legacy single-token (kept for Settings UI display). Prefer paired list."""
        cfg = self.app.cfg
        if not cfg.get("bridge_token"):
            cfg["bridge_token"] = secrets.token_urlsafe(24)
            self.app.persist()
        return cfg["bridge_token"]

    def regenerate_token(self):
        """Invalidate all paired browsers and issue a fresh legacy token."""
        self.app.cfg["bridge_token"] = secrets.token_urlsafe(24)
        self.app.cfg["paired_browsers"] = []
        self.app.persist()
        self._domains_rev = ""
        self._domains_cache = None
        return self.app.cfg["bridge_token"]

    def forget_all(self):
        self.app.cfg["paired_browsers"] = []
        self.app.persist()
        self._domains_rev = ""
        self._domains_cache = None

    def _valid_token(self, got):
        if not got.startswith("Bearer "):
            return False
        tok = got[7:].strip()
        if not tok:
            return False
        # Accept any currently paired token, or the legacy single token.
        for p in self._paired():
            if secrets.compare_digest(tok, p.get("token", "")):
                p["last_seen"] = time.time()
                return True
        legacy = self.app.cfg.get("bridge_token", "")
        if legacy and secrets.compare_digest(tok, legacy):
            return True
        return False

    @property
    def running(self):
        return self.server is not None

    # ---- lifecycle --------------------------------------------------------
    def start(self):
        self.stop()
        self.error = ""
        try:
            self.port = int(self.app.cfg.get("bridge_port", BRIDGE_DEFAULT_PORT))
        except (TypeError, ValueError):
            self.port = BRIDGE_DEFAULT_PORT
        self.token()
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "IronCladBridge"

            def log_message(self, *a):
                pass

            def _origin_ok(self):
                origin = self.headers.get("Origin")
                return origin is None or origin.startswith("chrome-extension://")

            def _host_ok(self):
                host = (self.headers.get("Host") or "").lower()
                return host in (f"127.0.0.1:{bridge.port}", f"localhost:{bridge.port}")

            def _cors(self):
                origin = self.headers.get("Origin")
                if origin and origin.startswith("chrome-extension://"):
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                    self.send_header("Access-Control-Allow-Headers",
                                     "Authorization, Content-Type")
                    self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

            def _send(self, code, obj):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self._cors()
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _auth(self, required=True):
                if not (self._host_ok() and self._origin_ok()):
                    self._send(403, {"error": "forbidden"})
                    return False
                if not required:
                    return True
                got = self.headers.get("Authorization", "")
                if not bridge._valid_token(got):
                    self._send(401, {"error": "bad token"})
                    return False
                return True

            def _body(self):
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = 0
                if n <= 0 or n > BRIDGE_MAX_BODY:
                    return {}
                try:
                    data = json.loads(self.rfile.read(n).decode("utf-8"))
                    return data if isinstance(data, dict) else {}
                except Exception:
                    return {}

            def do_OPTIONS(self):
                if not (self._host_ok() and self._origin_ok()):
                    self._send(403, {"error": "forbidden"})
                    return
                self.send_response(204)
                self._cors()
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                try:
                    path = self.path.split("?", 1)[0]
                    qs = {}
                    if "?" in self.path:
                        for part in self.path.split("?", 1)[1].split("&"):
                            if "=" in part:
                                k, v = part.split("=", 1)
                                qs[unquote(k)] = unquote(v)
                    if path == "/api/ping":
                        if not self._auth(required=False):
                            return
                        bridge.last_seen = time.time()
                        self._send(200, bridge.api_ping())
                    elif path == "/api/sync":
                        if not self._auth():
                            return
                        bridge.last_seen = time.time()
                        self._send(200, bridge.api_sync(qs.get("rev", "")))
                    elif path == "/api/state":
                        if not self._auth():
                            return
                        bridge.last_seen = time.time()
                        self._send(200, bridge.api_state())
                    elif path == "/api/domains":
                        if not self._auth():
                            return
                        bridge.last_seen = time.time()
                        self._send(200, bridge.api_domains())
                    else:
                        self._send(404, {"error": "not found"})
                except Exception as e:
                    log_exc()
                    self._send(500, {"error": str(e)})

            def do_POST(self):
                try:
                    path = self.path.split("?", 1)[0]
                    data = self._body()
                    # Pair does not require a token (that's how we obtain one).
                    if path == "/api/pair":
                        if not self._auth(required=False):
                            return
                        self._send(200, bridge.api_pair(data))
                        return
                    if not self._auth():
                        return
                    bridge.last_seen = time.time()
                    if path == "/api/unpair":
                        tok = (self.headers.get("Authorization") or "")[7:].strip()
                        self._send(200, bridge.api_unpair(tok))
                    elif path == "/api/allow":
                        self._send(200, bridge.api_allow(data, True))
                    elif path == "/api/unallow":
                        self._send(200, bridge.api_allow(data, False))
                    elif path == "/api/allowlist":
                        self._send(200, bridge.api_set_allowlist(data))
                    elif path == "/api/protection":
                        self._send(200, bridge.api_protection(data))
                    elif path == "/api/scan":
                        self._send(200, bridge.api_scan(data))
                    elif path == "/api/events":
                        self._send(200, bridge.api_events(data))
                    elif path == "/api/stats":
                        self._send(200, bridge.api_stats(data))
                    else:
                        self._send(404, {"error": "not found"})
                except Exception as e:
                    log_exc()
                    self._send(500, {"error": str(e)})

        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
            self.server.daemon_threads = True
        except OSError as e:
            self.server = None
            self.error = f"Could not listen on 127.0.0.1:{self.port} ({e.strerror or e})"
            return False
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True, name="ironclad-bridge")
        self.thread.start()
        return True

    def stop(self):
        srv, self.server = self.server, None
        if srv:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                log_swallowed("ExtensionBridge.stop")

    # ---- API implementations ---------------------------------------------
    def api_ping(self):
        a = self.app
        return {"app": "IronCladOS", "bridge": 2,
                "protection": bool(a.proxy and a.proxy.running)}

    def _list_info(self):
        a = self.app
        out = []
        for i in a.lists.catalog():
            st = a.cfg["lists"].get(i["id"], {})
            out.append({"id": i["id"], "name": i["name"], "category": i["category"],
                        "enabled": bool(st.get("enabled")),
                        "count": a.engine.list_count(i["id"])})
        return out

    def api_state(self):
        a, e = self.app, self.app.engine
        b, al, size, recent = e.snapshot()
        with e.lock:
            allow = sorted(e.allow)
        running = bool(a.proxy and a.proxy.running)
        return {"allow": allow, "lists": self._list_info(),
                "blocked": b, "allowed": al, "domains": size,
                "protection": running,
                "port": a.proxy.port if running else a.cfg.get("port", 8899),
                "sysproxy": bool(a.cfg.get("sysproxy_backup")),
                "top": [list(x) for x in e.get_top_blocked(8)],
                "recent": [list(x) for x in recent[:12]]}

    @staticmethod
    def _suffixes(domains):
        """Every parent suffix of every domain ('a.b.com' -> 'a.b.com', 'b.com'; never the bare TLD)."""
        out = set()
        for d in domains:
            labels = d.split(".")
            for i in range(len(labels) - 1):
                out.add(".".join(labels[i:]))
        return out

    def _compute_domains(self):
        """Return (rev, ads_list, security_list, exceptions_list). Cached until the engine changes.

        The revision is a hash of the FULL content. (It used to hash only the first 50 entries and
        the list sizes, so a changed list with the same size was never pushed to the browser.)"""
        e = self.app.engine
        ub = [h for h in (self.app.cfg.get("user_blocked") or []) if isinstance(h, str)]
        with e.lock:
            key = (e.version, len(ub), hash(frozenset(ub)))
            if self._domains_cache is not None and self._domains_key == key:
                return self._domains_cache
            sec = set(e.security)
            ads = set(e.blocked) - sec
            exc = set(e.exceptions)
        for h in ub:                         # scan auto-blocks count as security
            sec.add(h)
            ads.discard(h)
        ads -= exc                           # exact list exceptions simply drop out
        ads_suf, sec_suf = self._suffixes(ads), self._suffixes(sec)
        # keep only exceptions that still matter (they sit above a blocked domain) and never let
        # one override a malware/phishing entry
        eff = sorted(x for x in exc
                     if x not in sec_suf
                     and not any(c in sec for c in AdBlockEngine._candidates(x))
                     and (x in ads_suf or any(c in ads for c in AdBlockEngine._candidates(x))))
        ads_l, sec_l = sorted(ads), sorted(sec)
        h = hashlib.sha1()
        for part in (ads_l, sec_l, eff):
            for d in part:
                h.update(d.encode("utf-8", "replace"))
                h.update(b"\n")
            h.update(b"\x00")
        rev = h.hexdigest()[:16]
        self._domains_cache = (rev, ads_l, sec_l, eff)
        self._domains_key = key
        self._domains_rev = rev
        return self._domains_cache

    def api_sync(self, client_rev=""):
        """Push blocklists, allowlist and policy to the extension.
        policy.enabled mirrors the app's 'Start protection' state so the
        extension turns blocking on/off together with the desktop proxy."""
        a, e = self.app, self.app.engine
        rev, ads, sec, exc = self._compute_domains()
        with e.lock:
            allow = sorted(e.allow)
        running = bool(a.proxy and a.proxy.running)
        # Policy the extension applies while managed.
        policy = {
            "enabled": running,                          # Start protection ↔ Chrome on/off
            "warn": True,                                # show blocked.html interstitial
            "cosmetic": True,
            "youtube": bool(a.cfg.get("yt_skip", True)),
            "yt_flash": bool(a.cfg.get("yt_flash", True)),   # black "Ad blocked by IronClad" screen in Chrome
            "can_continue": True,
        }
        if client_rev and client_rev == rev:
            return {"unchanged": True, "rev": rev, "allow": allow, "policy": policy}
        return {
            "rev": rev,
            "ads": ads,
            "security": sec,
            "exceptions": exc,
            "allow": allow,
            "policy": policy,
            "domains": len(ads) + len(sec),
        }

    def api_pair(self, data):
        """Show an approval dialog on the Tk thread; return a new token on Yes."""
        name = str((data or {}).get("name") or "Chrome extension")[:80]
        # Rate-limit concurrent pair attempts.
        with self._pair_lock:
            if self._pending_pair is not None:
                return {"error": "A pairing request is already open in IronCladOS."}
            box = queue.Queue(maxsize=1)
            ev = threading.Event()
            self._pending_pair = (ev, box)

        def ask():
            try:
                ok = messagebox.askyesno(
                    "Chrome extension wants to connect",
                    f"Allow “{name}” to connect to IronCladOS?\n\n"
                    "It will share your blocklists and allowlist, and\n"
                    "“Start protection” will turn blocking on/off in Chrome.",
                    parent=self.app.root)
                box.put(bool(ok))
            except Exception:
                box.put(False)
            finally:
                ev.set()

        try:
            self.app.ui_q.put(ask)
        except Exception:
            with self._pair_lock:
                self._pending_pair = None
            return {"error": "Could not show the approval dialog."}

        # Wait up to 90 s for the user (matches extension timeout).
        if not ev.wait(timeout=90):
            with self._pair_lock:
                self._pending_pair = None
            return {"error": "Pairing timed out — no response in the app window."}
        try:
            approved = box.get_nowait()
        except queue.Empty:
            approved = False
        with self._pair_lock:
            self._pending_pair = None

        if not approved:
            # Extension treats non-200 / missing token as denied.
            return {"error": "denied"}

        tok = secrets.token_urlsafe(24)
        paired = self._paired()
        paired.append({"token": tok, "name": name, "last_seen": time.time()})
        # Keep at most 8 paired browsers.
        del paired[:-8]
        self.app.persist()
        try:
            self.app.ui_q.put(self.app.refresh_bridge_status)
        except Exception:
            log_swallowed("ExtensionBridge.api_pair")
        return {"token": tok, "app": "IronCladOS"}

    def api_unpair(self, tok):
        paired = self._paired()
        self.app.cfg["paired_browsers"] = [
            p for p in paired if not secrets.compare_digest(p.get("token", ""), tok or "")
        ]
        self.app.persist()
        try:
            self.app.ui_q.put(self.app.refresh_bridge_status)
        except Exception:
            log_swallowed("ExtensionBridge.api_unpair")
        return {"ok": True}

    def api_protection(self, data):
        on = bool(data.get("on"))
        box = queue.Queue(maxsize=1)

        def job():
            try:
                box.put(self.app.set_protection(on))
            except Exception as ex:
                box.put((False, str(ex)))
        self.app.ui_q.put(job)
        try:
            ok, err = box.get(timeout=6)
        except queue.Empty:
            return {"ok": False, "error": "The app didn't respond - is a dialog open in its window?"}
        st = self.api_state()
        st["ok"], st["error"] = ok, err
        # Invalidate domain cache so next sync pushes the new policy.enabled.
        self._domains_cache = None
        return st

    def api_domains(self):
        _, ads, sec, exc = self._compute_domains()
        return {"ads": ads, "security": sec, "exceptions": exc}

    def _clean_host(self, v):
        h = str(v or "").strip().lower()
        h = re.sub(r"^[a-z]+://", "", h)
        h = re.split(r"[/?#:]", h, 1)[0].lstrip("*.").rstrip(".")
        if h.startswith("www."):
            h = h[4:]
        return h if DOMAIN_RE.match(h) else ""

    def _after_allow_change(self):
        a = self.app
        a.persist()
        self._domains_cache = None
        try:
            a.ui_q.put(a.refresh_allow)
        except Exception:
            log_swallowed("ExtensionBridge._after_allow_change")

    def api_allow(self, data, add):
        """Support both single host and bulk {add: [...]} / {host: ...}."""
        hosts = []
        if isinstance(data.get("add"), list):
            hosts = [self._clean_host(h) for h in data["add"][:500]]
        elif data.get("host"):
            hosts = [self._clean_host(data.get("host"))]
        hosts = [h for h in hosts if h]
        if not hosts:
            return {"ok": False, "error": "invalid host"}
        e = self.app.engine
        with e.lock:
            for h in hosts:
                (e.allow.add if add else e.allow.discard)(h)
            allow = sorted(e.allow)
        self._after_allow_change()
        return {"ok": True, "allow": allow}

    def api_set_allowlist(self, data):
        hosts = {self._clean_host(h) for h in (data.get("allow") or [])[:5000]}
        hosts.discard("")
        e = self.app.engine
        with e.lock:
            e.allow = hosts
        self._after_allow_change()
        return {"ok": True, "allow": sorted(hosts)}

    def api_scan(self, data):
        url = str(data.get("url") or "")[:2048]
        if not re.match(r"^https?://", url, re.I):
            return {"error": "only http(s) URLs can be scanned"}
        r = scan_url(url)
        augment_with_lists(r, self.app.engine)
        blocked = bool(self.app.auto_block_result(r, "extension"))
        return {"url": url, "host": r.host, "score": r.score, "level": r.level,
                "verdict": r.verdict, "error": r.error, "blocked": blocked,
                "findings": [[p, t] for p, t in
                             sorted(r.findings, key=lambda f: -f[0])[:12]]}

    def api_events(self, data):
        """Chrome reports domains it blocked (domain names only)."""
        events = data.get("events") or []
        n = 0
        for ev in events[:300]:
            if not isinstance(ev, dict):
                continue
            h = self._clean_host(ev.get("host"))
            if not h:
                continue
            reason = str(ev.get("reason") or "ads")
            try:
                cnt = max(1, min(int(ev.get("count") or 1), 50))
            except (TypeError, ValueError):
                cnt = 1
            label = "Chrome · malware" if reason == "security" else "Chrome · ads"
            for _ in range(min(cnt, 10)):
                self.app.engine.record(h, True, label, "chrome")
            n += cnt
        try:
            self.app.ui_q.put(self.app.refresh_status)
        except Exception:
            log_swallowed("ExtensionBridge.api_events")
        return {"ok": True, "recorded": n}

    def api_stats(self, data):
        hosts = data.get("hosts") or {}
        n = 0
        if isinstance(hosts, dict):
            for host, cnt in list(hosts.items())[:500]:
                h = self._clean_host(host)
                try:
                    cnt = max(0, min(int(cnt), 1000))
                except (TypeError, ValueError):
                    continue
                for _ in range(min(cnt, 20)):
                    self.app.engine.record(h, True, "browser extension", "chrome")
                n += cnt
        return {"ok": True, "recorded": n}


#  WINDOWS SYSTEM PROXY
# =============================================================================
class SystemProxy:
    KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self, cfg, persist):
        self.cfg, self.persist = cfg, persist

    @staticmethod
    def supported():
        return sys.platform.startswith("win")

    @staticmethod
    def _refresh():
        try:
            import ctypes
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except Exception:
            log_swallowed("SystemProxy._refresh")

    def enable(self, host, port):
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY, 0,
                             winreg.KEY_ALL_ACCESS)
        try:
            if not self.cfg.get("sysproxy_backup"):
                backup = {}
                for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                    try:
                        v, t = winreg.QueryValueEx(key, name)
                        backup[name] = [v, t]
                    except FileNotFoundError:
                        backup[name] = None
                self.cfg["sysproxy_backup"] = backup
                self.persist()
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                              f"{host}:{port}")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        finally:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass
        self._refresh()

    def restore(self):
        backup = self.cfg.get("sysproxy_backup")
        if not backup:
            return
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY, 0,
                             winreg.KEY_ALL_ACCESS)
        try:
            for name, val in backup.items():
                try:
                    if val is None:
                        winreg.DeleteValue(key, name)
                    else:
                        winreg.SetValueEx(key, name, 0, val[1], val[0])
                except FileNotFoundError:
                    pass
        finally:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass
        self.cfg.pop("sysproxy_backup", None)
        self.persist()
        self._refresh()


# =============================================================================
#  ONLINE THREAT CHECKS
# =============================================================================
def check_dns(host):
    j = _json(f"https://dns.google/resolve?name={quote(host)}&type=A",
              {"Accept": "application/dns-json"})
    ev = []
    if j.get("Status") == 3:
        ev.append((12, "Domain does not exist in DNS (NXDOMAIN) — dead or throwaway link."))
        return ev
    ips = [a["data"] for a in j.get("Answer", []) if a.get("type") == 1]
    for ip in ips:
        try:
            if not ipaddress.ip_address(ip).is_global:
                ev.append((30, f"Domain resolves to a private/loopback address ({ip})."))
        except ValueError:
            pass
    ev.append((0, f"Resolves to {', '.join(ips[:3])}." if ips
               else "No A record returned (may be IPv6-only or CNAME-only)."))
    return ev


def check_domain_age(reg):
    j = _json(f"https://rdap.org/domain/{quote(reg)}",
              {"Accept": "application/rdap+json"}, timeout=12)
    created = None
    for e in j.get("events", []):
        if e.get("eventAction") == "registration":
            try:
                created = time.mktime(time.strptime(e["eventDate"][:19],
                                                    "%Y-%m-%dT%H:%M:%S"))
            except (ValueError, KeyError):
                pass
    if created is None:
        return [(0, "Registration date not published for this domain.")]
    days = max(0, int((time.time() - created) / 86400))
    if days < 7:
        return [(45, f"Domain was registered only {days} day(s) ago — typical of phishing infrastructure.")]
    if days < 30:
        return [(35, f"Domain was registered {days} days ago (under a month old).")]
    if days < 90:
        return [(20, f"Domain is only {days} days old (under 3 months).")]
    if days < 365:
        return [(6, f"Domain is {days // 30} months old.")]
    return [(0, f"Domain has existed for about {days // 365} year(s).")]


def check_tls(host, port):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
    except ssl.SSLCertVerificationError as e:
        msg = getattr(e, "verify_message", None) or str(e)
        return [(40, f"TLS certificate failed verification: {msg}.")]
    except (ssl.SSLError, OSError) as e:
        return [(10, f"Could not establish a secure (TLS) connection ({type(e).__name__}).")]
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    org = issuer.get("organizationName") or issuer.get("commonName") or "unknown issuer"
    try:
        age = (time.time() - ssl.cert_time_to_seconds(cert["notBefore"])) / 86400
    except Exception:
        age = 999
    ev = [(0, f"Valid TLS certificate issued by {org}.")]
    if age < 3:
        ev.append((8, "TLS certificate was issued within the last 3 days."))
    return ev


def trace_redirects(url, orig_reg, max_hops=8):
    chain, cur, note, reached = [url], url, None, False
    for hop in range(max_hops):
        p = urlparse(cur)
        host = p.hostname
        if not host:
            break
        https = p.scheme == "https"
        port = p.port or (443 if https else 80)
        if hop > 0:
            try:
                ip = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
                if not ipaddress.ip_address(ip).is_global:
                    note = "A redirect points into a private network address; trace stopped."
                    break
            except (OSError, ValueError):
                break
        conn = (http.client.HTTPSConnection if https else http.client.HTTPConnection)(
            host, port, timeout=8)
        try:
            conn.request("GET",
                         (p.path or "/") + ("?" + p.query if p.query else ""),
                         headers={"User-Agent": UA, "Accept": "text/html",
                                  "Connection": "close"})
            resp = conn.getresponse()
            status, loc = resp.status, resp.getheader("Location")
            reached = True
        except ssl.SSLError:
            note = "TLS verification failed while following the link."
            break
        except (OSError, http.client.HTTPException):
            break
        finally:
            try:
                conn.close()
            except Exception:
                log_swallowed("trace_redirects")
        if 300 <= status < 400 and loc:
            cur = urljoin(cur, loc)
            chain.append(cur)
        else:
            break
    if not reached:
        out = [(0, "Could not reach the site to trace redirects (offline, blocked or down).")]
        if note:
            out.append((8, note))
        return out
    hops = len(chain) - 1
    ev = []
    if hops == 0:
        ev.append((0, "No redirects: the link opens directly."))
        if note:
            ev.append((8, note))
        return ev
    fhost = (urlparse(chain[-1]).hostname or "").lower()
    freg = split_domain(fhost)[0] if fhost else ""
    ev.append((0, f"Redirects {hops} time(s); final destination host is {fhost}."))
    domains = {split_domain((urlparse(c).hostname or "").lower())[0] for c in chain}
    if len(domains) > 1 and freg != orig_reg:
        ev.append((min(30, 10 * (len(domains) - 1)),
                   f"Link hops across {len(domains)} different domains before landing on {freg}."))
    if hops >= 4:
        ev.append((10, f"Long redirect chain ({hops} hops)."))
    if freg != orig_reg:
        try:
            final = scan_url(chain[-1])
            top = sorted((f for f in final.findings if f[0] > 0),
                         key=lambda f: -f[0])[:5]
            for pts, reason in top:
                ev.append((max(1, round(pts * 0.8)),
                           f"Final destination ({fhost}): {reason}"))
        except Exception:
            log_swallowed("trace_redirects")
    if note:
        ev.append((8, note))
    return ev


_OP_CACHE = {"ts": 0, "urls": set(), "hosts": set()}
_OP_LOCK = threading.Lock()


def check_openphish(url, host):
    with _OP_LOCK:
        if time.time() - _OP_CACHE["ts"] > 3600:
            try:
                txt = _http("https://openphish.com/feed.txt", timeout=15,
                            limit=20_000_000).decode("utf-8", "replace")
                urls = {u.strip().rstrip("/").lower()
                        for u in txt.splitlines() if u.strip()}
                _OP_CACHE.update(ts=time.time(), urls=urls,
                                 hosts={(urlparse(u).hostname or "") for u in urls})
            except Exception:
                _OP_CACHE["ts"] = time.time()
        urls, hosts = _OP_CACHE["urls"], _OP_CACHE["hosts"]
    if url.rstrip("/").lower() in urls:
        return [(95, "Listed in the OpenPhish live phishing feed.")]
    if host in hosts:
        return [(65, "Host appears in the OpenPhish live phishing feed (different page).")]
    return [(0, "Not found in the OpenPhish community feed.")]


def _vt_events(stats, what="URL"):
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(v for v in stats.values() if isinstance(v, int))
    if mal >= 5:
        return [(90, f"VirusTotal: {mal} of {total} security engines flag this {what} as malicious.")]
    if mal >= 2:
        return [(70, f"VirusTotal: {mal} of {total} engines flag this {what} as malicious.")]
    if mal == 1:
        return [(35, f"VirusTotal: 1 of {total} engines flags this {what} (could be a false positive).")]
    if sus >= 3:
        return [(25, f"VirusTotal: {sus} engines call this {what} suspicious.")]
    if sus >= 1:
        return [(10, f"VirusTotal: {sus} engine(s) call this {what} suspicious.")]
    return [(0, f"VirusTotal: 0 of {total} engines flagged this {what}.")]


def check_virustotal(url, key, submit=False):
    uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    hdr = {"x-apikey": key, "accept": "application/json"}
    try:
        stats = _json(f"https://www.virustotal.com/api/v3/urls/{uid}", hdr) \
            ["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return [(0, "VirusTotal rejected the API key.")]
        if e.code == 429:
            return [(0, "VirusTotal rate limit reached (free keys allow 4 lookups/minute).")]
        if e.code != 404:
            raise
        if not submit:
            return [(0, "VirusTotal has no report for this URL (not submitted, to protect your privacy).")]
        sub = _json("https://www.virustotal.com/api/v3/urls",
                    {**hdr, "content-type": "application/x-www-form-urlencoded"},
                    data=urlencode({"url": url}).encode())
        aid = sub["data"]["id"]
        for _ in range(8):
            time.sleep(3)
            at = _json(f"https://www.virustotal.com/api/v3/analyses/{aid}", hdr) \
                ["data"]["attributes"]
            if at.get("status") == "completed":
                return _vt_events(at["stats"])
        return [(0, "VirusTotal analysis is still queued — try again shortly.")]
    return _vt_events(stats)


def check_vt_file(sha256, key):
    try:
        stats = _json(f"https://www.virustotal.com/api/v3/files/{sha256}",
                      {"x-apikey": key})["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [(0, "VirusTotal has never seen this file (only its hash was sent; the file was not uploaded).")]
        if e.code in (401, 403):
            return [(0, "VirusTotal rejected the API key.")]
        if e.code == 429:
            return [(0, "VirusTotal rate limit reached.")]
        raise
    return _vt_events(stats, "file")


def check_safe_browsing(url, key):
    body = {
        "client": {"clientId": "ironclados", "clientVersion": "3.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        j = _json("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
                  quote(key),
                  {"Content-Type": "application/json"},
                  data=json.dumps(body).encode())
    except urllib.error.HTTPError as e:
        if e.code in (400, 403):
            return [(0, "Google Safe Browsing rejected the key (is the Safe Browsing API enabled for it?).")]
        raise
    matches = j.get("matches", [])
    if matches:
        kinds = ", ".join(sorted({m.get("threatType", "?") for m in matches}))
        return [(95, f"Google Safe Browsing lists this URL: {kinds}.")]
    return [(0, "Google Safe Browsing: no match.")]


def check_urlhaus(url, host, key):
    hdr = {"Auth-Key": key}
    j = _json("https://urlhaus-api.abuse.ch/v1/url/", hdr,
              data=urlencode({"url": url}).encode())
    if j.get("query_status") == "ok":
        threat = j.get("threat") or "malware"
        if j.get("url_status") == "online":
            return [(95, f"URLhaus: this URL is an ACTIVE {threat} distribution point.")]
        return [(75, f"URLhaus: this URL was used to distribute {threat} "
                     f"(now {j.get('url_status', 'offline')}).")]
    h = _json("https://urlhaus-api.abuse.ch/v1/host/", hdr,
              data=urlencode({"host": host}).encode())
    if h.get("query_status") == "ok":
        online = int(h.get("urls_online") or 0)
        total = int(h.get("url_count") or 0)
        if online:
            return [(70, f"URLhaus: this host currently serves {online} malware URL(s).")]
        if total:
            return [(40, f"URLhaus: this host previously served {total} malware URL(s).")]
    return [(0, "URLhaus: no matching records.")]


def run_online_checks(res, opts, keys, emit, status, cancelled, vt_submit=False):
    host, reg = res.host, res.registered_domain
    url = res.normalized or res.url
    is_ip = parse_ip_host(host) is not None
    tasks = {}
    if "feeds" in opts:
        tasks["Phishing feed"] = lambda: check_openphish(url, host)
    if "dns" in opts and not is_ip:
        tasks["DNS"] = lambda: check_dns(host)
    shared = any(host == s or host.endswith("." + s) for s in PRIVATE_SUFFIX)
    if "age" in opts and not is_ip and not res.official and not shared and "." in reg:
        tasks["Domain age"] = lambda: check_domain_age(reg)
    if "tls" in opts and not is_ip and url.lower().startswith("https"):
        try:
            port = urlparse(url).port or 443
        except Exception:
            port = 443
        tasks["TLS"] = lambda: check_tls(host, port)
    if "trace" in opts:
        tasks["Redirects"] = lambda: trace_redirects(url, reg)
    if "vt" in opts and keys.get("vt"):
        tasks["VirusTotal"] = lambda: check_virustotal(url, keys["vt"], vt_submit)
    if "gsb" in opts and keys.get("gsb"):
        tasks["Safe Browsing"] = lambda: check_safe_browsing(url, keys["gsb"])
    if "urlhaus" in opts and keys.get("urlhaus"):
        tasks["URLhaus"] = lambda: check_urlhaus(url, host, keys["urlhaus"])
    if not tasks:
        return
    status(f"Running {len(tasks)} online check(s)…")
    pool = ThreadPoolExecutor(max_workers=min(8, len(tasks)))
    futures = {pool.submit(fn): name for name, fn in tasks.items()}
    done = 0
    try:
        for fut in as_completed(futures):
            if cancelled():
                break
            name = futures[fut]
            try:
                events = fut.result()
            except Exception as e:
                events = [(0, f"{name} check unavailable ({type(e).__name__}).")]
            for pts, reason in events:
                if cancelled():
                    break
                try:
                    emit(pts, reason, name)
                except Exception:
                    log_swallowed("run_online_checks")
            done += 1
            status(f"{done}/{len(tasks)} online checks complete")
    finally:
        try:
            pool.shutdown(wait=False)
        except Exception:
            log_swallowed("run_online_checks")


# =============================================================================
#  UI PRIMITIVES
# =============================================================================
_LabelBase = tk.Label if tk else object
_CanvasBase = tk.Canvas if tk else object


class FlatButton(_LabelBase):
    STYLES = {
        "primary":   (ADOBE_RED,   ADOBE_RED_HOVER,   "#ffffff"),
        "secondary": (BG3,         BG4,               TEXT),
        "ghost":     (BG2,         BG3,               MUTED),
        "accent":    (ACCENT,      ACCENT_HOVER,      "#ffffff"),
        "success":   (GREEN,       GREEN_HOVER,       "#ffffff"),
        "danger":    (DANGER,      DANGER_HOVER,      "#ffffff"),
    }

    def __init__(self, parent, text, command=None, style="primary", **kw):
        bg, hover, fg = self.STYLES.get(style, self.STYLES["primary"])
        kw.setdefault("highlightthickness", 1)           # glass rim
        kw.setdefault("highlightbackground", mix(bg, "#ffffff", 0.22))
        kw.setdefault("bd", 0)
        super().__init__(parent, text=text, bg=bg, fg=fg,
                         font=(UI_FONT, 10, "bold"),
                         padx=16, pady=7, cursor="hand2", **kw)
        self._colors = (bg, hover, fg)
        self.command = command
        self.enabled = True
        self._style_name = style
        self.bind("<Enter>", lambda e: self.enabled and self._paint(True))
        self.bind("<Leave>", lambda e: self._paint(False))
        self.bind("<ButtonRelease-1>", self._click)

    def _click(self, e):
        if self.enabled and self.command:
            try:
                if 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height():
                    self.command()
            except Exception:
                log_exc()

    def _paint(self, hot):
        bg = self._colors[1] if hot else self._colors[0]
        self.config(bg=bg, highlightbackground=mix(bg, "#ffffff", 0.30 if hot else 0.22))

    def set_style(self, style):
        self._style_name = style
        self._colors = self.STYLES.get(style, self.STYLES["primary"])
        self.config(fg=self._colors[2])
        self._paint(False)

    def set_text(self, text):
        self.config(text=text)

    def set_enabled(self, on):
        self.enabled = on
        self.config(fg=self._colors[2] if on else MUTED,
                    cursor="hand2" if on else "arrow")


class Gauge(_CanvasBase):
    def __init__(self, parent, size=230, bg=BG2):
        super().__init__(parent, width=size, height=int(size * 0.68),
                         bg=bg, highlightthickness=0)
        self.size = size
        self.bg_color = bg
        self.value = self.target = 0.0
        self.color = MUTED
        self.caption = "Ready"
        self.center = "—"
        self._job = None
        self.draw()

    def set(self, target, color, caption, center=None):
        self.target = float(target)
        self.color = color
        self.caption = caption
        self.center = str(int(target)) if center is None else str(center)
        self._step()

    def _step(self):
        if self._job is not None:
            try:
                self.after_cancel(self._job)
            except Exception:
                log_swallowed("Gauge._step")
            self._job = None
        diff = self.target - self.value
        if abs(diff) <= 1:
            self.value = self.target
            self.draw()
            return
        self.value += diff * 0.22 if abs(diff) > 4 else (1 if diff > 0 else -1)
        self.draw()
        try:
            self._job = self.after(16, self._step)
        except Exception:
            self._job = None

    def draw(self):
        try:
            s, pad = self.size, 20
            self.delete("all")
            box = (pad, pad, s - pad, s - pad)
            self.create_arc(*box, start=180, extent=-180, style="arc",
                            outline=BG3, width=16)
            if self.value > 0:
                self.create_arc(*box, start=180, extent=-180 * self.value / 100,
                                style="arc", outline=self.color, width=16)
            self.create_text(s / 2, s * 0.40, text=self.center, fill=TEXT,
                             font=(UI_FONT, 34, "bold"))
            show_slash = bool(self.center) and self.center.lstrip("-").isdigit()
            self.create_text(s / 2, s * 0.54,
                             text="/ 100" if show_slash else "",
                             fill=MUTED, font=(UI_FONT, 10))
            self.create_text(s / 2, s * 0.64, text=self.caption,
                             fill=self.color, font=(UI_FONT, 11, "bold"))
        except Exception:
            log_swallowed("Gauge.draw")


# =============================================================================
#  GLASS UI PRIMITIVES
# =============================================================================
def aurora_rgb(u, v):
    """Soft colour field for the window backdrop; u and v run 0..1 across the window."""
    c = _rgb(BG_ROOT)
    for cx, cy, rad, col, k in (
            (0.10, 0.08, 0.55, (15, 184, 164), 0.55),    # teal glow, top-left
            (0.95, 0.16, 0.50, (10, 132, 255), 0.62),    # blue glow, top-right
            (0.78, 1.00, 0.62, (191, 90, 242), 0.52),    # violet glow, bottom-right
            (0.02, 0.95, 0.42, (48, 209, 88), 0.20)):    # faint green, bottom-left
        d = math.hypot(u - cx, (v - cy) * 0.75) / rad
        w = k * math.exp(-2.4 * d * d)
        c = tuple(c[i] + (col[i] - c[i]) * w for i in range(3))
    return tuple(int(x) for x in c)


def _rr_points(x1, y1, x2, y2, r):
    """Point list for a rounded rectangle drawn as a smooth Tk polygon."""
    return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
            x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]


def _bg_of(widget):
    try:
        return widget.cget("bg")
    except Exception:
        return BG0


_FrameBase = tk.Frame if tk else object


class GlassCard(_FrameBase):
    """A frosted, rounded card. Put content in `.body` (a normal Frame).

    A canvas sits behind the body (via place) and paints the rounded glass, so the card
    sizes itself from its content and `pack(expand=True)` works like it does for a Frame.
    """

    def __init__(self, parent, radius=16, fill=None):
        pbg = _bg_of(parent)
        super().__init__(parent, bg=pbg)
        self.fill = fill or BG2
        self.radius = radius
        self._cv = tk.Canvas(self, bg=pbg, highlightthickness=0, bd=0)
        self._cv.place(x=0, y=0, relwidth=1, relheight=1)
        m = max(3, int(radius * 0.30)) + 1        # keeps the body's square corners inside the curve
        self.body = tk.Frame(self, bg=self.fill)
        self.body.pack(fill="both", expand=True, padx=m, pady=m)
        self._cv.bind("<Configure>", self._paint)

    def _paint(self, e):
        w, h, r = e.width, e.height, self.radius
        if w < 4 or h < 4:
            return
        try:
            cv = self._cv
            cv.delete("all")
            cv.create_polygon(_rr_points(1, 1, w - 2, h - 2, r), smooth=True,
                              fill=self.fill, outline=GLASS_EDGE, width=1)
            if w > 2 * r + 8:                      # specular highlight along the top edge
                cv.create_line(r + 2, 2, w - r - 2, 2, fill=GLASS_SPEC)
        except Exception:
            log_swallowed("GlassCard._paint")


class AuroraBackdrop(_CanvasBase):
    """Window-sized canvas: aurora gradient underneath, rounded glass panels on top."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG_ROOT, highlightthickness=0, bd=0)
        self._img = None
        self._job = None
        self._panels = []
        self.bind("<Configure>", self._on_configure)

    def add_panel(self, widget, geom, radius=24, fill=BG1, inset=9):
        """geom(W, H) -> (x, y, w, h). The widget is clipped inside the glass rim by `inset`."""
        item = self.create_window(0, 0, anchor="nw", window=widget)
        self._panels.append({"widget": widget, "item": item, "geom": geom, "r": radius,
                             "fill": fill, "inset": inset, "tag": f"panel{len(self._panels)}"})

    def _on_configure(self, e):
        self._layout(e.width, e.height)
        try:
            if self._job is not None:
                self.after_cancel(self._job)
            self._job = self.after(70, self._paint_aurora)
        except Exception:
            log_swallowed("AuroraBackdrop._on_configure")

    def _layout(self, W, H):
        try:
            for p in self._panels:
                x, y, w, h = p["geom"](W, H)
                w, h = max(w, 40), max(h, 40)
                self.delete(p["tag"])
                self.create_polygon(_rr_points(x, y, x + w, y + h, p["r"]), smooth=True,
                                    fill=p["fill"], outline=GLASS_EDGE, width=1, tags=p["tag"])
                self.create_line(x + p["r"], y + 1, x + w - p["r"], y + 1,
                                 fill=GLASS_SPEC, tags=p["tag"])
                i = p["inset"]
                self.coords(p["item"], x + i, y + i)
                self.itemconfigure(p["item"], width=max(1, w - 2 * i), height=max(1, h - 2 * i))
            self.tag_lower("aurora")
        except Exception:
            log_swallowed("AuroraBackdrop._layout")

    def _paint_aurora(self):
        self._job = None
        try:
            W, H = self.winfo_width(), self.winfo_height()
            if W < 40 or H < 40:
                return
            self.delete("aurora")
            try:
                from PIL import Image, ImageTk          # optional (also used for QR scanning)
                lw, lh = 96, 60
                img = Image.new("RGB", (lw, lh))
                img.putdata([aurora_rgb(x / (lw - 1), y / (lh - 1))
                             for y in range(lh) for x in range(lw)])
                resample = getattr(getattr(Image, "Resampling", Image), "BICUBIC")
                self._img = ImageTk.PhotoImage(img.resize((W, H), resample))
                self.create_image(0, 0, anchor="nw", image=self._img, tags="aurora")
            except Exception:                           # no Pillow: banded vertical gradient
                n = max(1, H // 6)
                for i in range(n):
                    col = _hex(aurora_rgb(0.5, i / max(1, n - 1)))
                    self.create_rectangle(0, i * H // n, W, (i + 1) * H // n + 1,
                                          fill=col, outline="", tags="aurora")
            self.tag_lower("aurora")
        except Exception:
            log_swallowed("AuroraBackdrop._paint_aurora")


def apply_native_glass(root, alpha=0.97):
    """Optional polish: dark title bar + rounded corners on Windows 11, faint window translucency."""
    try:
        if 0.5 <= alpha < 1.0:
            root.attributes("-alpha", alpha)
    except Exception:
        log_swallowed("apply_native_glass")
    if os.name != "nt":
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()

        def put(attr, val):
            v = ctypes.c_int(val)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(v), ctypes.sizeof(v))

        def colorref(c):
            r, g, b = _rgb(c)
            return r | (g << 8) | (b << 16)

        put(20, 1)                       # dark title bar (Windows 10 2004+ / 11)
        put(33, 2)                       # rounded window corners (Windows 11)
        put(34, colorref(GLASS_EDGE))    # window border colour (Windows 11)
        put(35, colorref(BG_ROOT))       # title-bar colour (Windows 11)
        put(36, colorref(TEXT))          # title-bar text colour (Windows 11)
    except Exception:
        log_swallowed("apply_native_glass")


# =============================================================================
#  THREAT ALERTS (desktop toasts)
# =============================================================================
ALERT_KINDS = {
    # kind: (severity, title, accent colour attribute name, icon, seconds on screen)
    "malware":    (3, "Malware / phishing blocked", "DANGER", "⛨", 9.0),
    "danger":     (2, "Dangerous link blocked", "ORANGE", "⚠", 8.0),
    "aggressive": (1, "Aggressive ad network blocked", "YELLOW", "⛔", 6.0),
}
NOTIFY_DEFAULTS = {"enabled": True, "malware": True, "danger": True, "aggressive": True,
                   "cooldown": 60}


def classify_block(host, reason):
    """Which alert category a blocked request belongs to, or None for ordinary ads/trackers.

    malware     - host is on a malware/phishing feed (or was blocked by a scan; also Chrome reports)
    danger      - the threat scanner rated the host 70 or higher
    aggressive  - pop-under / push / redirect ad networks (AGGRESSIVE_AD_DOMAINS)
    """
    r = (reason or "").lower()
    if "malware" in r or "phishing" in r:
        return "malware"
    m = re.search(r"score\D{0,3}(\d+)", r)
    if m and int(m.group(1)) >= 70:
        return "danger"
    h = (host or "").lower().strip("[]").rstrip(".")
    if h and any(h == d or h.endswith("." + d) for d in AGGRESSIVE_AD_DOMAINS):
        return "aggressive"
    return None


class AlertThrottle:
    """Decides WHEN to show a toast. Pure logic (no Tk), so it can be unit-tested.

    * per-host cooldown : the same host + category is announced at most once per `host_cooldown`
                          seconds; repeats are only counted.
    * burst coalescing  : events arriving within `coalesce` seconds of the first one are merged
                          into ONE toast ("+14 more blocked") instead of one toast each.
    * minimum gap       : at least `min_gap` seconds between two toasts.
    * rate cap          : at most `cap` toasts per `cap_window` seconds; whatever is blocked while
                          capped is folded into the next toast that is allowed.
    """

    def __init__(self, host_cooldown=60.0, coalesce=1.0, min_gap=3.0, cap=8, cap_window=300.0):
        self.host_cooldown = host_cooldown
        self.coalesce = coalesce
        self.min_gap = min_gap
        self.cap = cap
        self.cap_window = cap_window
        self._lock = threading.Lock()
        self._host_last = {}          # (kind, host) -> time of last announcement
        self._pending = []            # events waiting for the next toast
        self._first_at = None
        self._suppressed = 0          # events swallowed by the host cooldown since the last toast
        self._last_toast = -1e18
        self._toasts = deque()        # times of recent toasts (for the cap)

    def offer(self, kind, host, reason, source, now):
        """Register one blocked request. Returns True if it will be announced, False if suppressed."""
        key = (kind, host)
        with self._lock:
            last = self._host_last.get(key)
            if last is not None and now - last < self.host_cooldown:
                self._suppressed += 1
                return False
            self._host_last[key] = now
            if len(self._host_last) > 3000:
                cutoff = now - self.host_cooldown
                self._host_last = {k: t for k, t in self._host_last.items() if t >= cutoff}
            if not self._pending:
                self._first_at = now
            self._pending.append({"kind": kind, "host": host, "reason": reason,
                                  "source": source, "t": now})
            if len(self._pending) > 500:
                del self._pending[:250]
            return True

    def has_pending(self):
        with self._lock:
            return bool(self._pending)

    def _ready_at_locked(self, now):
        if not self._pending:
            return None
        t = max(self._first_at + self.coalesce, self._last_toast + self.min_gap)
        while self._toasts and now - self._toasts[0] >= self.cap_window:
            self._toasts.popleft()
        if len(self._toasts) >= self.cap:
            t = max(t, self._toasts[0] + self.cap_window)
        return t

    def next_delay(self, now):
        """Seconds until poll() can produce a digest (None if nothing is waiting)."""
        with self._lock:
            t = self._ready_at_locked(now)
        return None if t is None else max(0.0, t - now)

    def poll(self, now):
        """A digest dict when a toast is due, else None."""
        with self._lock:
            t = self._ready_at_locked(now)
            if t is None or now < t:
                return None
            events, self._pending, self._first_at = self._pending, [], None
            suppressed, self._suppressed = self._suppressed, 0
            self._last_toast = now
            self._toasts.append(now)
        events.sort(key=lambda e: -ALERT_KINDS[e["kind"]][0])      # worst first
        seen, hosts = set(), []
        for e in events:
            if e["host"] not in seen:
                seen.add(e["host"])
                hosts.append(e["host"])
        return {"kind": events[0]["kind"], "head": events[0], "hosts": hosts,
                "events": len(events), "suppressed": suppressed,
                "total": len(events) + suppressed}


class Toast(tk.Toplevel if tk else object):
    """One borderless, always-on-top glass notification. Created and driven on the Tk thread."""
    WIDTH = 372
    KEY = "#010203"          # colour keyed out on Windows so the rounded corners are see-through

    def __init__(self, master, digest, on_gone):
        super().__init__(master)
        self._on_gone = on_gone
        self._hover = False
        self._closing = False
        self._after = None
        kind = digest["kind"]
        _sev, title, color_name, icon, secs = ALERT_KINDS[kind]
        accent = globals()[color_name]
        self.seconds = secs
        self.withdraw()
        self.configure(bg=self.KEY)
        try:
            self.overrideredirect(True)
        except Exception:
            log_swallowed("Toast.overrideredirect")
        for opt, val in (("-topmost", True), ("-alpha", 0.0), ("-transparentcolor", self.KEY)):
            try:
                self.attributes(opt, val)
            except Exception:
                pass                                     # not supported on this platform

        card = GlassCard(self, radius=18, fill=BG2)
        card.pack(fill="both", expand=True)
        b = card.body
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x", padx=14, pady=(12, 12))
        badge = tk.Label(row, text=icon, bg=accent, fg="#10131f", width=2,
                         font=(UI_FONT, 14, "bold"))
        badge.pack(side="left", anchor="n")
        col = tk.Frame(row, bg=BG2)
        col.pack(side="left", fill="x", expand=True, padx=(12, 6))
        top = tk.Frame(col, bg=BG2)
        top.pack(fill="x")
        tk.Label(top, text=title, bg=BG2, fg=TEXT, anchor="w",
                 font=(UI_FONT, 10, "bold")).pack(side="left")
        close = tk.Label(top, text="✕", bg=BG2, fg=MUTED, cursor="hand2", font=(UI_FONT, 10))
        close.pack(side="right")
        close.bind("<Button-1>", lambda e: self.dismiss())
        head = digest["head"]
        tk.Label(col, text=head["host"], bg=BG2, fg=TEXT, anchor="w", justify="left",
                 font=(UI_FONT, 10), wraplength=self.WIDTH - 110).pack(fill="x", pady=(2, 0))
        tk.Label(col, text=self._detail(digest), bg=BG2, fg=MUTED, anchor="w", justify="left",
                 font=(UI_FONT, 9), wraplength=self.WIDTH - 110).pack(fill="x", pady=(1, 0))
        more = digest["total"] - 1
        if more > 0:
            others = [h for h in digest["hosts"] if h != head["host"]][:3]
            txt = f"+{more} more blocked"
            if others:
                txt += " (" + ", ".join(others) + ("…" if len(digest["hosts"]) > 4 else "") + ")"
            tk.Label(col, text=txt, bg=BG2, fg=accent, anchor="w", justify="left",
                     font=(UI_FONT, 9, "bold"), wraplength=self.WIDTH - 110).pack(fill="x", pady=(4, 0))

        for w in (self, card, card.body, row, col, top, badge):
            w.bind("<Enter>", self._enter, add="+")
            w.bind("<Leave>", self._leave, add="+")
            if w is not close:
                w.bind("<Button-1>", lambda e: self.dismiss(), add="+")
        self.update_idletasks()
        self.height = self.winfo_reqheight()

    @staticmethod
    def _detail(d):
        e = d["head"]
        src = {"proxy": "local proxy", "chrome": "Chrome extension"}.get(e.get("source"), "")
        reason = e.get("reason") or ""
        reason = reason.replace("Chrome · ", "") if src == "Chrome extension" else reason
        bits = [x for x in (reason, "via " + src if src else "") if x]
        return " · ".join(bits) or "Request stopped before it reached your browser"

    def place_at(self, x, y):
        self.geometry(f"{self.WIDTH}x{self.height}+{int(x)}+{int(y)}")

    def show(self):
        try:
            self.deiconify()
            self.lift()
        except Exception:
            log_swallowed("Toast.show")
        self._fade(0.0, 0.97, 8, then=self._arm)

    def _fade(self, a, b, steps, then=None, i=0):
        if self._gone():
            return
        try:
            self.attributes("-alpha", a + (b - a) * (i + 1) / steps)
        except Exception:
            pass
        if i + 1 < steps:
            self._after = self.after(18, lambda: self._fade(a, b, steps, then, i + 1))
        elif then:
            then()

    def _gone(self):
        try:
            return not self.winfo_exists()
        except Exception:
            return True

    def _arm(self):
        if self._gone() or self._closing:
            return
        self._deadline = time.time() + self.seconds
        self._watch()

    def _watch(self):
        if self._gone() or self._closing:
            return
        if self._hover:
            self._deadline = time.time() + 2.0              # keep it up while the pointer is on it
        if time.time() >= self._deadline:
            return self.dismiss()
        self._after = self.after(200, self._watch)

    def _enter(self, e=None):
        self._hover = True

    def _leave(self, e=None):
        self._hover = False

    def dismiss(self):
        if self._closing or self._gone():
            return
        self._closing = True
        try:
            if self._after:
                self.after_cancel(self._after)
        except Exception:
            pass
        self._fade(0.97, 0.0, 6, then=self._destroy)

    def _destroy(self):
        try:
            self.destroy()
        except Exception:
            log_swallowed("Toast._destroy")
        try:
            self._on_gone(self)
        except Exception:
            log_swallowed("Toast._destroy")


class ThreatNotifier:
    """Glue between the filtering engine (any thread) and the toast windows (Tk thread)."""
    MAX_VISIBLE = 3

    def __init__(self, app):
        self.app = app
        self.throttle = AlertThrottle()
        self._timer = None                 # Tk after() id, only touched on the Tk thread
        self._timer_lock = threading.Lock()
        self._arm_queued = False
        self.toasts = []
        self.shown = 0                     # toasts shown this session (for the Settings page)

    # ---- settings ---------------------------------------------------------
    def conf(self):
        c = dict(NOTIFY_DEFAULTS)
        try:
            c.update(self.app.cfg.get("notify") or {})
        except Exception:
            log_swallowed("ThreatNotifier.conf")
        return c

    # ---- called from proxy / bridge threads (AdBlockEngine.on_block) -------
    def submit(self, host, reason, source=""):
        try:
            c = self.conf()
            if not c.get("enabled"):
                return
            kind = classify_block(host, reason)
            if not kind or not c.get(kind, True):
                return
            self.throttle.host_cooldown = max(0.0, float(c.get("cooldown", 60)))
            self.throttle.offer(kind, (host or "").lower().rstrip("."), reason, source, time.time())
            with self._timer_lock:
                if self._arm_queued:
                    return
                self._arm_queued = True
            self.app.ui_q.put(self._arm)                    # hop to the Tk thread
        except Exception:
            log_swallowed("ThreatNotifier.submit")

    # ---- Tk thread --------------------------------------------------------
    def _arm(self):
        with self._timer_lock:
            self._arm_queued = False
        if self._timer is not None:
            return
        delay = self.throttle.next_delay(time.time())
        if delay is None:
            return
        self._timer = self.app.root.after(int(delay * 1000) + 30, self._fire)

    def _fire(self):
        self._timer = None
        try:
            digest = self.throttle.poll(time.time())
            if digest:
                self._show(digest)
        except Exception:
            log_exc("ThreatNotifier._fire")
        if self.throttle.has_pending():
            self._arm()

    def _show(self, digest):
        while len(self.toasts) >= self.MAX_VISIBLE:
            self.toasts.pop(0).dismiss()
        t = Toast(self.app.root, digest, self._gone)
        self.toasts.append(t)
        self.shown += 1
        self._layout()
        t.show()

    def _gone(self, toast):
        if toast in self.toasts:
            self.toasts.remove(toast)
        self._layout()

    def _layout(self):
        try:
            root = self.app.root
            sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
            margin, gap, bottom = 20, 10, 64          # bottom leaves room for the taskbar / dock
            y = sh - bottom
            for t in reversed(self.toasts):          # newest at the bottom, older ones above
                y -= t.height
                t.place_at(sw - Toast.WIDTH - margin, y)
                y -= gap
        except Exception:
            log_swallowed("ThreatNotifier._layout")

    def test(self):
        """Settings page 'Send test alert': bypasses the throttle so it always appears."""
        digest = {"kind": "malware",
                  "head": {"kind": "malware", "host": "example-malware.test",
                           "reason": "malware/phishing feed", "source": "proxy"},
                  "hosts": ["example-malware.test"], "events": 1, "suppressed": 0, "total": 1}
        self._show(digest)


# =============================================================================
#  MAIN APPLICATION
# =============================================================================
class IronCladOSApp:
    def __init__(self, root):
        global UI_FONT
        self.root = root
        self.cfg = load_config()
        self.cfg.setdefault("online", {"enabled": True, "dns": True, "age": True,
                                       "tls": True, "trace": True, "feeds": True,
                                       "vt": True, "gsb": True, "urlhaus": True})
        self.cfg.setdefault("keys", {})
        self.cfg.setdefault("auto_update", True)
        self.cfg.setdefault("yt_skip", True)
        self.cfg.setdefault("yt_flash", True)
        self.engine = AdBlockEngine()
        self.engine.apply_config(self.cfg)
        self.lists = ListManager(self.engine, self.cfg, self.persist)
        self.cfg.setdefault("auto_block_scans", True)
        if self.cfg.get("user_blocked"):
            self.engine.set_list("user:blocked", set(self.cfg["user_blocked"]), "security")
        self.sysproxy = SystemProxy(self.cfg, self.persist)
        self.proxy = None
        self.bridge = ExtensionBridge(self)
        self.ui_q = queue.Queue()
        self.cfg.setdefault("notify", dict(NOTIFY_DEFAULTS))
        self.notifier = ThreatNotifier(self)
        self.engine.on_block = self.notifier.submit      # proxy + Chrome blocks -> throttled toasts
        self.scan_seq = self.file_seq = 0
        self.last_result = self.last_file = None
        self.history = []
        self._prot_strips = []
        self._recent_shown = None
        self._ads_warned_for = None

        try:
            import tkinter.font as tkfont
            fams = set(tkfont.families())
            UI_FONT = next((f for f in ("Adobe Clean", "Segoe UI", "SF Pro Text",
                                        "Helvetica Neue", "Ubuntu", "Arial")
                            if f in fams), "Arial")
        except Exception:
            UI_FONT = "Arial"

        try:
            root.report_callback_exception = self._report_callback_exception
        except Exception:
            log_swallowed("IronCladOSApp.__init__")

        self._style()
        self._shell()
        try:
            apply_native_glass(root, float(self.cfg.get("glass_alpha", 0.97)))
        except Exception:
            log_swallowed("IronCladOSApp.__init__")
        self.pages = {}
        for key in ("dashboard", "link", "file", "adblock", "password", "settings"):
            f = tk.Frame(self.container, bg=BG0)
            f.grid(row=0, column=0, sticky="nsew")
            self.pages[key] = f
        self._page_dashboard()
        self._page_link()
        self._page_file()
        self._page_adblock()
        self._page_password()
        self._page_settings()
        self.show_page("dashboard")

        if SystemProxy.supported() and self.cfg.get("sysproxy_backup"):
            try:
                self.sysproxy.restore()
            except Exception:
                log_swallowed("IronCladOSApp.__init__")
        try:
            self.lists.load_cached()
        except Exception:
            log_exc()
        try:
            self.refresh_lists_tree()
        except Exception:
            log_exc()
        if self.cfg.get("bridge_enabled", True):
            self.bridge.start()
        self.refresh_bridge_status()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.bind("<Control-r>", lambda e: self.reset_link())
        root.after(100, self.poll_ui)
        root.after(1000, self.tick)
        if self.cfg.get("auto_update"):
            root.after(2000, self.auto_update_lists)

    def _report_callback_exception(self, exc, val, tb):
        log.error("unhandled exception in a tkinter callback", exc_info=(exc, val, tb))

    def font(self, size=10, bold=False):
        return (UI_FONT, size, "bold" if bold else "normal")

    def persist(self):
        try:
            save_config(self.engine.export_config(self.cfg))
        except Exception:
            log_exc()

    def keys(self):
        k = self.cfg.get("keys", {}) or {}
        return {
            "vt": (k.get("vt") or os.environ.get("VT_API_KEY", "") or "").strip(),
            "gsb": (k.get("gsb") or os.environ.get("GSB_API_KEY", "") or "").strip(),
            "urlhaus": (k.get("urlhaus") or os.environ.get("URLHAUS_AUTH_KEY", "") or "").strip(),
        }

    def lbl(self, parent, text, size=10, bold=False, fg=TEXT, **kw):
        bg = kw.pop("bg", None)
        if bg is None:
            try:
                bg = parent.cget("bg")
            except Exception:
                bg = BG0
        anchor = kw.pop("anchor", "w")
        return tk.Label(parent, text=text, font=self.font(size, bold), fg=fg,
                        bg=bg, anchor=anchor, **kw)

    def card(self, parent, title=None, subtitle=None):
        outer = GlassCard(parent, radius=16, fill=BG2)
        inner = outer.body
        if title:
            head = tk.Frame(inner, bg=BG2)
            head.pack(fill="x", padx=18, pady=(14, 0))
            self.lbl(head, title, 11, True, bg=BG2).pack(fill="x")
            if subtitle:
                self.lbl(head, subtitle, 9, fg=MUTED, bg=BG2, wraplength=520,
                         justify="left").pack(fill="x", pady=(2, 0))
        body = tk.Frame(inner, bg=BG2)
        body.pack(fill="both", expand=True, padx=18, pady=(10, 16))
        return outer, body

    def entry(self, parent, var=None, show=""):
        return tk.Entry(parent, textvariable=var, show=show, bg=BG3, fg=TEXT,
                        insertbackground=TEXT, relief="flat", highlightthickness=1,
                        highlightbackground=BORDER, highlightcolor=ACCENT,
                        font=self.font(11), disabledbackground=BG3)

    def make_tree(self, parent, columns, height=7):
        wrap = tk.Frame(parent, bg=BG2)
        tree = ttk.Treeview(wrap, columns=[c[0] for c in columns],
                            show="headings", height=height, selectmode="browse")
        for cid, title, width, stretch in columns:
            tree.heading(cid, text=title, anchor="w")
            tree.column(cid, width=width, anchor="w", stretch=stretch)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        for tag, color in (("high", DANGER), ("medium", ORANGE),
                           ("low", YELLOW), ("info", MUTED)):
            try:
                tree.tag_configure(tag, foreground=color)
            except Exception:
                log_swallowed("IronCladOSApp.make_tree")
        return wrap, tree

    def _style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            log_swallowed("IronCladOSApp._style")
        try:
            st.configure(".", background=BG0, foreground=TEXT, font=(UI_FONT, 10))
            st.configure("Treeview", background=BG2, fieldbackground=BG2,
                         foreground=TEXT, borderwidth=0, rowheight=28,
                         font=(UI_FONT, 10))
            st.configure("Treeview.Heading", background=BG3, foreground=MUTED,
                         relief="flat", font=(UI_FONT, 9, "bold"), padding=(8, 6))
            st.map("Treeview", background=[("selected", SELECT_BG)],
                   foreground=[("selected", "#ffffff")])
            st.map("Treeview.Heading", background=[("active", BG3)])
            st.configure("Vertical.TScrollbar", background=BG3, troughcolor=BG2,
                         bordercolor=BG2, arrowcolor=MUTED, darkcolor=BG3,
                         lightcolor=BG3, gripcount=0)
            st.configure("Horizontal.TProgressbar", troughcolor=BG3,
                         background=ACCENT, bordercolor=BG3, lightcolor=ACCENT,
                         darkcolor=ACCENT, thickness=4)
            st.configure("TCheckbutton", background=BG2, foreground=TEXT,
                         focuscolor=BG2, font=(UI_FONT, 10))
            st.map("TCheckbutton", background=[("active", BG2)],
                   foreground=[("disabled", "#5b6788")],
                   indicatorcolor=[("selected", ACCENT), ("!selected", BG3)])
        except Exception:
            log_swallowed("IronCladOSApp._style")

    def _shell(self):
        r = self.root
        r.title("IronCladOS")
        r.geometry("1120x780")
        r.minsize(1000, 680)
        r.configure(bg=BG_ROOT)

        self.backdrop = AuroraBackdrop(r)
        self.backdrop.pack(fill="both", expand=True)
        side = tk.Frame(self.backdrop, bg=BG1)
        side.pack_propagate(False)

        brand = tk.Frame(side, bg=BG1)
        brand.pack(fill="x", padx=18, pady=(24, 22))
        tk.Label(brand, text="⛨", bg=ADOBE_RED, fg="#ffffff",
                 font=(UI_FONT, 16, "bold"), width=2).pack(side="left")
        names = tk.Frame(brand, bg=BG1)
        names.pack(side="left", padx=(10, 0))
        self.lbl(names, "IronCladOS", 13, True, bg=BG1).pack(anchor="w")
        self.lbl(names, "Threat protection", 9, fg=MUTED, bg=BG1).pack(anchor="w")

        self.nav = {}
        self.current = "dashboard"
        nav_items = (
            ("dashboard", "Dashboard", "◧"),
            ("link", "Link Scanner", "⊕"),
            ("file", "File Scanner", "▤"),
            ("adblock", "Ad Blocker", "⛔"),
            ("password", "Password Security", "🔑"),
            ("settings", "Settings", "⚙"),
        )
        for key, text, icon in nav_items:
            row = tk.Frame(side, bg=BG1, cursor="hand2")
            row.pack(fill="x")
            bar = tk.Frame(row, bg=BG1, width=3)
            bar.pack(side="left", fill="y")
            lab = tk.Label(row, text=f"{icon}   {text}", bg=BG1, fg=MUTED,
                           anchor="w", font=self.font(10, True),
                           padx=18, pady=11, cursor="hand2")
            lab.pack(side="left", fill="x", expand=True)
            for w in (row, lab):
                w.bind("<Button-1>", lambda e, k=key: self.show_page(k))
                w.bind("<Enter>", lambda e, k=key: self._nav_hover(k))
                w.bind("<Leave>", lambda e: self._nav_paint())
            self.nav[key] = (row, lab, bar)

        foot = tk.Frame(side, bg=BG1)
        foot.pack(side="bottom", fill="x", padx=18, pady=16)
        self.foot_status = self.lbl(foot, "● Protection off", 9, fg=MUTED, bg=BG1)
        self.foot_status.pack(anchor="w")
        self.lbl(foot, "v3.1 · STAI 2026", 8, fg="#5b6788", bg=BG1).pack(
            anchor="w", pady=(2, 0))

        main = tk.Frame(self.backdrop, bg=BG0)
        self.backdrop.add_panel(side, lambda W, H: (16, 16, 244, H - 32), 26, BG1)
        self.backdrop.add_panel(main, lambda W, H: (272, 16, W - 288, H - 32), 26, BG0)
        head = tk.Frame(main, bg=BG0)
        head.pack(fill="x", padx=30, pady=(24, 14))
        self.page_title = self.lbl(head, "", 20, True, bg=BG0)
        self.page_title.pack(fill="x")
        self.page_sub = self.lbl(head, "", 10, fg=MUTED, bg=BG0)
        self.page_sub.pack(fill="x", pady=(2, 0))
        self.container = tk.Frame(main, bg=BG0)
        self.container.pack(fill="both", expand=True, padx=30, pady=(0, 24))
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

    TITLES = {
        "dashboard": ("Dashboard", "Your protection at a glance"),
        "link": ("Link Scanner", "Offline analysis plus optional live threat-intelligence checks"),
        "file": ("File Scanner", "Hash, content and disguise checks for downloaded files"),
        "adblock": ("Ad Blocker", "Block ad, tracker and malware domains system-wide through a local proxy"),
        "password": ("Password Security", "Check password strength locally before continuing"),
        "settings": ("Settings", "API keys, privacy and behaviour"),
    }

    def _nav_hover(self, k):
        if self.current == k:
            return
        try:
            row, lab, _ = self.nav[k]
            row.config(bg=BG3)
            lab.config(bg=BG3)
        except Exception:
            log_swallowed("IronCladOSApp._nav_hover")

    def _nav_paint(self):
        try:
            for k, (row, lab, bar) in self.nav.items():
                on = k == self.current
                bg = BG3 if on else BG1
                row.config(bg=bg)
                lab.config(bg=bg, fg=TEXT if on else MUTED)
                bar.config(bg=ADOBE_RED if on else bg)
        except Exception:
            log_swallowed("IronCladOSApp._nav_paint")

    def show_page(self, key):
        try:
            self.current = key
            self.pages[key].tkraise()
            self.page_title.config(text=self.TITLES[key][0])
            self.page_sub.config(text=self.TITLES[key][1])
            self._nav_paint()
        except Exception:
            log_exc()

    def _page_dashboard(self):
        pg = self.pages["dashboard"]
        tiles = tk.Frame(pg, bg=BG0)
        tiles.pack(fill="x")

        def tile(title, first=False):
            outer, body = self.card(tiles)
            outer.pack(side="left", fill="both", expand=True,
                       padx=(0 if first else 7, 7))
            self.lbl(body, title.upper(), 8, True, fg=MUTED, bg=BG2).pack(fill="x")
            val = self.lbl(body, "—", 22, True, bg=BG2)
            val.pack(fill="x", pady=(4, 0))
            sub = self.lbl(body, "", 9, fg=MUTED, bg=BG2)
            sub.pack(fill="x")
            return body, val, sub

        body, self.t_prot, self.t_prot_sub = tile("Ad & tracker protection", True)
        self.t_prot_btn = FlatButton(body, "Start protection", self.toggle_protection)
        self.t_prot_btn.pack(anchor="w", pady=(10, 0))
        _, self.t_blocked, self.t_blocked_sub = tile("Requests blocked")
        _, self.t_domains, self.t_domains_sub = tile("Domains on blocklists")

        lower = tk.Frame(pg, bg=BG0)
        lower.pack(fill="both", expand=True, pady=(14, 0))
        left = tk.Frame(lower, bg=BG0)
        left.pack(side="left", fill="both", expand=True, padx=(0, 7))
        right = tk.Frame(lower, bg=BG0)
        right.pack(side="left", fill="both", expand=True, padx=(7, 0))

        o, b = self.card(left, "Quick link check",
                         "Paste a link to scan it before you click.")
        o.pack(fill="x")
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x")
        self.quick_entry = self.entry(row)
        self.quick_entry.pack(side="left", fill="x", expand=True, ipady=7)
        self.quick_entry.bind("<Return>", lambda e: self.quick_scan())
        FlatButton(row, "Scan", self.quick_scan).pack(side="left", padx=(8, 0))

        o, b = self.card(left, "Recent activity")
        o.pack(fill="both", expand=True, pady=(14, 0))
        wrap, self.hist_tree = self.make_tree(
            b,
            (("time", "Time", 70, False), ("type", "Type", 60, False),
             ("target", "Target", 230, True), ("verdict", "Result", 110, False)),
            6)
        wrap.pack(fill="both", expand=True)

        o, b = self.card(right, "Protection status", "What is active right now.")
        o.pack(fill="both", expand=True)
        self.status_rows = {}
        for key, title in (("proxy", "Local filtering proxy"),
                           ("sys", "System proxy"),
                           ("lists", "Blocklists"),
                           ("online", "Online checks"),
                           ("intel", "Threat-intel API keys")):
            row = tk.Frame(b, bg=BG2)
            row.pack(fill="x", pady=5)
            dot = self.lbl(row, "●", 10, fg=MUTED, bg=BG2)
            dot.pack(side="left")
            self.lbl(row, title, 10, bg=BG2).pack(side="left", padx=(8, 0))
            val = self.lbl(row, "", 9, fg=MUTED, bg=BG2, anchor="e")
            val.pack(side="right")
            self.status_rows[key] = (dot, val)

    def quick_scan(self):
        try:
            url = self.quick_entry.get().strip()
        except Exception:
            url = ""
        if url:
            try:
                self.link_entry.delete(0, tk.END)
                self.link_entry.insert(0, url)
            except Exception:
                log_swallowed("IronCladOSApp.quick_scan")
            self.start_link_scan()

    def _page_link(self):
        pg = self.pages["link"]
        self._protection_strip(pg)
        o, b = self.card(pg)
        o.pack(fill="x")
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x")
        self.link_entry = self.entry(row)
        self.link_entry.pack(side="left", fill="x", expand=True, ipady=8)
        self.link_entry.insert(0, "https://example.com")
        self.link_entry.bind("<Return>", lambda e: self.start_link_scan())
        for seq in ("<Control-v>", "<Command-v>"):
            self.link_entry.bind(seq, lambda e: (self.paste_link(), "break")[1])
        FlatButton(row, "Paste", self.paste_link, "secondary").pack(side="left", padx=(8, 0))
        self.btn_scan = FlatButton(row, "Scan link", self.start_link_scan)
        self.btn_scan.pack(side="left", padx=(8, 0))

        opts = self.cfg.get("online", {}) or {}
        self.var_online = tk.BooleanVar(value=bool(opts.get("enabled", True)))
        self.opt_vars = {}
        orow = tk.Frame(b, bg=BG2)
        orow.pack(fill="x", pady=(12, 0))
        ttk.Checkbutton(orow, text="Deep scan (online)",
                        variable=self.var_online,
                        command=self.save_opts).pack(side="left")
        self.cbs = {}
        for key, text in (("dns", "DNS"), ("age", "Domain age"),
                          ("tls", "TLS cert"), ("trace", "Follow redirects"),
                          ("feeds", "Phishing feed"), ("vt", "VirusTotal"),
                          ("gsb", "Safe Browsing"), ("urlhaus", "URLhaus")):
            self.opt_vars[key] = tk.BooleanVar(value=bool(opts.get(key, True)))
            cb = ttk.Checkbutton(orow, text=text, variable=self.opt_vars[key],
                                 command=self.save_opts)
            cb.pack(side="left", padx=(14, 0))
            self.cbs[key] = cb
        self.lbl(b, "Deep scan contacts DNS, the domain registry and (headers only) the site itself. "
                    "Keyed services need an API key in Settings.",
                 8, fg=MUTED, bg=BG2).pack(fill="x", pady=(8, 0))
        self.refresh_key_state()

        o, b = self.card(pg)
        o.pack(fill="x", pady=(14, 0))
        self.link_ctx = self._result_panel(b, "link")

        o, b = self.card(pg, "Findings")
        o.pack(fill="both", expand=True, pady=(14, 0))
        wrap, tree = self.make_tree(
            b,
            (("sev", "Severity", 80, False), ("pts", "Pts", 50, False),
             ("src", "Source", 110, False), ("msg", "Finding", 560, True)),
            7)
        wrap.pack(fill="both", expand=True)
        self.link_ctx["tree"] = tree
        detail = self.lbl(b, "Select a finding to read it in full.", 9,
                          fg=MUTED, bg=BG2, wraplength=820, justify="left")
        detail.pack(fill="x", pady=(8, 0))
        tree.bind("<<TreeviewSelect>>", lambda e: self._show_detail(tree, detail))
        btns = tk.Frame(b, bg=BG2)
        btns.pack(fill="x", pady=(10, 0))
        FlatButton(btns, "Copy report", self.copy_report, "secondary").pack(side="left")
        FlatButton(btns, "Export…", self.export_report, "secondary").pack(side="left", padx=(8, 0))
        FlatButton(btns, "Block this domain", self.link_block_domain, "secondary").pack(side="left", padx=(8, 0))
        FlatButton(btns, "Reset", self.reset_link, "ghost").pack(side="left", padx=(8, 0))

    def _result_panel(self, parent, kind):
        row = tk.Frame(parent, bg=BG2)
        row.pack(fill="x")
        gauge = Gauge(row)
        gauge.pack(side="left")
        info = tk.Frame(row, bg=BG2)
        info.pack(side="left", fill="both", expand=True, padx=(20, 0))
        verdict = self.lbl(info,
                           "Paste a link and press Scan" if kind == "link"
                           else "Choose a file to scan",
                           16, True, bg=BG2, wraplength=620, justify="left")
        verdict.pack(fill="x", pady=(18, 4))
        sub = self.lbl(info, "", 10, fg=MUTED, bg=BG2, wraplength=620,
                       justify="left")
        sub.pack(fill="x")
        extra = self.lbl(info, "", 9, fg=MUTED, bg=BG2, wraplength=620,
                         justify="left")
        extra.pack(fill="x", pady=(4, 0))
        bar = ttk.Progressbar(info, mode="indeterminate", length=320)
        busy = self.lbl(info, "", 9, fg=ACCENT, bg=BG2)
        busy.pack(fill="x", pady=(10, 0))
        return {"gauge": gauge, "verdict": verdict, "sub": sub, "extra": extra,
                "bar": bar, "busy": busy, "tree": None}

    def _show_detail(self, tree, label):
        try:
            sel = tree.selection()
            if sel:
                vals = tree.item(sel[0], "values")
                if len(vals) >= 4:
                    label.config(text=vals[3])
        except Exception:
            log_swallowed("IronCladOSApp._show_detail")

    def _fill_tree(self, tree, r):
        try:
            tree.delete(*tree.get_children())
            for pts, reason in sorted(r.findings, key=lambda f: -f[0]):
                sev = "High" if pts >= 35 else "Medium" if pts >= 12 else "Low" if pts > 0 else "Info"
                tree.insert("", "end",
                            values=(sev, f"{pts:+d}" if pts else "0",
                                    r.sources.get(reason, "Local"), reason),
                            tags=(sev.lower(),))
        except Exception:
            log_exc()

    def render(self, ctx, r):
        try:
            if r.error and not r.findings:
                ctx["gauge"].set(0, MUTED, "—", "—")
                ctx["verdict"].config(text=r.error, fg=YELLOW)
                ctx["sub"].config(text="")
                ctx["extra"].config(text="")
                if ctx["tree"] is not None:
                    ctx["tree"].delete(*ctx["tree"].get_children())
                return
            color = LEVEL_COLOR[r.level]
            cap = (SHORT_VERDICT[r.level] if r.kind == "link"
                   else ("No known threats" if r.level == "info" else SHORT_VERDICT[r.level]))
            ctx["gauge"].set(r.score, color, cap)
            ctx["verdict"].config(text=r.verdict, fg=color)
            if r.kind == "link":
                ctx["sub"].config(text=f"{r.host}   ·   registered domain: {r.registered_domain}")
                ctx["extra"].config(text=("Ad/tracker network   " if r.ad_network else "") +
                                         (f"Final destination: {r.final_url}" if r.final_url else ""))
            else:
                ctx["sub"].config(text=f"{os.path.basename(r.url)}   ·   {self._fmt_size(r.size)}")
                ctx["extra"].config(text=f"SHA-256: {r.sha256}")
            if ctx["tree"] is not None:
                self._fill_tree(ctx["tree"], r)
        except Exception:
            log_exc()

    @staticmethod
    def _fmt_size(n):
        try:
            n = float(n)
        except (TypeError, ValueError):
            return "?"
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024

    def set_busy(self, ctx, on, text=""):
        try:
            if on:
                try:
                    ctx["bar"].pack(anchor="w", pady=(10, 0), before=ctx["busy"])
                except Exception:
                    log_swallowed("IronCladOSApp.set_busy")
                ctx["bar"].start(12)
            else:
                ctx["bar"].stop()
                try:
                    ctx["bar"].pack_forget()
                except Exception:
                    log_swallowed("IronCladOSApp.set_busy")
            ctx["busy"].config(text=text)
        except Exception:
            log_swallowed("IronCladOSApp.set_busy")

    def save_opts(self):
        try:
            o = {k: bool(v.get()) for k, v in self.opt_vars.items()}
            o["enabled"] = bool(self.var_online.get())
            self.cfg["online"] = o
            self.persist()
        except Exception:
            log_exc()

    def refresh_key_state(self):
        try:
            keys = self.keys()
            for k in ("vt", "gsb", "urlhaus"):
                cb = self.cbs.get(k)
                if cb is None:
                    continue
                cb.state(["!disabled"] if keys.get(k) else ["disabled"])
        except Exception:
            log_exc()

    def paste_link(self):
        try:
            txt = self.root.clipboard_get().strip()
        except tk.TclError:
            messagebox.showwarning("Clipboard", "Couldn't read text from the clipboard.")
            return
        if txt:
            self.link_entry.delete(0, tk.END)
            self.link_entry.insert(0, txt)

    def current_opts(self):
        try:
            if not self.var_online.get():
                return set()
            keys = self.keys()
            out = {k for k in ("dns", "age", "tls", "trace", "feeds")
                   if self.opt_vars[k].get()}
            out |= {k for k in ("vt", "gsb", "urlhaus")
                    if self.opt_vars[k].get() and keys.get(k)}
            return out
        except Exception:
            return set()

    def start_link_scan(self):
        try:
            url = self.link_entry.get().strip()
        except Exception:
            url = ""
        if url in ("", "https://", "http://"):
            messagebox.showwarning("Link Scanner",
                                   "Please type or paste a website link first.")
            return
        try:
            self.show_page("link")
            self.scan_seq += 1
            seq = self.scan_seq
            r = scan_url(url)
            augment_with_lists(r, self.engine)
            self.last_result = r
            self.render(self.link_ctx, r)
            opts = self.current_opts()
            if r.error or not r.host or not opts:
                self.set_busy(self.link_ctx, False)
                self._record("Link", r.host or url, r)
                self._auto_block(self.link_ctx, r)
                self._maybe_warn_ads(seq)
                return
            self.set_busy(self.link_ctx, True, "Running online checks…")
            keys, submit = self.keys(), bool(self.cfg.get("vt_submit"))

            def worker():
                def emit(p, reason, src):
                    self.ui_q.put(lambda p=p, reason=reason, src=src:
                                  self._link_event(seq, p, reason, src))

                def status(t):
                    self.ui_q.put(lambda t=t: self._link_status(seq, t))
                try:
                    run_online_checks(r, opts, keys, emit, status,
                                      lambda: seq != self.scan_seq, submit)
                except Exception:
                    log_exc()
                finally:
                    self.ui_q.put(lambda: self._link_done(seq))

            threading.Thread(target=worker, daemon=True).start()
        except Exception:
            log_exc()

    def _link_event(self, seq, pts, reason, src):
        try:
            if seq != self.scan_seq or self.last_result is None:
                return
            self.last_result.add(pts, reason, src)
            if src == "Redirects" and " final destination host is " in reason:
                self.last_result.final_url = reason.rsplit(" final destination host is ", 1)[1].rstrip(".")
            self.render(self.link_ctx, self.last_result)
        except Exception:
            log_exc()

    def _link_status(self, seq, text):
        try:
            if seq == self.scan_seq:
                self.link_ctx["busy"].config(text=text)
        except Exception:
            log_swallowed("IronCladOSApp._link_status")

    def _link_done(self, seq):
        try:
            if seq != self.scan_seq:
                return
            self.set_busy(self.link_ctx, False, "Online checks finished.")
            if self.last_result is not None:
                self._auto_block(self.link_ctx, self.last_result)
                self._record("Link", self.last_result.host or self.last_result.url,
                             self.last_result)
            self._maybe_warn_ads(seq)
        except Exception:
            log_exc()

    def _maybe_warn_ads(self, seq):
        try:
            if seq != self.scan_seq or self.last_result is None:
                return
            r = self.last_result
            if not r.has_unwanted_ads:
                return
            if getattr(self, "_ads_warned_for", None) == r.host:
                return
            self._ads_warned_for = r.host

            top = sorted((f for f in r.findings if f[0] > 0),
                         key=lambda f: -f[0])[:3]
            detail = "\n".join(f"  • [{p:+d}] {t}" for p, t in top) or \
                     "  • Domain matches a known ad/tracker network."

            win = tk.Toplevel(self.root)
            win.title("Unwanted ads detected")
            win.configure(bg=BG1)
            win.transient(self.root)
            win.resizable(False, False)

            header = tk.Frame(win, bg=ORANGE, height=64)
            header.pack(fill="x")
            header.pack_propagate(False)
            tk.Label(header, text="⚠", bg=ORANGE, fg="#1b2029",
                     font=(UI_FONT, 22, "bold")).pack(side="left",
                                                      padx=(20, 10))
            tk.Label(header, text="This website has unwanted ads",
                     bg=ORANGE, fg="#1b2029",
                     font=(UI_FONT, 13, "bold")).pack(side="left")

            body = tk.Frame(win, bg=BG1)
            body.pack(fill="both", expand=True, padx=22, pady=18)

            self.lbl(body, f"Host: {r.host}", 10, True, bg=BG1).pack(anchor="w")
            self.lbl(body,
                     "The link scanner matched this site against known "
                     "ad / tracker / pop-under networks.",
                     9, fg=MUTED, bg=BG1, wraplength=440,
                     justify="left").pack(anchor="w", pady=(4, 12))

            box = tk.Text(body, height=6, bg=BG3, fg=TEXT, relief="flat",
                          highlightthickness=1, highlightbackground=BORDER,
                          font=(UI_FONT, 9), wrap="word")
            box.pack(fill="x")
            box.insert("1.0", detail)
            box.configure(state="disabled")

            self.lbl(body,
                     "Turn on the Ad Blocker tab and set it as your system "
                     "proxy to strip these ads before they load.",
                     9, fg=ACCENT_LIGHT, bg=BG1,
                     wraplength=440, justify="left").pack(anchor="w",
                                                          pady=(12, 0))

            btns = tk.Frame(body, bg=BG1)
            btns.pack(fill="x", pady=(16, 0))
            FlatButton(btns, "Open Ad Blocker",
                       lambda: (win.destroy(), self.show_page("adblock")),
                       "accent").pack(side="left")
            FlatButton(btns, "Dismiss", win.destroy,
                       "secondary").pack(side="left", padx=(8, 0))

            win.update_idletasks()
            w, h = 520, win.winfo_reqheight()
            x = self.root.winfo_rootx() + (self.root.winfo_width() - w) // 2
            y = self.root.winfo_rooty() + 120
            win.geometry(f"{w}x{h}+{x}+{y}")
            win.attributes("-topmost", True)
            win.after(300, lambda: win.attributes("-topmost", False))
        except Exception:
            log_exc()

    def _record(self, kind, target, r):
        try:
            self.history.insert(0, (time.strftime("%H:%M"), kind, (target or "")[:60],
                                    f"{SHORT_VERDICT[r.level]} ({r.score})"))
            del self.history[40:]
            self.hist_tree.delete(*self.hist_tree.get_children())
            for h in self.history:
                self.hist_tree.insert("", "end", values=h)
        except Exception:
            log_exc()

    def reset_link(self):
        try:
            self.scan_seq += 1
            self._ads_warned_for = None
            self.link_entry.delete(0, tk.END)
            self.link_entry.insert(0, "https://example.com")
            self.last_result = None
            ctx = self.link_ctx
            ctx["gauge"].set(0, MUTED, "Ready", "—")
            ctx["verdict"].config(text="Paste a link and press Scan", fg=TEXT)
            ctx["sub"].config(text="")
            ctx["extra"].config(text="")
            ctx["tree"].delete(*ctx["tree"].get_children())
            self.set_busy(ctx, False)
        except Exception:
            log_exc()

    def _report_dict(self, r):
        return {"target": r.url, "scanned": time.strftime("%Y-%m-%d %H:%M:%S"),
                "verdict": r.verdict, "score": r.score, "host": r.host,
                "registered_domain": r.registered_domain,
                "final_url": r.final_url, "sha256": r.sha256,
                "findings": [{"points": p, "source": r.sources.get(t, "Local"),
                              "finding": t}
                             for p, t in sorted(r.findings, key=lambda f: -f[0])]}

    def copy_report(self):
        r = self.last_result
        if r:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(r.report())
            except Exception:
                log_swallowed("IronCladOSApp.copy_report")

    def export_report(self):
        r = self.last_result
        if not r:
            return
        try:
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json"), ("Text", "*.txt")])
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    if path.lower().endswith(".txt"):
                        f.write(r.report())
                    else:
                        json.dump(self._report_dict(r), f, indent=2)
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _page_file(self):
        pg = self.pages["file"]
        o, b = self.card(pg)
        o.pack(fill="x")
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x")
        FlatButton(row, "Choose file…", self.start_file_scan).pack(side="left")
        self.file_path_lbl = self.lbl(row, "No file selected", 10, fg=MUTED, bg=BG2)
        self.file_path_lbl.pack(side="left", padx=(14, 0))
        self.var_file_vt = tk.BooleanVar(value=True)
        ttk.Checkbutton(b,
                        text="Look up the file's SHA-256 on VirusTotal "
                             "(hash only — the file is never uploaded)",
                        variable=self.var_file_vt).pack(anchor="w", pady=(12, 0))

        o, b = self.card(pg)
        o.pack(fill="x", pady=(14, 0))
        self.file_ctx = self._result_panel(b, "file")
        o, b = self.card(pg, "Findings")
        o.pack(fill="both", expand=True, pady=(14, 0))
        wrap, tree = self.make_tree(
            b,
            (("sev", "Severity", 80, False), ("pts", "Pts", 50, False),
             ("src", "Source", 110, False), ("msg", "Finding", 560, True)),
            7)
        wrap.pack(fill="both", expand=True)
        self.file_ctx["tree"] = tree
        btns = tk.Frame(b, bg=BG2)
        btns.pack(fill="x", pady=(10, 0))
        FlatButton(btns, "Copy SHA-256",
                   lambda: self._copy(self.last_file.sha256 if self.last_file else ""),
                   "secondary").pack(side="left")

    def _copy(self, text):
        if text:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
            except Exception:
                log_swallowed("IronCladOSApp._copy")

    def start_file_scan(self):
        try:
            path = filedialog.askopenfilename(title="Choose a file to scan")
        except Exception:
            return
        if not path:
            return
        try:
            self.show_page("file")
            self.file_seq += 1
            seq = self.file_seq
            self.file_path_lbl.config(text=path)
            self.file_ctx["gauge"].set(0, MUTED, "Scanning…", "…")
            self.set_busy(self.file_ctx, True, "Hashing and analysing…")
            keys, use_vt = self.keys(), bool(self.var_file_vt.get())

            def worker():
                r = analyze_file(path)
                self.ui_q.put(lambda r=r: self._file_local(seq, r))
                if r.sha256 and use_vt and keys.get("vt"):
                    try:
                        for pts, reason in check_vt_file(r.sha256, keys["vt"]):
                            self.ui_q.put(lambda p=pts, t=reason:
                                          self._file_event(seq, p, t))
                    except Exception as e:
                        self.ui_q.put(lambda e=e:
                                      self._file_event(seq, 0,
                                                       f"VirusTotal lookup unavailable ({type(e).__name__})."))
                self.ui_q.put(lambda: self._file_done(seq))

            threading.Thread(target=worker, daemon=True).start()
        except Exception:
            log_exc()

    def _file_local(self, seq, r):
        try:
            if seq == self.file_seq:
                self.last_file = r
                self.render(self.file_ctx, r)
        except Exception:
            log_exc()

    def _file_event(self, seq, pts, reason):
        try:
            if seq == self.file_seq and self.last_file:
                self.last_file.add(pts, reason, "VirusTotal")
                self.render(self.file_ctx, self.last_file)
        except Exception:
            log_exc()

    def _file_done(self, seq):
        try:
            if seq == self.file_seq:
                self.set_busy(self.file_ctx, False, "")
                if self.last_file:
                    self._record("File", os.path.basename(self.last_file.url),
                                 self.last_file)
        except Exception:
            log_exc()










    # ------------------------------------------------------------------ protection links
    def _protection_strip(self, parent):
        """Status + Start/Stop button shown at the top of the scanner pages."""
        o, b = self.card(parent)
        o.pack(fill="x", pady=(0, 14))
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x")
        lbl = self.lbl(row, "● Protection off", 10, True, fg=MUTED, bg=BG2)
        lbl.pack(side="left")
        self.lbl(row, "   Dangerous results are blocked automatically while protection is on.",
                 9, fg=MUTED, bg=BG2).pack(side="left")
        btn = FlatButton(row, "Start protection", self.toggle_protection)
        btn.pack(side="right")
        self._prot_strips.append((lbl, btn))

    def block_domain(self, host, why="manual"):
        """Add a host to the persistent 'blocked by scans' list. Returns (ok, info)."""
        h = (host or "").strip().lower().rstrip(".")
        if h.startswith("www."):
            h = h[4:]
        if not DOMAIN_RE.match(h):
            return False, "That isn't a blockable domain name."
        with self.engine.lock:
            if h in self.engine.allow:
                return False, f"{h} is on your allowlist, so it was not blocked."
        ub = self.cfg.setdefault("user_blocked", [])
        if h not in ub:
            ub.append(h)
            del ub[:-5000]
        self.engine.set_list("user:blocked", set(ub), "security")
        self.persist()
        return True, h

    def auto_block_result(self, r, source="scan"):
        """If protection is ON and the scan says DANGEROUS, block the host. Returns a message or ''."""
        try:
            if not self.cfg.get("auto_block_scans", True):
                return ""
            if not (self.proxy and self.proxy.running):
                return ""
            if r.error or not r.host or r.level != "danger":
                return ""
            if r.host in self.cfg.get("user_blocked", []):
                return ""
            ok, info = self.block_domain(r.host, source)
            if ok:
                return f"Protection is ON: {info} was blocked automatically."
        except Exception:
            log_exc()
        return ""

    def _auto_block(self, ctx, r):
        msg = self.auto_block_result(r, "scan")
        if msg:
            try:
                ctx["busy"].config(text=msg)
                self.refresh_blocked_count()
            except Exception:
                log_swallowed("IronCladOSApp._auto_block")

    def _manual_block(self, r):
        if r is None or not r.host:
            messagebox.showinfo("Block domain", "Scan a link or QR code first.")
            return
        ok, info = self.block_domain(r.host, "manual")
        if ok:
            messagebox.showinfo("Block domain",
                                f"{info} is now blocked while protection is on (and shared with the browser extension).\n"
                                "To undo, add it to the allowlist on the Ad Blocker tab.")
            self.refresh_blocked_count()
        else:
            messagebox.showwarning("Block domain", info)


    def link_block_domain(self):
        self._manual_block(self.last_result)

    def on_auto_block_toggle(self):
        self.cfg["auto_block_scans"] = bool(self.var_autoblock.get())
        self.persist()

    def clear_user_blocked(self):
        if messagebox.askyesno("Blocked by scans", "Remove every domain that was blocked from scan results?"):
            self.cfg["user_blocked"] = []
            self.engine.remove_list("user:blocked")
            self.persist()
            self.refresh_blocked_count()

    def refresh_blocked_count(self):
        try:
            n = len(self.cfg.get("user_blocked", []))
            self.lbl_user_blocked.config(text=f"{n} domain(s) currently blocked from scan results")
        except Exception:
            log_swallowed("IronCladOSApp.refresh_blocked_count")

    def _page_adblock(self):
        pg = self.pages["adblock"]
        left = tk.Frame(pg, bg=BG0)
        left.pack(side="left", fill="both", expand=True, padx=(0, 7))
        right = tk.Frame(pg, bg=BG0)
        right.pack(side="left", fill="both", expand=True, padx=(7, 0))

        o, b = self.card(left, "Protection",
                         "Runs a filter on 127.0.0.1. Browsers and apps that use it "
                         "never load blocked domains.")
        o.pack(fill="x")
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x")
        self.ad_status = self.lbl(row, "● Off", 12, True, fg=MUTED, bg=BG2)
        self.ad_status.pack(side="left")
        self.ad_btn = FlatButton(row, "Start protection", self.toggle_protection)
        self.ad_btn.pack(side="right")
        prow = tk.Frame(b, bg=BG2)
        prow.pack(fill="x", pady=(12, 0))
        self.lbl(prow, "Port", 10, bg=BG2).pack(side="left")
        self.port_var = tk.StringVar(value=str(self.cfg.get("port", 8899)))
        e = self.entry(prow, self.port_var)
        e.config(width=7)
        e.pack(side="left", padx=(8, 0), ipady=3)
        self.var_sys = tk.BooleanVar(value=bool(self.cfg.get("sysproxy", False)))
        if SystemProxy.supported():
            ttk.Checkbutton(b,
                            text="Set as Windows system proxy while running "
                                 "(restored automatically)",
                            variable=self.var_sys,
                            command=self.on_sys_toggle).pack(anchor="w", pady=(10, 0))
        else:
            FlatButton(b, "How to connect your browser",
                       self.show_help, "secondary").pack(anchor="w", pady=(10, 0))
        self.var_scan_block = tk.BooleanVar(value=self.engine.scan_block)
        ttk.Checkbutton(b,
                        text="Also block sites the link scanner rates Dangerous "
                             "(score ≥ 70)",
                        variable=self.var_scan_block,
                        command=self.on_scan_block).pack(anchor="w", pady=(8, 0))
        self.ad_stats = self.lbl(b, "", 9, fg=MUTED, bg=BG2)
        self.ad_stats.pack(fill="x", pady=(12, 0))

        o, b = self.card(left, "Allowlist", "Domains that are never blocked.")
        o.pack(fill="both", expand=True, pady=(14, 0))
        self.allow_list = tk.Listbox(b, height=4, bg=BG3, fg=TEXT, relief="flat",
                                     highlightthickness=1, highlightbackground=BORDER,
                                     selectbackground=SELECT_BG, font=self.font(10))
        self.allow_list.pack(fill="both", expand=True)
        arow = tk.Frame(b, bg=BG2)
        arow.pack(fill="x", pady=(10, 0))
        FlatButton(arow, "Add…", self.add_allow, "secondary").pack(side="left")
        FlatButton(arow, "Remove", self.remove_allow, "secondary").pack(side="left", padx=(8, 0))
        FlatButton(arow, "Export hosts file…", self.export_hosts, "ghost").pack(side="right")
        self.refresh_allow()

        o, b = self.card(right, "Blocklists", "Double-click a list to turn it on or off.")
        o.pack(fill="x")
        wrap, self.lists_tree = self.make_tree(
            b,
            (("on", "State", 56, False), ("name", "List", 220, True),
             ("n", "Domains", 80, False), ("upd", "Updated", 120, False)),
            5)
        wrap.pack(fill="x")
        self.lists_tree.bind("<Double-1>", self.toggle_list)
        lrow = tk.Frame(b, bg=BG2)
        lrow.pack(fill="x", pady=(10, 0))
        FlatButton(lrow, "Update now", self.update_lists_now).pack(side="left")
        FlatButton(lrow, "Add URL…", self.add_list_url, "secondary").pack(side="left", padx=(8, 0))
        FlatButton(lrow, "Add file…", self.add_list_file, "secondary").pack(side="left", padx=(8, 0))
        self.lists_status = self.lbl(b, "", 9, fg=ACCENT, bg=BG2)
        self.lists_status.pack(fill="x", pady=(8, 0))

        o, b = self.card(right, "Recently blocked")
        o.pack(fill="both", expand=True, pady=(14, 0))
        wrap, self.block_tree = self.make_tree(
            b,
            (("t", "Time", 70, False), ("host", "Domain", 230, True),
             ("why", "Reason", 110, False)),
            6)
        wrap.pack(fill="both", expand=True)

    def on_scan_block(self):
        try:
            self.engine.scan_block = bool(self.var_scan_block.get())
            self.persist()
        except Exception:
            log_swallowed("IronCladOSApp.on_scan_block")

    def on_sys_toggle(self):
        try:
            self.cfg["sysproxy"] = bool(self.var_sys.get())
            self.persist()
            if self.proxy and self.proxy.running and SystemProxy.supported():
                if self.var_sys.get():
                    self.sysproxy.enable("127.0.0.1", self.proxy.port)
                else:
                    self.sysproxy.restore()
        except Exception as e:
            messagebox.showerror("System proxy", str(e))

    def set_protection(self, on):
        """Start/stop the filtering proxy without dialogs. Returns (ok, error).
        Must run on the Tk thread (the bridge schedules it through ui_q)."""
        try:
            running = bool(self.proxy and self.proxy.running)
            if on and not running:
                try:
                    port = int(self.cfg.get("port", 8899))
                    if not 1024 <= port <= 65535:
                        raise ValueError
                except (TypeError, ValueError):
                    port = 8899
                p = FilteringProxy(self.engine, port=port,
                                   yt_skip=bool(self.cfg.get("yt_skip", True)))
                try:
                    p.start()
                except OSError as e:
                    return False, f"Port {port} is unavailable: {e.strerror or e}"
                self.proxy = p
                self.cfg["port"] = port
                self.persist()
                if SystemProxy.supported() and self.cfg.get("sysproxy"):
                    try:
                        self.sysproxy.enable("127.0.0.1", port)
                    except Exception as e:
                        return True, f"Protection started, but the Windows proxy could not be set: {e}"
            elif not on and running:
                self.proxy.stop()
                self.proxy = None
                if SystemProxy.supported():
                    try:
                        self.sysproxy.restore()
                    except Exception:
                        log_swallowed("IronCladOSApp.set_protection")
            self.refresh_status()
            return True, ""
        except Exception as e:
            log_exc()
            return False, str(e)

    def toggle_protection(self):
        try:
            if self.proxy and self.proxy.running:
                self.proxy.stop()
                self.proxy = None
                if SystemProxy.supported():
                    try:
                        self.sysproxy.restore()
                    except Exception:
                        log_swallowed("IronCladOSApp.toggle_protection")
            else:
                try:
                    port = int(self.port_var.get())
                    if not 1024 <= port <= 65535:
                        raise ValueError
                except (ValueError, tk.TclError):
                    messagebox.showwarning("Port", "Enter a port between 1024 and 65535.")
                    return
                p = FilteringProxy(self.engine, port=port,
                                   yt_skip=bool(self.cfg.get("yt_skip", True)))
                try:
                    p.start()
                except OSError as e:
                    messagebox.showerror("Could not start",
                                         f"Port {port} is unavailable:\n{e}")
                    return
                self.proxy = p
                self.cfg["port"] = port
                self.persist()
                if SystemProxy.supported() and self.var_sys.get():
                    try:
                        self.sysproxy.enable("127.0.0.1", port)
                    except Exception as e:
                        messagebox.showerror("System proxy",
                                             f"Could not set the Windows proxy:\n{e}")
            try:
                self.bridge._domains_cache = None
            except Exception:
                log_swallowed("IronCladOSApp.toggle_protection")
            self.refresh_status()
        except Exception:
            log_exc()

    def show_help(self):
        try:
            messagebox.showinfo("How to connect",
                f"1. Press 'Start protection'.\n"
                f"2. Set your browser/OS HTTP and HTTPS proxy to "
                f"127.0.0.1 port {self.port_var.get()}.\n\n"
                "Blocked requests fail instantly so ads and trackers never load.\n\n"
                "Limits: HTTPS is filtered by domain only (traffic is never "
                "decrypted), so ads served from the same domain as the content — "
                "e.g. YouTube video ads — cannot be removed this way.")
        except Exception:
            log_swallowed("IronCladOSApp.show_help")

    def refresh_allow(self):
        try:
            self.allow_list.delete(0, tk.END)
            with self.engine.lock:
                allowed = sorted(self.engine.allow)
            for d in allowed:
                self.allow_list.insert(tk.END, d)
        except Exception:
            log_swallowed("IronCladOSApp.refresh_allow")

    def add_allow(self):
        try:
            d = simpledialog.askstring("Allow a site",
                                       "Domain to never block (e.g. example.com):")
            if d and d.strip():
                with self.engine.lock:
                    self.engine.allow.add(d.strip().lower().lstrip("*."))
                self.persist()
                self.refresh_allow()
        except Exception:
            log_swallowed("IronCladOSApp.add_allow")

    def remove_allow(self):
        try:
            sel = self.allow_list.curselection()
            if sel:
                with self.engine.lock:
                    self.engine.allow.discard(self.allow_list.get(sel[0]))
                self.persist()
                self.refresh_allow()
        except Exception:
            log_swallowed("IronCladOSApp.remove_allow")

    def export_hosts(self):
        try:
            path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                initialfile="ironclad_hosts.txt")
            if path:
                n = self.engine.export_hosts(path)
                messagebox.showinfo("Exported",
                                    f"Wrote {n:,} entries.\n"
                                    "Merge them into your system hosts file "
                                    "(needs administrator rights).")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def refresh_lists_tree(self):
        try:
            self.lists_tree.delete(*self.lists_tree.get_children())
            for item in self.lists.catalog():
                st = self.cfg["lists"].get(item["id"],
                                           {"enabled": False, "updated": 0})
                n = self.engine.list_count(item["id"])
                upd = (time.strftime("%Y-%m-%d %H:%M",
                                     time.localtime(st["updated"]))
                       if st.get("updated") else "never")
                self.lists_tree.insert("", "end", iid=item["id"],
                                       values=("On" if st.get("enabled") else "Off",
                                               item["name"],
                                               f"{n:,}" if n is not None else "—",
                                               upd))
            for f in self.engine.sources:
                self.lists_tree.insert("", "end", iid="file:" + f,
                                       values=("On", os.path.basename(f),
                                               f"{self.engine.list_count('file:' + f):,}",
                                               "local file"))
        except Exception:
            log_exc()

    def toggle_list(self, event):
        try:
            lid = self.lists_tree.focus()
            if not lid or lid.startswith("file:"):
                return
            st = self.cfg["lists"].setdefault(lid,
                                              {"enabled": False, "updated": 0,
                                               "count": 0})
            on = not st.get("enabled", False)
            self.lists.set_enabled(lid, on)
            if on:
                if os.path.exists(self.lists.path(lid)):
                    self.lists.load_cached()
                else:
                    self.run_updates([lid])
            self.refresh_lists_tree()
        except Exception:
            log_exc()

    def run_updates(self, ids):
        if not ids:
            return

        def worker():
            for lid in ids:
                try:
                    item = self.lists.item(lid)
                    name = item["name"] if item else lid
                    self.ui_q.put(lambda n=name:
                                  self.lists_status.config(text=f"Downloading {n}…",
                                                           fg=ACCENT))
                    try:
                        count = self.lists.update(lid)
                        self.ui_q.put(lambda n=name, c=count:
                                      self.lists_status.config(
                                          text=f"{n}: {c:,} domains", fg=GREEN))
                    except Exception as e:
                        self.ui_q.put(lambda n=name, e=e:
                                      self.lists_status.config(
                                          text=(f"{n}: {e}" if isinstance(e, ValueError) else
                                                f"{n}: update failed "
                                                f"({type(e).__name__}) — are you online?"),
                                          fg=DANGER))
                    self.ui_q.put(self.refresh_lists_tree)
                except Exception:
                    log_exc()

        threading.Thread(target=worker, daemon=True).start()

    def update_lists_now(self):
        try:
            ids = [i["id"] for i in self.lists.catalog()
                   if self.cfg["lists"].get(i["id"], {}).get("enabled")]
            self.run_updates(ids)
        except Exception:
            log_exc()

    def auto_update_lists(self):
        try:
            self.run_updates(self.lists.stale())
        except Exception:
            log_exc()

    def add_list_url(self):
        try:
            url = simpledialog.askstring(
                "Add blocklist",
                "URL of a hosts / domain / Adblock-style list (https://…):")
            if not url or not url.lower().startswith(("http://", "https://")):
                return
            name = simpledialog.askstring("Add blocklist",
                                          "Name for this list:") or url[:40]
            lid = "custom_" + hashlib.sha1(url.encode()).hexdigest()[:8]
            if not any(c["id"] == lid for c in self.cfg.get("custom_lists", [])):
                self.cfg.setdefault("custom_lists", []).append(
                    {"id": lid, "name": name, "url": url, "category": "ads"})
            self.lists.catalog()
            self.persist()
            self.refresh_lists_tree()
            self.run_updates([lid])
        except Exception:
            log_exc()

    def add_list_file(self):
        try:
            path = filedialog.askopenfilename(
                title="Choose a blocklist (hosts / domains / ABP rules)")
            if not path:
                return
            n = self.engine.load_file(path)
            self.persist()
            self.refresh_lists_tree()
            messagebox.showinfo("Blocklist loaded", f"Added {n:,} domains.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _page_password(self):
        pg = self.pages["password"]
        wrap = tk.Frame(pg, bg=BG0)
        wrap.pack(fill="both", expand=True)
        outer, body = self.card(
            wrap, "CREDENTIAL DEFENSE MATRIX",
            "LIVE LOCAL ANALYSIS  •  No password is saved or transmitted.")
        outer.pack(fill="x", pady=(0, 14))

        self.lbl(body, "Create a strong password", 16, True, bg=BG2).pack(anchor="w")
        self.lbl(body,
                 "Use a long, unique passphrase. Avoid names, dates, and passwords "
                 "you use elsewhere.",
                 9, fg=MUTED, bg=BG2, wraplength=690, justify="left").pack(
            anchor="w", pady=(4, 14))

        entry_row = tk.Frame(body, bg=BG2)
        entry_row.pack(fill="x")
        self.password_var = tk.StringVar()
        self.password_entry = self.entry(entry_row, self.password_var, show="•")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=8)
        self.password_show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(entry_row, text="Show password",
                       variable=self.password_show_var,
                       command=self._toggle_password_visibility,
                       bg=BG2, fg=TEXT, activebackground=BG2,
                       activeforeground=TEXT, selectcolor=BG3,
                       font=self.font(9)).pack(side="left", padx=(12, 0))
        self.password_entry.bind("<KeyRelease>", lambda _e: self._evaluate_password())

        meter_head = tk.Frame(body, bg=BG2)
        meter_head.pack(fill="x", pady=(18, 6))
        self.password_strength_label = self.lbl(meter_head,
                                                "THREAT RATING: STANDBY",
                                                11, True, fg=MUTED, bg=BG2)
        self.password_strength_label.pack(side="left")
        self.password_score_label = self.lbl(meter_head, "0 / 100", 9,
                                             fg=MUTED, bg=BG2)
        self.password_score_label.pack(side="right")
        self.password_progress = ttk.Progressbar(body, mode="determinate",
                                                 maximum=100, value=0,
                                                 style="Horizontal.TProgressbar")
        self.password_progress.pack(fill="x", ipady=3)

        self.password_feedback = self.lbl(
            body,
            "Awaiting credential input… analysis engine on standby.",
            10, fg=MUTED, bg=BG2, wraplength=700, justify="left")
        self.password_feedback.pack(anchor="w", pady=(12, 6))
        self.password_checks = self.lbl(body, "", 9, fg=MUTED, bg=BG2,
                                        justify="left", wraplength=700)
        self.password_checks.pack(anchor="w", pady=(0, 10))

        buttons = tk.Frame(body, bg=BG2)
        buttons.pack(fill="x", pady=(8, 0))
        FlatButton(buttons, "Clear", self._clear_password_demo,
                   style="secondary").pack(side="left")
        FlatButton(buttons, "Generate strong password", self._generate_strong_password,
                   style="secondary").pack(side="left", padx=(8, 0))
        self.password_continue_btn = FlatButton(buttons, "Continue",
                                                self._password_demo_continue)
        self.password_continue_btn.pack(side="right")
        self.password_continue_btn.set_enabled(False)

        note_outer, note = self.card(
            wrap, "What this demo does",
            "A simple local heuristic, not a guarantee of account security.")
        note_outer.pack(fill="x")
        for line in (
            "• Rewards longer passwords and a mix of character types.",
            "• Warns about common/example passwords and repeated or predictable patterns.",
            "• Continue stays disabled until the password meets the demo's minimum rules.",
            "• The password is not written to a file, logged, or transmitted over the network.",
            "• Generate strong passwords locally with the secure-random generator button.",
        ):
            self.lbl(note, line, 9, fg=MUTED, bg=BG2, wraplength=700,
                     justify="left").pack(anchor="w", pady=3)

    def _generate_strong_password(self):
        """Generate a random high-entropy password locally; never save or transmit it."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        # Guarantee a mix of character types, then cryptographically shuffle.
        chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()-_=+"),
        ]
        chars.extend(secrets.choice(alphabet) for _ in range(20))
        secrets.SystemRandom().shuffle(chars)
        generated = "".join(chars)

        self.password_var.set(generated)
        # Show the generated value so the user can copy it into a password manager.
        self.password_show_var.set(True)
        self._toggle_password_visibility()
        self._evaluate_password()
        try:
            self.password_feedback.config(
                text="Generated locally using Python's secure random source. Save it in a password manager; it is not stored by IronCladOS."
            )
        except Exception:
            log_swallowed("IronCladOSApp._generate_strong_password")

    def _toggle_password_visibility(self):
        try:
            self.password_entry.config(show="" if self.password_show_var.get() else "•")
        except Exception:
            log_swallowed("IronCladOSApp._toggle_password_visibility")

    @staticmethod
    def _password_strength(password):
        common = {
            "password", "password123", "12345678", "123456789", "qwerty123",
            "qwertyuiop", "letmein", "welcome123", "admin123", "iloveyou",
            "changeme", "abc12345",
        }
        p = password
        if not p:
            return 0, "Not checked", ["Enter a password to check it."], False
        lower = p.lower()
        tips = []
        score = 0
        if len(p) >= 16:
            score += 35
        elif len(p) >= 12:
            score += 27
        elif len(p) >= 8:
            score += 15
        else:
            tips.append("Use at least 12 characters; 16 or more is better.")
        if any(c.islower() for c in p):
            score += 10
        else:
            tips.append("Add lowercase letters.")
        if any(c.isupper() for c in p):
            score += 10
        else:
            tips.append("Add uppercase letters, or use a longer passphrase.")
        if any(c.isdigit() for c in p):
            score += 10
        else:
            tips.append("Consider adding a number.")
        if any(not c.isalnum() for c in p):
            score += 10
        else:
            tips.append("Consider a symbol, or make the passphrase longer.")
        unique_ratio = len(set(p)) / max(1, len(p))
        if unique_ratio >= 0.65:
            score += 10
        else:
            tips.append("Avoid repeating the same characters many times.")
        if not (lower in common or lower in {x + "1" for x in common}):
            score += 15
        else:
            score = min(score, 20)
            tips.insert(0, "This resembles a commonly used password. "
                           "Choose something completely different.")
        if len(p) < 12:
            score = min(score, 59)
        if len(set(p)) <= 2 and len(p) >= 6:
            score = min(score, 25)
            tips.insert(0, "Too many repeated characters. Use a unique passphrase.")
        score = max(0, min(100, score))
        if score < 35:
            label = "CRITICAL"
        elif score < 55:
            label = "EXPOSED"
        elif score < 75:
            label = "GUARDED"
        else:
            label = "FORTIFIED"
        if not tips:
            tips.append("SCAN COMPLETE: no basic weaknesses detected. "
                        "Keep it unique and never reuse it.")
        eligible = score >= 70 and len(p) >= 12 and not (lower in common)
        return score, label, tips, eligible

    def _evaluate_password(self):
        try:
            p = self.password_var.get()
            score, label, tips, eligible = self._password_strength(p)
            colors = {"CRITICAL": DANGER, "EXPOSED": ORANGE, "GUARDED": YELLOW,
                      "FORTIFIED": GREEN, "Not checked": MUTED}
            self.password_strength_label.config(text="THREAT RATING: " + label,
                                                fg=colors.get(label, MUTED))
            self.password_score_label.config(text=f"{score} / 100")
            self.password_progress.configure(value=score)
            try:
                ttk.Style().configure("Horizontal.TProgressbar",
                                      background=colors.get(label, ACCENT))
            except Exception:
                log_swallowed("IronCladOSApp._evaluate_password")
            self.password_feedback.config(
                text=("This password meets the demo's minimum rules." if eligible
                      else "This password is not strong enough to continue." if p
                      else "Awaiting credential input… analysis engine on standby."),
                fg=GREEN if eligible else (DANGER if p else MUTED))
            self.password_checks.config(text="\n".join("• " + tip
                                                       for tip in tips[:5]))
            self.password_continue_btn.set_enabled(eligible)
        except Exception:
            log_exc()

    def _clear_password_demo(self):
        self.password_var.set("")
        self.password_entry.config(show="•")
        self.password_show_var.set(False)
        self._evaluate_password()
        self.password_entry.focus_set()

    def _password_demo_continue(self):
        p = self.password_var.get()
        score, label, tips, eligible = self._password_strength(p)
        if not eligible:
            messagebox.showwarning(
                "Choose a stronger password",
                "This password is not strong enough yet.\n\n" +
                "\n".join("• " + t for t in tips[:4]),
                parent=self.root)
            return
        self.password_var.set("")
        self._evaluate_password()
        messagebox.showinfo(
            "Demo complete",
            "Password strength checks passed.\n\n"
            "This is a demonstration only; no account was created and the "
            "password was not saved.",
            parent=self.root)

    def _page_settings(self):
        pg = self.pages["settings"]
        o, b = self.card(
            pg, "Threat-intelligence API keys",
            "Optional. Keys are stored only on this computer (in your home "
            "folder) and are sent only to the matching service.")
        o.pack(fill="x")
        self.key_vars = {}
        k = self.cfg.get("keys", {}) or {}
        for key, label, hint in (
            ("vt", "VirusTotal", "free key: virustotal.com → profile → API key"),
            ("gsb", "Google Safe Browsing",
             "Google Cloud console → enable Safe Browsing API → create key"),
            ("urlhaus", "URLhaus (abuse.ch)", "free Auth-Key from auth.abuse.ch"),
        ):
            row = tk.Frame(b, bg=BG2)
            row.pack(fill="x", pady=5)
            self.lbl(row, label, 10, True, bg=BG2, width=22).pack(side="left")
            self.key_vars[key] = tk.StringVar(value=k.get(key, "") or "")
            self.entry(row, self.key_vars[key], show="•").pack(
                side="left", fill="x", expand=True, ipady=5)
            self.lbl(row, hint, 8, fg=MUTED, bg=BG2).pack(side="left", padx=(10, 0))

        o, b = self.card(pg, "Behaviour")
        o.pack(fill="x", pady=(14, 0))
        self.var_auto = tk.BooleanVar(value=bool(self.cfg.get("auto_update", True)))
        self.var_vt_submit = tk.BooleanVar(value=bool(self.cfg.get("vt_submit", False)))
        self.var_yt_skip = tk.BooleanVar(value=bool(self.cfg.get("yt_skip", True)))
        ttk.Checkbutton(b,
                        text="Refresh blocklists automatically when the app "
                             "starts (daily)",
                        variable=self.var_auto).pack(anchor="w", pady=3)
        ttk.Checkbutton(b,
                        text="Submit unknown URLs to VirusTotal for analysis "
                             "(shares the URL with the VirusTotal community)",
                        variable=self.var_vt_submit).pack(anchor="w", pady=3)
        ttk.Checkbutton(b,
                        text="Auto-skip YouTube ads through the local proxy "
                             "(patches YouTube HTML; no extension needed)",
                        variable=self.var_yt_skip).pack(anchor="w", pady=3)
        self.var_yt_flash = tk.BooleanVar(value=bool(self.cfg.get("yt_flash", True)))
        ttk.Checkbutton(b,
                        text="Chrome extension: show a black screen for 2 seconds "
                             "when a YouTube ad is blocked",
                        variable=self.var_yt_flash).pack(anchor="w", pady=3)
        FlatButton(b, "Save settings", self.save_settings).pack(anchor="w", pady=(12, 0))

        o, b = self.card(
            pg, "Threat alerts",
            "Show a small notification when IronClad blocks malware or phishing, a dangerous link "
            "(scanner score 70 or higher) or an aggressive ad network. A burst of blocked requests "
            "becomes one alert, and the same site is announced at most once per cooldown.")
        o.pack(fill="x", pady=(14, 0))
        nc = self.notifier.conf()
        self.var_notify = tk.BooleanVar(value=bool(nc["enabled"]))
        self.var_notify_kind = {k: tk.BooleanVar(value=bool(nc.get(k, True))) for k in ALERT_KINDS}
        ttk.Checkbutton(b, text="Show desktop alerts for blocked threats",
                        variable=self.var_notify, command=self.save_notify).pack(anchor="w", pady=3)
        for k, text in (("malware", "Malware / phishing domains"),
                        ("danger", "Dangerous links (scanner score 70 or higher)"),
                        ("aggressive", "Aggressive ad / pop-under networks")):
            ttk.Checkbutton(b, text="      " + text, variable=self.var_notify_kind[k],
                            command=self.save_notify).pack(anchor="w", pady=1)
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x", pady=(10, 0))
        self.lbl(row, "Repeat cooldown per site (seconds)", 10, True, bg=BG2).pack(side="left")
        self.var_notify_cd = tk.StringVar(value=str(int(nc.get("cooldown", 60))))
        cd = self.entry(row, self.var_notify_cd)
        cd.config(width=6)
        cd.pack(side="left", padx=(10, 0), ipady=4)
        cd.bind("<FocusOut>", lambda e: self.save_notify())
        cd.bind("<Return>", lambda e: self.save_notify())
        FlatButton(row, "Send test alert", self.notifier.test,
                   style="secondary").pack(side="left", padx=12)

        o, b = self.card(
            pg, "Scan-linked protection",
            "While Start protection is ON, links and QR codes rated DANGEROUS (Link Scanner, "
            "QR Scanner, or the browser extension) are added to the blocklist automatically. "
            "Allowlisted sites are never blocked.")
        o.pack(fill="x", pady=(14, 0))
        self.var_autoblock = tk.BooleanVar(value=bool(self.cfg.get("auto_block_scans", True)))
        ttk.Checkbutton(b, text="Auto-block dangerous scan results while protection is on",
                        variable=self.var_autoblock,
                        command=self.on_auto_block_toggle).pack(anchor="w", pady=3)
        self.lbl_user_blocked = self.lbl(b, "", 9, fg=MUTED, bg=BG2)
        self.lbl_user_blocked.pack(anchor="w", pady=(6, 0))
        FlatButton(b, "Clear blocked-by-scan list", self.clear_user_blocked,
                   style="secondary").pack(anchor="w", pady=(8, 0))
        self.refresh_blocked_count()

        o, b = self.card(
            pg, "Browser extension (IronClad Ad Blocker for Chrome)",
            "Lets the extension share the allowlist and blocklists with this app "
            "and use its link scanner. Listens only on this computer (127.0.0.1).\n"
            "In Chrome: click the extension icon → Connect to app → approve the "
            "dialog that appears here. After that, Start protection turns blocking "
            "on/off in Chrome as well.")
        o.pack(fill="x", pady=(14, 0))
        self.var_bridge = tk.BooleanVar(value=bool(self.cfg.get("bridge_enabled", True)))
        self.var_bridge_port = tk.StringVar(value=str(self.cfg.get("bridge_port", BRIDGE_DEFAULT_PORT)))
        ttk.Checkbutton(b, text="Enable the local extension bridge",
                        variable=self.var_bridge).pack(anchor="w", pady=3)
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x", pady=5)
        self.lbl(row, "Port", 10, True, bg=BG2, width=22).pack(side="left")
        self.entry(row, self.var_bridge_port).pack(side="left", ipady=5)
        row = tk.Frame(b, bg=BG2)
        row.pack(fill="x", pady=(8, 0))
        FlatButton(row, "Apply", self.apply_bridge).pack(side="left")
        FlatButton(row, "Forget paired browsers", self.forget_paired_browsers,
                   style="secondary").pack(side="left", padx=8)
        self.bridge_status = self.lbl(b, "", 9, fg=MUTED, bg=BG2)
        self.bridge_status.pack(anchor="w", pady=(8, 0))
        self.bridge_paired_lbl = self.lbl(b, "", 9, fg=MUTED, bg=BG2)
        self.bridge_paired_lbl.pack(anchor="w", pady=(4, 0))

        o, b = self.card(pg, "Privacy & limits")
        o.pack(fill="x", pady=(14, 0))
        self.lbl(b,
                 ("• Offline checks never leave your computer.\n"
                  "• Deep scan sends the domain to Google DNS and the domain "
                  "registry (RDAP), connects to the site for its TLS certificate "
                  "and redirect headers, and downloads the public OpenPhish feed.\n"
                  "• File scans never upload files; only the SHA-256 hash is "
                  "looked up, and only if you enable it.\n"
                  "• No scanner can prove a link or file is safe. Treat a clean "
                  "result as 'nothing found', not a guarantee."),
                 9, fg=MUTED, bg=BG2, wraplength=820,
                 justify="left").pack(fill="x")

    def save_notify(self):
        try:
            try:
                cd = max(0, min(3600, int(float((self.var_notify_cd.get() or "60").strip()))))
            except ValueError:
                cd = 60
            self.var_notify_cd.set(str(cd))
            conf = {"enabled": bool(self.var_notify.get()), "cooldown": cd}
            for k, v in self.var_notify_kind.items():
                conf[k] = bool(v.get())
            self.cfg["notify"] = conf
            self.persist()
        except Exception:
            log_exc("save_notify")

    def save_settings(self):
        try:
            self.cfg["keys"] = {k: v.get().strip()
                                for k, v in self.key_vars.items()}
            self.cfg["auto_update"] = bool(self.var_auto.get())
            self.cfg["vt_submit"] = bool(self.var_vt_submit.get())
            self.cfg["yt_skip"] = bool(self.var_yt_skip.get())
            self.cfg["yt_flash"] = bool(self.var_yt_flash.get())
            self.persist()
            self.refresh_key_state()
            messagebox.showinfo("Settings", "Saved.")
        except Exception as e:
            messagebox.showerror("Settings", str(e))

    def refresh_bridge_status(self):
        try:
            br = self.bridge
            paired = self.cfg.get("paired_browsers") or []
            if br.running:
                if br.last_seen:
                    seen = "last contact " + time.strftime("%H:%M:%S", time.localtime(br.last_seen))
                elif paired:
                    seen = f"{len(paired)} paired browser(s)"
                else:
                    seen = "waiting for Connect in the extension"
                txt, col = f"● Listening on 127.0.0.1:{br.port} — {seen}", GREEN
            elif br.error:
                txt, col = "● " + br.error, DANGER
            else:
                txt, col = "● Bridge is off", MUTED
            if hasattr(self, "bridge_status"):
                self.bridge_status.config(text=txt, fg=col)
            if hasattr(self, "bridge_paired_lbl"):
                if paired:
                    names = ", ".join(p.get("name", "?")[:40] for p in paired[-4:])
                    self.bridge_paired_lbl.config(
                        text=f"Paired: {names}" + ("…" if len(paired) > 4 else ""),
                        fg=TEXT_SECONDARY)
                else:
                    self.bridge_paired_lbl.config(
                        text="No browsers paired yet — open the extension and click Connect to app.",
                        fg=MUTED)
        except Exception:
            log_swallowed("IronCladOSApp.refresh_bridge_status")

    def apply_bridge(self):
        try:
            port = int(self.var_bridge_port.get().strip())
            if not 1024 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Bridge", "Port must be a number between 1024 and 65535.")
            return
        self.cfg["bridge_enabled"] = bool(self.var_bridge.get())
        self.cfg["bridge_port"] = port
        self.persist()
        if self.cfg["bridge_enabled"]:
            self.bridge.start()
        else:
            self.bridge.stop()
        self.refresh_bridge_status()
        if self.cfg["bridge_enabled"] and self.bridge.error:
            messagebox.showerror("Bridge", self.bridge.error)

    def forget_paired_browsers(self):
        if messagebox.askyesno(
                "Forget paired browsers",
                "Disconnect every Chrome extension that is currently paired?\n"
                "They will need to click Connect to app again."):
            self.bridge.forget_all()
            self.refresh_bridge_status()

    def poll_ui(self):
        while True:
            try:
                fn = self.ui_q.get_nowait()
            except queue.Empty:
                break
            except Exception:
                break
            try:
                fn()
            except Exception:
                log_exc()
        try:
            self.root.after(100, self.poll_ui)
        except Exception:
            log_swallowed("IronCladOSApp.poll_ui")

    def tick(self):
        try:
            self.refresh_status()
        except Exception:
            log_exc()
        try:
            self.root.after(1000, self.tick)
        except Exception:
            log_swallowed("IronCladOSApp.tick")

    def refresh_status(self):
        self.refresh_bridge_status()
        try:
            running = bool(self.proxy and self.proxy.running)
            b, a, size, recent = self.engine.snapshot()
            total = b + a
            label = "Stop protection" if running else "Start protection"
            style = "danger" if running else "primary"
            for btn in (getattr(self, "t_prot_btn", None),
                        getattr(self, "ad_btn", None)):
                if btn is None:
                    continue
                try:
                    btn.set_text(label)
                    btn.set_style(style)
                except Exception:
                    log_swallowed("IronCladOSApp.refresh_status")
            if hasattr(self, "ad_status"):
                port = self.proxy.port if (running and self.proxy) \
                    else self.cfg.get("port", 8899)
                txt = f"● Running on 127.0.0.1:{port}" if running else "● Off"
                self.ad_status.config(text=txt, fg=GREEN if running else MUTED)
            if hasattr(self, "t_prot"):
                self.t_prot.config(text="Active" if running else "Off",
                                   fg=GREEN if running else TEXT)
                port = self.proxy.port if (running and self.proxy) \
                    else self.cfg.get("port", 8899)
                self.t_prot_sub.config(text=f"127.0.0.1:{port}" if running
                                       else "Not filtering traffic")
            if hasattr(self, "t_blocked"):
                self.t_blocked.config(text=f"{b:,}")
                self.t_blocked_sub.config(
                    text=f"{100 * b / total:.0f}% of {total:,} requests"
                    if total else "No traffic yet")
            if hasattr(self, "t_domains"):
                self.t_domains.config(text=f"{size:,}")
                self.t_domains_sub.config(text="ads, trackers, malware")
            for lbl, btn in getattr(self, "_prot_strips", []):
                try:
                    lbl.config(text="● Protection on" if running else "● Protection off",
                               fg=GREEN if running else MUTED)
                    btn.set_text(label)
                    btn.set_style(style)
                except Exception:
                    log_swallowed("IronCladOSApp.refresh_status")
            if hasattr(self, "foot_status"):
                self.foot_status.config(
                    text="● Protection on" if running else "● Protection off",
                    fg=GREEN if running else MUTED)
            if hasattr(self, "ad_stats"):
                self.ad_stats.config(
                    text=f"Blocked {b:,} · Allowed {a:,} · "
                         f"{size:,} domains on blocklists")

            try:
                on_lists = [i for i in self.lists.catalog()
                            if self.cfg["lists"].get(i["id"], {}).get("enabled")]
            except Exception:
                on_lists = []
            keys = self.keys()
            n_keys = sum(1 for v in keys.values() if v)
            rows = {
                "proxy": (GREEN if running else MUTED,
                          "running" if running else "stopped"),
                "sys": ((GREEN, "enabled") if self.cfg.get("sysproxy_backup")
                        else (MUTED, "not set")) if SystemProxy.supported()
                       else (MUTED, "manual setup"),
                "lists": (GREEN if on_lists else YELLOW,
                          f"{len(on_lists)} enabled"),
                "online": (GREEN if self.var_online.get() else MUTED,
                           "on" if self.var_online.get() else "off"),
                "intel": (GREEN if n_keys else YELLOW,
                          f"{n_keys}/3 configured"),
            }
            for key, (color, text) in rows.items():
                pair = self.status_rows.get(key)
                if not pair:
                    continue
                dot, val = pair
                try:
                    dot.config(fg=color)
                    val.config(text=text)
                except Exception:
                    log_swallowed("IronCladOSApp.refresh_status")
            if hasattr(self, "block_tree") and recent != self._recent_shown:
                self._recent_shown = recent
                try:
                    self.block_tree.delete(*self.block_tree.get_children())
                    for t, host, why in recent[:100]:
                        self.block_tree.insert("", "end",
                                               values=(t, host, why))
                except Exception:
                    log_swallowed("IronCladOSApp.refresh_status")
        except Exception:
            log_exc()

    def on_close(self):
        try:
            self.bridge.stop()
        except Exception:
            log_swallowed("IronCladOSApp.on_close")
        try:
            if self.proxy:
                self.proxy.stop()
        except Exception:
            log_swallowed("IronCladOSApp.on_close")
        if SystemProxy.supported():
            try:
                self.sysproxy.restore()
            except Exception:
                log_swallowed("IronCladOSApp.on_close")
        try:
            self.root.destroy()
        except Exception:
            log_swallowed("IronCladOSApp.on_close")


# =============================================================================
#  ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    if tk is None:
        raise SystemExit("tkinter is not installed - install it to run the GUI.")
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        log_swallowed("<module>")
    try:
        window = tk.Tk()
        IronCladOSApp(window)
        window.mainloop()
    except Exception:
        log_exc()
        raise
