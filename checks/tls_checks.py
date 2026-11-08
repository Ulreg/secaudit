"""TLS versions, cipher suites, compression, certificate, OCSP stapling, renegotiation."""
import shutil
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .common import add, fetch_der, host_of, https_port

V = ssl.TLSVersion
ALL = "ALL:COMPLEMENTOFALL"


def _ctx(minv, maxv, ciphers=None, compression=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = minv
        ctx.maximum_version = maxv
    except ValueError:
        return None
    try:
        ctx.set_ciphers((ciphers or ALL) + ":@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if compression:
        ctx.options &= ~ssl.OP_NO_COMPRESSION
    return ctx


def _hs(host, port, ctx, timeout=6):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return {"version": ss.version(), "cipher": ss.cipher(), "compression": ss.compression()}
    except (OSError, ssl.SSLError):
        return None


def classify(name: str) -> str:
    """insecure / no_pfs / phase_out / good for an OpenSSL cipher-suite name."""
    n = name.upper()
    if any(x in n for x in ("RC4", "DES", "NULL", "EXP", "MD5", "ADH", "AECDH", "ANON")):
        return "insecure"
    if not n.startswith(("ECDHE", "DHE", "EDH")):
        return "no_pfs"
    if not any(x in n for x in ("GCM", "CHACHA20", "CCM")):
        return "phase_out"
    return "good"


def _ciphers(host, port, out, ctx):
    base = _ctx(V.TLSv1_2, V.TLSv1_2)
    if not base:
        return
    names = [c["name"] for c in base.get_ciphers() if c.get("protocol") == "TLSv1.2"]
    ctx(f"TLS: testing {len(names)} TLS 1.2 cipher suites")

    def probe(n):
        ctx.stop()
        c = _ctx(V.TLSv1_2, V.TLSv1_2, n)
        return n if c and _hs(host, port, c, 4) else None

    with ThreadPoolExecutor(4) as ex:
        accepted = [n for n in ex.map(probe, names) if n]
    groups = {"insecure": [], "no_pfs": [], "phase_out": [], "good": []}
    for n in accepted:
        groups[classify(n)].append(n)
    ev = f"{len(accepted)} accepted TLS 1.2 suites"
    add(out, not groups["insecure"], "cipher_insecure", ", ".join(groups["insecure"]) or ev)
    add(out, not groups["no_pfs"], "cipher_no_pfs", ", ".join(groups["no_pfs"]) or ev)
    add(out, not groups["phase_out"], "cipher_cbc", ", ".join(groups["phase_out"]) or ev, optional=True)


def _cert(host, port, out):
    err = None
    try:
        with socket.create_connection((host, port), timeout=8) as s:
            with ssl.create_default_context().wrap_socket(s, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as e:
        err = e.verify_message
    except (OSError, ssl.SSLError) as e:
        err = str(e)
    add(out, err is None, "cert_trusted", err or "Chain and hostname verified")
    cert = x509.load_der_x509_certificate(fetch_der(host, port))
    days = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
    add(out, days >= 30, "cert_expiry", f"Expires {cert.not_valid_after_utc:%Y-%m-%d} ({days} days)",
        severity="High" if days < 0 else "Medium")
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        ok, desc = pk.key_size >= 2048, f"RSA {pk.key_size}"
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        ok, desc = pk.curve.key_size >= 256, f"EC {pk.curve.name}"
    else:
        ok, desc = True, type(pk).__name__
    add(out, ok, "cert_key", desc)
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"
    add(out, sig not in ("md5", "sha1"), "cert_sig", sig)
    try:
        cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
        sct = True
    except x509.ExtensionNotFound:
        sct = False
    add(out, sct, "cert_sct", "SCT extension " + ("present" if sct else "missing"), optional=True)


def _openssl(host, port, out, ctx):
    exe = shutil.which("openssl")
    if not exe:
        ctx("TLS: openssl not installed - skipping OCSP/renegotiation checks")
        return
    try:
        r = subprocess.run([exe, "s_client", "-tls1_2", "-status", "-connect", f"{host}:{port}", "-servername", host],
                           input=b"", capture_output=True, timeout=20)
    except Exception:
        return
    txt = (r.stdout + r.stderr).decode(errors="ignore")
    if "Secure Renegotiation" in txt:
        add(out, "Secure Renegotiation IS supported" in txt, "tls_reneg", "openssl s_client -tls1_2")
    if "OCSP response:" in txt:
        ok = "OCSP Response Status: successful" in txt
        add(out, ok, "ocsp_stapling", "OCSP response " + ("stapled" if ok else "not sent"), optional=True)


def run(target, ctx):
    out = []
    host, port = host_of(target), https_port(target)
    if port is None:
        ctx("TLS: target is plain HTTP on a custom port - skipped")
        return out
    ctx(f"TLS: probing {host}:{port}")
    sup = {}
    for name, v in (("TLS 1.0", V.TLSv1), ("TLS 1.1", V.TLSv1_1), ("TLS 1.2", V.TLSv1_2), ("TLS 1.3", V.TLSv1_3)):
        ctx.stop()
        c = _ctx(v, v)
        sup[name] = bool(c and _hs(host, port, c))
    if not any(sup.values()):
        add(out, False, "tls_no_connection", f"{host}:{port}")
        return out
    legacy = [n for n in ("TLS 1.0", "TLS 1.1") if sup[n]]
    add(out, not legacy, "tls_legacy_disabled", ", ".join(legacy) or "not offered", confidence="medium")
    add(out, sup["TLS 1.2"], "tls12_supported", str(sup["TLS 1.2"]))
    add(out, sup["TLS 1.3"], "tls13_supported", str(sup["TLS 1.3"]), optional=True)
    info = _hs(host, port, _ctx(V.TLSv1_2, V.TLSv1_2, compression=True)) if sup["TLS 1.2"] else None
    if info:
        add(out, not info["compression"], "tls_compression", str(info["compression"]), confidence="medium")
    steps = [(_cert, (host, port, out)), (_openssl, (host, port, out, ctx))]
    if ctx.cfg["ciphers"]:
        steps.insert(0, (_ciphers, (host, port, out, ctx)))
    for fn, args in steps:
        try:
            fn(*args)
        except Exception as e:
            if type(e).__name__ == "Cancelled":
                raise
            ctx(f"TLS: {fn.__name__} failed: {e}")
    return out
