#!/usr/bin/env bash
set -euo pipefail

BIN="./build-linux/rsatool"
ART="artifacts/linux"

mkdir -p "$ART/benchmark"

echo "===== SELFTEST ====="
$BIN selftest

echo
echo "===== KEYGEN RSA-3072 ====="
$BIN keygen --bits 3072 --pub "$ART/demo_rsa3072_pub.pem" --priv "$ART/demo_rsa3072_priv.pem"
$BIN keyinfo --pub "$ART/demo_rsa3072_pub.pem"

echo
echo "===== DIRECT RSA-OAEP ROUNDTRIP ====="
cat > samples/demo_msg_small_linux.txt <<'TXT'
Lab 3 Linux demo message for RSA-OAEP direct encryption.
TXT

$BIN encrypt --in samples/demo_msg_small_linux.txt --pub "$ART/demo_rsa3072_pub.pem" --out "$ART/demo_msg_small_rsa.ct"
$BIN decrypt --in "$ART/demo_msg_small_rsa.ct" --priv "$ART/demo_rsa3072_priv.pem" --out "$ART/demo_msg_small_rsa.dec.txt"
diff -u samples/demo_msg_small_linux.txt "$ART/demo_msg_small_rsa.dec.txt"
echo "[OK] Linux direct RSA-OAEP roundtrip"

echo
echo "===== HYBRID ROUNDTRIP ====="
python3 - <<'PY'
from pathlib import Path
Path("samples/demo_msg_large_1k_linux.bin").write_bytes(b"B" * 1024)
print("[OK] Created Linux 1 KiB demo plaintext")
PY

$BIN encrypt --in samples/demo_msg_large_1k_linux.bin --pub "$ART/demo_rsa3072_pub.pem" --out "$ART/demo_msg_large_1k.hybrid.json"
$BIN decrypt --in "$ART/demo_msg_large_1k.hybrid.json" --priv "$ART/demo_rsa3072_priv.pem" --out "$ART/demo_msg_large_1k.hybrid.dec.bin"
cmp samples/demo_msg_large_1k_linux.bin "$ART/demo_msg_large_1k.hybrid.dec.bin"
echo "[OK] Linux hybrid roundtrip"

echo
echo "===== HYBRID TAMPER TEST ====="
cp "$ART/demo_msg_large_1k.hybrid.json" "$ART/demo_msg_large_1k_tampered_ct.hybrid.json"
python3 - <<'PY'
import base64, json
from pathlib import Path
p = Path("artifacts/linux/demo_msg_large_1k_tampered_ct.hybrid.json")
j = json.loads(p.read_text())
ct = bytearray(base64.b64decode(j["ciphertext"]))
ct[0] ^= 0x01
j["ciphertext"] = base64.b64encode(ct).decode()
p.write_text(json.dumps(j, indent=4) + "\n")
print("[OK] Tampered Linux hybrid ciphertext")
PY

set +e
$BIN decrypt --in "$ART/demo_msg_large_1k_tampered_ct.hybrid.json" --priv "$ART/demo_rsa3072_priv.pem" --out "$ART/demo_msg_large_1k_tampered_ct.dec.bin"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] Tampered Linux hybrid ciphertext unexpectedly decrypted"
  exit 1
fi
echo "[OK] Linux tampered hybrid ciphertext rejected"

echo
echo "===== BENCH RSA QUICK ====="
$BIN bench --bits 3072 --out "$ART/benchmark/demo_bench_rsa3072_linux.csv"

echo
echo "[OK] Lab 3 Linux demo completed successfully."
