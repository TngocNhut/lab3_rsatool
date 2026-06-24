#!/usr/bin/env bash
set -euo pipefail

BIN="./build-windows-ucrt64/rsatool.exe"
ART="artifacts/windows"

mkdir -p "$ART/benchmark"

echo "===== SELFTEST ====="
$BIN selftest

echo
echo "===== KEYGEN RSA-3072 / RSA-4096 ====="
$BIN keygen --bits 3072 --pub "$ART/demo_rsa3072_pub.pem" --priv "$ART/demo_rsa3072_priv.pem"
$BIN keyinfo --pub "$ART/demo_rsa3072_pub.pem"

$BIN keygen --bits 4096 --pub "$ART/demo_rsa4096_pub.pem" --priv "$ART/demo_rsa4096_priv.pem"
$BIN keyinfo --pub "$ART/demo_rsa4096_pub.pem"

echo
echo "===== DIRECT RSA-OAEP ROUNDTRIP ====="
cat > samples/demo_msg_small.txt <<'TXT'
Lab 3 demo message for RSA-OAEP direct encryption.
TXT

$BIN encrypt --in samples/demo_msg_small.txt --pub "$ART/demo_rsa3072_pub.pem" --out "$ART/demo_msg_small_rsa.ct"
$BIN decrypt --in "$ART/demo_msg_small_rsa.ct" --priv "$ART/demo_rsa3072_priv.pem" --out "$ART/demo_msg_small_rsa.dec.txt"
diff -u samples/demo_msg_small.txt "$ART/demo_msg_small_rsa.dec.txt"
echo "[OK] Direct RSA-OAEP roundtrip"

echo
echo "===== DIRECT RSA TAMPER TEST ====="
cp "$ART/demo_msg_small_rsa.ct" "$ART/demo_msg_small_rsa_tampered.ct"
python3 - <<'PY'
from pathlib import Path
p = Path("artifacts/windows/demo_msg_small_rsa_tampered.ct")
data = bytearray(p.read_bytes())
data[0] ^= 0x01
p.write_bytes(data)
print("[OK] Tampered RSA ciphertext")
PY

set +e
$BIN decrypt --in "$ART/demo_msg_small_rsa_tampered.ct" --priv "$ART/demo_rsa3072_priv.pem" --out "$ART/demo_msg_small_rsa_tampered.dec.txt"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] Tampered RSA ciphertext unexpectedly decrypted"
  exit 1
fi
echo "[OK] Tampered RSA ciphertext rejected"

echo
echo "===== HYBRID ROUNDTRIP ====="
python3 - <<'PY'
from pathlib import Path
Path("samples/demo_msg_large_1k.bin").write_bytes(b"A" * 1024)
print("[OK] Created 1 KiB demo plaintext")
PY

$BIN encrypt --in samples/demo_msg_large_1k.bin --pub "$ART/demo_rsa3072_pub.pem" --out "$ART/demo_msg_large_1k.hybrid.json"
$BIN decrypt --in "$ART/demo_msg_large_1k.hybrid.json" --priv "$ART/demo_rsa3072_priv.pem" --out "$ART/demo_msg_large_1k.hybrid.dec.bin"
cmp samples/demo_msg_large_1k.bin "$ART/demo_msg_large_1k.hybrid.dec.bin"
echo "[OK] Hybrid roundtrip"

echo
echo "===== HYBRID GCM TAMPER TEST ====="
cp "$ART/demo_msg_large_1k.hybrid.json" "$ART/demo_msg_large_1k_tampered_ct.hybrid.json"
python3 - <<'PY'
import base64, json
from pathlib import Path
p = Path("artifacts/windows/demo_msg_large_1k_tampered_ct.hybrid.json")
j = json.loads(p.read_text())
ct = bytearray(base64.b64decode(j["ciphertext"]))
ct[0] ^= 0x01
j["ciphertext"] = base64.b64encode(ct).decode()
p.write_text(json.dumps(j, indent=4) + "\n")
print("[OK] Tampered AES-GCM ciphertext in envelope")
PY

set +e
$BIN decrypt --in "$ART/demo_msg_large_1k_tampered_ct.hybrid.json" --priv "$ART/demo_rsa3072_priv.pem" --out "$ART/demo_msg_large_1k_tampered_ct.dec.bin"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] Tampered hybrid ciphertext unexpectedly decrypted"
  exit 1
fi
echo "[OK] Tampered hybrid ciphertext rejected"

echo
echo "===== BENCH RSA QUICK ====="
$BIN bench --bits 3072 --out "$ART/benchmark/demo_bench_rsa3072_windows.csv"

echo
echo "===== BENCH HYBRID ====="
$BIN bench-hybrid --pub "$ART/demo_rsa3072_pub.pem" --priv "$ART/demo_rsa3072_priv.pem" --out "$ART/benchmark/demo_bench_hybrid_windows.csv"

echo
echo "[OK] Lab 3 Windows demo completed successfully."
