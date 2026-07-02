
# Lab 3 - RSA-OAEP and Hybrid Encryption


Họ Tên: Trần Ngọc Nhất
MSSV: 24162086


## Goal
 RSA-OAEP with SHA-256 and hybrid envelope encryption using RSA-OAEP + AES-256-GCM.

## Tính năng cần build
- RSA-3072 key generation

- RSA-4096 performance comparison

- RSA-OAEP with SHA-256

- Optional OAEP label

- Hybrid encryption for large plaintext

- AES-256-GCM authenticated encryption

- PEM/DER key storage

- Negative tests

- Benchmarking on Windows and Linux



## Lệnh Build, sử dụng Windows MSYS2 UCRT64



```bash

cmake -S . -B build-windows-ucrt64 -G Ninja -DCMAKE_BUILD_TYPE=Release

cmake --build build-windows-ucrt64

./build-windows-ucrt64/rsatool.exe selftest

