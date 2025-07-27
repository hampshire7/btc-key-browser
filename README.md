# Puzzle 135 – Bitcoin Key Browser

A deterministic, HTML-based key explorer for specific ECC private key ranges.

## Key Features
- Lists keys deterministically across 4 predefined slices
- Derives compressed secp256k1 public keys using `coincurve`
- Displays Bitcoin P2PKH addresses
- No backend — pure static HTML

## Generate Pages

```bash
pip install -r requirements.txt
python generate_pages.py