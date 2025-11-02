#!/usr/bin/env bash
set -eu
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp -n .env.example .env || true
echo "Done. Edit .env then run: python -m flask --app app run -p 8000"
