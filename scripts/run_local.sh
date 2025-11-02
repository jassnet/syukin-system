#!/usr/bin/env bash
set -eu
source .venv/bin/activate
python -m flask --app app run -p 8000
