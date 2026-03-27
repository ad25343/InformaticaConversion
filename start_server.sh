#!/bin/bash
cd "$(dirname "$0")/app"
set -a && source .env && set +a
export DB_PATH="$(pwd)/data/jobs.db"
exec uvicorn main:app --host 0.0.0.0 --port 8001
