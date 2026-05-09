#!/usr/bin/env bash

# Exit on any error
set -e

# Ensure we are in the project root
cd "$(dirname "$0")"

# Function to stop background processes on exit
cleanup() {
  echo "Stopping servers..."
  if [[ -n "$API_PID" ]]; then kill "$API_PID" 2>/dev/null || true; fi
  if [[ -n "$WEB_PID" ]]; then kill "$WEB_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

# Start FastAPI backend (uvicorn) on port 8000
echo "Starting FastAPI backend..."
uvicorn apps.api.main:app --reload --host 0.0.0.0 --port 8000 &
API_PID=$!

echo "FastAPI PID: $API_PID"

# Start Vite dev server for the web UI (default port 5173)
echo "Starting Vite frontend..."
# Change to the web app directory
pushd apps/web > /dev/null
npm install --silent
npm run dev &
WEB_PID=$!
popd > /dev/null

echo "Vite PID: $WEB_PID"

# Wait for both processes to finish (they run indefinitely until stopped)
wait $API_PID $WEB_PID
