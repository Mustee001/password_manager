#!/bin/bash
cd server && python app.py &
FLASK_PID=$!
cd client && npm run dev &
NPM_PID=$!
trap "kill $FLASK_PID $NPM_PID 2>/dev/null" EXIT
wait
