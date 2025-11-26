#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt

cd client
npm install
npm run build
cd ..

echo "Build completed successfully!"
