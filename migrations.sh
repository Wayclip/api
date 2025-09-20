#!/bin/bash
cd "$(dirname "$0")/migrations" || exit 1
cat *.up.sql >../merged.sql
echo "Merged all .up.sql files into merged.sql"
