#!/bin/bash

directory="/path/to/directory"

# Find empty files and directories within the directory
find "$directory" -empty | while read -r entry; do
    if [ -d "$entry" ]; then
        echo "Deleting empty directory: $entry"
        rmdir "$entry"
    else
        echo "Deleting empty file: $entry"
        rm "$entry"
    fi
done