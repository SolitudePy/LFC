#!/bin/bash

# Destination directory for copying artifacts
destination_dir="/tmp/procfs"

# Create the destination directory if it doesn't exist
mkdir -p "$destination_dir"

# Array of important files to copy
proc_important_files=(
    "cmdline"
    "status"
    "stat"
    "maps"
    "exe"
    "comm"
    "environ"
    # Add more files as needed
)

# Traverse /proc and copy files from each process directory
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    process_dir="/proc/$pid"

    # Create corresponding process directory in the destination directory
    mkdir -p "$destination_dir$process_dir"

    # Copy important artifacts from the process directory
    for artifact in "${proc_important_files[@]}"; do
        artifact_path="$process_dir/$artifact"

        # Copy artifact to the destination directory
        if [ -f "$artifact_path" ]; then
            cp -p "$artifact_path" "$destination_dir$artifact_path"
        fi
    done
done
