#!/bin/bash

# Output directory
OUTPUT_DIR="/path/to/output/directory"
mkdir -p "$OUTPUT_DIR"

# Copy contents of /etc/rc*.d directories while maintaining directory structure
find /etc/rc*.d/ -type d -exec mkdir -p "$OUTPUT_DIR"/{} \;
find /etc/rc*.d/ -type f -exec cp --parents {} "$OUTPUT_DIR" \;

# Copy contents of /etc/init.d directory while maintaining directory structure
find /etc/init.d/ -type d -exec mkdir -p "$OUTPUT_DIR"/{} \;
find /etc/init.d/ -type f -exec cp --parents {} "$OUTPUT_DIR" \;

echo "Contents of /etc/rc*.d and /etc/init.d directories copied to $OUTPUT_DIR."w