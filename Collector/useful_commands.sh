
# Lists files by size recursively
find . -type f -exec ls -lh {} + | sort -h -k5

# zip a directory -v is for verbose
tar -czvf results.tar.gz result/

# unzip a directory -v is for verbose
tar -xzvf archive.tar.gz -C /path/to/target_directory
