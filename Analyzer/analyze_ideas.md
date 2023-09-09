# Find processes with no executable on disk 
Check all processes that does not have an executable associated, and parent pid not equals 2(kthreadd) and pid not equals 2(kthreadd)

# Compare between procfs to 'ps' command
Check process pids that appear in "procfs" and not in "ps_aux"
vice versa(?)

# Compare between procfs to 'lsmod' command
Check module names that appear in "/proc/modules" and not in "lsmod"
vice versa(?)

# Compare files hashes to baseline
Gather hashes of various files such as:
- /etc/* files
- systemd unit files
- system-generators
- user static init scripts(bashrc, bash_profile, bash_logout, etc)
Compare them to a baseline of hashes(path.hash -> baseline.path.hash)
if there are differences -> shows diff strings
This way, it will be easy to clear out all files that can be used for malicious purposes,
and if there's a difference, you could also immediately get the difference.

# Compare executable files hashes to baseline
Gather hashes of all executable files on the system
Compare them to a baseline of hashes(executable_path.hash - > baseline.executable_path.hash)
and divide it to 3 categories:
KnownTrusted -> executables that are in the trusted baseline
KnownMalicious -> executables that are in the malicious baseline
Unknown -> executables that are not in both

# Open files with deleted entry
Shows all open files that has a deleted entry
Could indicate a malicious technique to delete artifacts

# Recent created/modified executable files
With this collect technique it's possible to find new executable created,
if u check their path, hash, etc you could find malicious ones.

# Compare installed packages to baseline
self explained



