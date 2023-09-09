# Find processes with no executable on disk 
Check all processes that does not have an executable associated, and parent pid not equals 2(kthreadd) and pid not equals 2(kthreadd)

# Compare procfs to 'ps' command
Check process pids that appear in "procfs" and not in "ps_aux"
vice versa(?)

# Compare procfs to 'lsmod' command
Check module names that appear in "/proc/modules" and not in "lsmod"
vice versa(?)

