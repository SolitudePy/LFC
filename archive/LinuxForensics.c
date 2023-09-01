#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

void copyFile(const char* srcPath, const char* destPath) {
    FILE* srcFile = fopen(srcPath, "rb");
    FILE* destFile = fopen(destPath, "wb");
    if (srcFile == NULL || destFile == NULL) {
        printf("Failed to copy file: %s\n", srcPath);
        return;
    }

    char buffer[4096];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), srcFile)) > 0) {
        fwrite(buffer, 1, bytesRead, destFile);
    }

    fclose(srcFile);
    fclose(destFile);
}

void copyDirectory(const char* srcPath, const char* destPath) {
    DIR* dir = opendir(srcPath);
    if (dir == NULL) {
        printf("Failed to open directory: %s\n", srcPath);
        return;
    }

    // Create destination directory if it doesn't exist
    mkdir(destPath, 0755);

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char srcFile[1024];
        char destFile[1024];
        sprintf(srcFile, "%s/%s", srcPath, entry->d_name);
        sprintf(destFile, "%s/%s", destPath, entry->d_name);

        struct stat st;
        stat(srcFile, &st);
        if (S_ISDIR(st.st_mode)) {
            copyDirectory(srcFile, destFile);
        } else {
            copyFile(srcFile, destFile);
        }
    }

    closedir(dir);
}

int main() {
    const char* outputDir = "/path/to/output/directory";
    mkdir(outputDir, 0755);

    // File System Metadata
    copyDirectory("/path/to/file/system", "outputDir/file_system_metadata");

    // System Logs
    copyFile("/var/log/secure", "outputDir/secure");
    copyFile("/var/log/audit/audit.log", "outputDir/audit.log");

    // User Account Information
    copyFile("/etc/passwd", "outputDir/passwd");
    copyFile("/etc/shadow", "outputDir/shadow");
    copyFile("/etc/group", "outputDir/group");
    copyFile("/etc/login.defs", "outputDir/login.defs");
    copyFile("/etc/skel/.bash_history", "outputDir/user_bash_history");

    // Network Artifacts
    copyFile("/etc/network/interfaces", "outputDir/interfaces");
    copyFile("/etc/resolv.conf", "outputDir/resolv.conf");

    // System and Application Logs
    copyDirectory("/var/log/httpd", "outputDir/httpd");
    copyDirectory("/var/log/mysql", "outputDir/mysql");
    copyDirectory("/var/log/ssh", "outputDir/ssh");

    // Configuration Files
    copyDirectory("/etc/init.d", "outputDir/init_scripts");
    copyDirectory("/etc/cron.d", "outputDir/cron_jobs");
    copyDirectory("/etc/httpd", "outputDir/httpd_configs");
    copyDirectory("/etc/nginx", "outputDir/nginx_configs");
    copyDirectory("/etc/mysql", "outputDir/mysql_configs");
    copyFile("/etc/sudoers", "outputDir/sudoers");
    copyDirectory("/etc/sudoers.d", "outputDir/sudoers.d");
    copyDirectory("/etc/pam.d", "outputDir/pam.d");
    copyFile("/etc/ssh/sshd_config", "outputDir/sshd_config");
    copyFile("/etc/hosts", "outputDir/hosts");
    copyFile("/etc/sysctl.conf", "outputDir/sysctl.conf");
    copyFile("/etc/security/limits.conf", "outputDir/limits.conf");
    copyFile("/etc/fstab", "outputDir/fstab");
    copyFile("/etc/exports", "outputDir/exports");
    copyFile("/etc/aliases", "outputDir/aliases");
    copyFile("/etc/rsyslog.conf", "outputDir/rsyslog.conf");
    copyFile("/etc/logrotate.conf", "outputDir/logrotate.conf");
    copyFile("/etc/environment", "outputDir/environment");
    copyFile("/etc/crontab", "outputDir/crontab");
    copyFile("/etc/profile", "outputDir/profile");
    copyFile("/etc/issue", "outputDir/issue");
    copyFile("/etc/motd", "outputDir/motd");
    copyFile("/etc/ntp.conf", "outputDir/ntp.conf");
Apologies for the incomplete response. Here's the continuation and completion of the C code:

```c
    copyFile("/etc/nsswitch.conf", "outputDir/nsswitch.conf");
    copyFile("/etc/hosts.allow", "outputDir/hosts.allow");
    copyFile("/etc/hosts.deny", "outputDir/hosts.deny");
    copyFile("/etc/sysconfig/network", "outputDir/sysconfig_network");

    printf("Disk artifact collection completed. Artifacts saved in %s.\n", outputDir);

    return 0;
}