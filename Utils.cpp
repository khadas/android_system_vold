/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sehandle.h"
#include "Utils.h"
#include "Process.h"

#include <base/file.h>
#include <base/logging.h>
#include <base/stringprintf.h>
#include <cutils/fs.h>
#include <cutils/properties.h>
#include <private/android_filesystem_config.h>
#include <logwrap/logwrap.h>

#include <mutex>
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/statvfs.h>

#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW    0x00000008  /* Don't follow symlink on umount */
#endif

using android::base::ReadFileToString;
using android::base::StringPrintf;

namespace android {
namespace vold {

security_context_t sBlkidContext = nullptr;
security_context_t sBlkidUntrustedContext = nullptr;
security_context_t sFsckContext = nullptr;
security_context_t sFsckUntrustedContext = nullptr;

static const char* kBlkidPath = "/system/bin/blkid";
static const char* kKeyPath = "/data/misc/vold";

static const char* kProcFilesystems = "/proc/filesystems";

status_t CreateDeviceNode(const std::string& path, dev_t dev) {
    const char* cpath = path.c_str();
    status_t res = 0;

    char* secontext = nullptr;
    if (sehandle) {
        if (!selabel_lookup(sehandle, &secontext, cpath, S_IFBLK)) {
            setfscreatecon(secontext);
        }
    }

    mode_t mode = 0660 | S_IFBLK;
    if (mknod(cpath, mode, dev) < 0) {
        if (errno != EEXIST) {
            PLOG(ERROR) << "Failed to create device node for " << major(dev)
                    << ":" << minor(dev) << " at " << path;
            res = -errno;
        }
    }

    if (secontext) {
        setfscreatecon(nullptr);
        freecon(secontext);
    }

    return res;
}

status_t DestroyDeviceNode(const std::string& path) {
    const char* cpath = path.c_str();
    if (TEMP_FAILURE_RETRY(unlink(cpath))) {
        return -errno;
    } else {
        return OK;
    }
}

status_t PrepareDir(const std::string& path, mode_t mode, uid_t uid, gid_t gid) {
    const char* cpath = path.c_str();

    char* secontext = nullptr;
    if (sehandle) {
        if (!selabel_lookup(sehandle, &secontext, cpath, S_IFDIR)) {
            setfscreatecon(secontext);
        }
    }

    int res = fs_prepare_dir(cpath, mode, uid, gid);

    if (secontext) {
        setfscreatecon(nullptr);
        freecon(secontext);
    }

    if (res == 0) {
        return OK;
    } else {
        return -errno;
    }
}

status_t ForceUnmount(const std::string& path) {
    const char* cpath = path.c_str();
    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    PLOG(WARNING) << "Failed to unmount " << path;

    sleep(5);
    Process::killProcessesWithOpenFiles(cpath, SIGINT);

    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    PLOG(WARNING) << "Failed to unmount " << path;

    sleep(5);
    Process::killProcessesWithOpenFiles(cpath, SIGTERM);

    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    PLOG(WARNING) << "Failed to unmount " << path;

    sleep(5);
    Process::killProcessesWithOpenFiles(cpath, SIGKILL);

    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    PLOG(ERROR) << "Failed to unmount " << path;

    return -errno;
}

status_t BindMount(const std::string& source, const std::string& target) {
    if (::mount(source.c_str(), target.c_str(), "", MS_BIND, NULL)) {
        PLOG(ERROR) << "Failed to bind mount " << source << " to " << target;
        return -errno;
    }
    return OK;
}

static status_t readMetadata(const std::string& path, std::string& fsType,
        std::string& fsUuid, std::string& fsLabel, bool untrusted) {
    fsType.clear();
    fsUuid.clear();
    fsLabel.clear();

    std::vector<std::string> cmd;
    cmd.push_back(kBlkidPath);
    cmd.push_back("-c");
    cmd.push_back("/dev/null");
    cmd.push_back("-s");
    cmd.push_back("TYPE");
    cmd.push_back("-s");
    cmd.push_back("UUID");
    cmd.push_back("-s");
    cmd.push_back("LABEL");
    cmd.push_back(path);

    std::vector<std::string> output;
    status_t res = ForkExecvp(cmd, output, untrusted ? sBlkidUntrustedContext : sBlkidContext);
    if (res != OK) {
        LOG(WARNING) << "blkid failed to identify " << path;
        return res;
    }

    char value[128];
    for (auto line : output) {
        // Extract values from blkid output, if defined
        const char* cline = line.c_str();
        char* start = strstr(cline, "TYPE=");
        if (start != nullptr && sscanf(start + 5, "\"%127[^\"]\"", value) == 1) {
            fsType = value;
        }

        start = strstr(cline, "UUID=");
        if (start != nullptr && sscanf(start + 5, "\"%127[^\"]\"", value) == 1) {
            fsUuid = value;
        }

        start = strstr(cline, "LABEL=");
        if (start != nullptr && sscanf(start + 6, "\"%127[^\"]\"", value) == 1) {
            fsLabel = value;
        }
    }

    return OK;
}

status_t ReadMetadata(const std::string& path, std::string& fsType,
        std::string& fsUuid, std::string& fsLabel) {
    return readMetadata(path, fsType, fsUuid, fsLabel, false);
}

status_t ReadMetadataUntrusted(const std::string& path, std::string& fsType,
        std::string& fsUuid, std::string& fsLabel) {
    return readMetadata(path, fsType, fsUuid, fsLabel, true);
}

status_t ForkExecvp(const std::vector<std::string>& args) {
    return ForkExecvp(args, nullptr);
}

status_t ForkExecvp(const std::vector<std::string>& args, security_context_t context) {
    size_t argc = args.size();
    char** argv = (char**) calloc(argc, sizeof(char*));
    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char*) args[i].c_str();
        if (i == 0) {
            LOG(VERBOSE) << args[i];
        } else {
            LOG(VERBOSE) << "    " << args[i];
        }
    }

    if (setexeccon(context)) {
        LOG(ERROR) << "Failed to setexeccon";
        abort();
    }
    status_t res = android_fork_execvp(argc, argv, NULL, false, true);
    if (setexeccon(nullptr)) {
        LOG(ERROR) << "Failed to setexeccon";
        abort();
    }

    free(argv);
    return res;
}

status_t ForkExecvp(const std::vector<std::string>& args,
        std::vector<std::string>& output) {
    return ForkExecvp(args, output, nullptr);
}

status_t ForkExecvp(const std::vector<std::string>& args,
        std::vector<std::string>& output, security_context_t context) {
    std::string cmd;
    for (size_t i = 0; i < args.size(); i++) {
        cmd += args[i] + " ";
        if (i == 0) {
            LOG(VERBOSE) << args[i];
        } else {
            LOG(VERBOSE) << "    " << args[i];
        }
    }
    output.clear();

    if (setexeccon(context)) {
        LOG(ERROR) << "Failed to setexeccon";
        abort();
    }
    FILE* fp = popen(cmd.c_str(), "r");
    if (setexeccon(nullptr)) {
        LOG(ERROR) << "Failed to setexeccon";
        abort();
    }

    if (!fp) {
        PLOG(ERROR) << "Failed to popen " << cmd;
        return -errno;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp) != nullptr) {
        LOG(VERBOSE) << line;
        output.push_back(std::string(line));
    }
    if (pclose(fp) != 0) {
        PLOG(ERROR) << "Failed to pclose " << cmd;
        return -errno;
    }

    return OK;
}

pid_t ForkExecvpAsync(const std::vector<std::string>& args) {
    size_t argc = args.size();
    char** argv = (char**) calloc(argc + 1, sizeof(char*));
    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char*) args[i].c_str();
        if (i == 0) {
            LOG(VERBOSE) << args[i];
        } else {
            LOG(VERBOSE) << "    " << args[i];
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        if (execvp(argv[0], argv)) {
            PLOG(ERROR) << "Failed to exec";
        }

        _exit(1);
    }

    if (pid == -1) {
        PLOG(ERROR) << "Failed to exec";
    }

    free(argv);
    return pid;
}

status_t ReadRandomBytes(size_t bytes, std::string& out) {
    out.clear();

    int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd == -1) {
        return -errno;
    }

    char buf[BUFSIZ];
    size_t n;
    while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[0], std::min(sizeof(buf), bytes)))) > 0) {
        out.append(buf, n);
        bytes -= n;
    }
    close(fd);

    if (bytes == 0) {
        return OK;
    } else {
        return -EIO;
    }
}

status_t HexToStr(const std::string& hex, std::string& str) {
    str.clear();
    bool even = true;
    char cur = 0;
    for (size_t i = 0; i < hex.size(); i++) {
        int val = 0;
        switch (hex[i]) {
        case ' ': case '-': case ':': continue;
        case 'f': case 'F': val = 15; break;
        case 'e': case 'E': val = 14; break;
        case 'd': case 'D': val = 13; break;
        case 'c': case 'C': val = 12; break;
        case 'b': case 'B': val = 11; break;
        case 'a': case 'A': val = 10; break;
        case '9': val = 9; break;
        case '8': val = 8; break;
        case '7': val = 7; break;
        case '6': val = 6; break;
        case '5': val = 5; break;
        case '4': val = 4; break;
        case '3': val = 3; break;
        case '2': val = 2; break;
        case '1': val = 1; break;
        case '0': val = 0; break;
        default: return -EINVAL;
        }

        if (even) {
            cur = val << 4;
        } else {
            cur += val;
            str.push_back(cur);
            cur = 0;
        }
        even = !even;
    }
    return even ? OK : -EINVAL;
}

static const char* kLookup = "0123456789abcdef";

status_t StrToHex(const std::string& str, std::string& hex) {
    hex.clear();
    for (size_t i = 0; i < str.size(); i++) {
        hex.push_back(kLookup[(str[i] & 0xF0) >> 4]);
        hex.push_back(kLookup[str[i] & 0x0F]);
    }
    return OK;
}

status_t NormalizeHex(const std::string& in, std::string& out) {
    std::string tmp;
    if (HexToStr(in, tmp)) {
        return -EINVAL;
    }
    return StrToHex(tmp, out);
}

uint64_t GetFreeBytes(const std::string& path) {
    struct statvfs sb;
    if (statvfs(path.c_str(), &sb) == 0) {
        return sb.f_bfree * sb.f_bsize;
    } else {
        return -1;
    }
}

// TODO: borrowed from frameworks/native/libs/diskusage/ which should
// eventually be migrated into system/
static int64_t stat_size(struct stat *s) {
    int64_t blksize = s->st_blksize;
    // count actual blocks used instead of nominal file size
    int64_t size = s->st_blocks * 512;

    if (blksize) {
        /* round up to filesystem block size */
        size = (size + blksize - 1) & (~(blksize - 1));
    }

    return size;
}

// TODO: borrowed from frameworks/native/libs/diskusage/ which should
// eventually be migrated into system/
int64_t calculate_dir_size(int dfd) {
    int64_t size = 0;
    struct stat s;
    DIR *d;
    struct dirent *de;

    d = fdopendir(dfd);
    if (d == NULL) {
        close(dfd);
        return 0;
    }

    while ((de = readdir(d))) {
        const char *name = de->d_name;
        if (fstatat(dfd, name, &s, AT_SYMLINK_NOFOLLOW) == 0) {
            size += stat_size(&s);
        }
        if (de->d_type == DT_DIR) {
            int subfd;

            /* always skip "." and ".." */
            if (name[0] == '.') {
                if (name[1] == 0)
                    continue;
                if ((name[1] == '.') && (name[2] == 0))
                    continue;
            }

            subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
            if (subfd >= 0) {
                size += calculate_dir_size(subfd);
            }
        }
    }
    closedir(d);
    return size;
}

uint64_t GetTreeBytes(const std::string& path) {
    int dirfd = open(path.c_str(), O_DIRECTORY, O_RDONLY);
    if (dirfd < 0) {
        PLOG(WARNING) << "Failed to open " << path;
        return -1;
    } else {
        uint64_t res = calculate_dir_size(dirfd);
        close(dirfd);
        return res;
    }
}

bool IsFilesystemSupported(const std::string& fsType) {
    std::string supported;
    if (!ReadFileToString(kProcFilesystems, &supported)) {
        PLOG(ERROR) << "Failed to read supported filesystems";
        return false;
    }
    return supported.find(fsType + "\n") != std::string::npos;
}

status_t WipeBlockDevice(const std::string& path) {
    status_t res = -1;
    const char* c_path = path.c_str();
    unsigned long nr_sec = 0;
    unsigned long long range[2];

    int fd = TEMP_FAILURE_RETRY(open(c_path, O_RDWR | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << path;
        goto done;
    }

    if ((ioctl(fd, BLKGETSIZE, nr_sec)) == -1) {
        PLOG(ERROR) << "Failed to determine size of " << path;
        goto done;
    }

    range[0] = 0;
    range[1] = (unsigned long long) nr_sec * 512;

    LOG(INFO) << "About to discard " << range[1] << " on " << path;
    if (ioctl(fd, BLKDISCARD, &range) == 0) {
        LOG(INFO) << "Discard success on " << path;
        res = 0;
    } else {
        PLOG(ERROR) << "Discard failure on " << path;
    }

done:
    close(fd);
    return res;
}

std::string BuildKeyPath(const std::string& partGuid) {
    return StringPrintf("%s/expand_%s.key", kKeyPath, partGuid.c_str());
}

dev_t GetDevice(const std::string& path) {
    struct stat sb;
    if (stat(path.c_str(), &sb)) {
        PLOG(WARNING) << "Failed to stat " << path;
        return 0;
    } else {
        return sb.st_dev;
    }
}

std::string DefaultFstabPath() {
    char hardware[PROPERTY_VALUE_MAX];
    property_get("ro.hardware", hardware, "");
    return StringPrintf("/fstab.%s", hardware);
}

static status_t readBlockDevMajorAndMinor(
    const std::string& devPath,
    std::string& major, std::string& minor) {
    major.clear();
    minor.clear();

    std::vector<std::string> cmd;
    cmd.push_back("/system/bin/ls");
    cmd.push_back("-l");
    cmd.push_back(devPath);

    std::vector<std::string> output;
    status_t res = ForkExecvp(cmd, output);
    if (res != OK) {
        LOG(WARNING) << "failed to identify ls -l " << devPath;
        return res;
    }

    // Extract values from output
    // brw------- root     root     179,   1 2015-01-01 00:00 mmcblk0p1
    char value[128];
    for (auto line : output) {
        int count = sscanf(line.c_str(), "%3s", value);
        if (count == 1 && !strcmp(value, "brw")) {              // block device
            char f[128], s[128];
            if (sscanf(line.c_str(), "%[^','],%s", f, s) == 2) { // split ','
                minor = s;
                char *cline = strdup(f);
                char *str = strtok(cline, " ");
                char buf[25];
                while (str != nullptr) {
                    if (sscanf(str, "%[1-9]", buf) == 1) {
                        major = buf;
                    }
                    str = strtok(nullptr, " ");
                }
            }
        }
    }

    return OK;
}

// Get physical device path (such as /dev/block/sda) by kernel event sys path
status_t GetPhysicalDevice(
    const std::string& sysPath, std::string& physicalDev) {
    int iPos = sysPath.find("/block/");
    if (iPos < 0) {
        LOG(WARNING) << "can't find \"/block/\" in " << sysPath;
        return -1;
    }

    physicalDev = StringPrintf("/dev/block/%s", sysPath.substr(iPos + 7).c_str());
    if (access(physicalDev.c_str(), F_OK)) {
        LOG(INFO) << "physical dev: " << physicalDev + " doesn't exist";
        return -1;
    }

    return OK;
}

// /sys//devices/d0072000.sd/mmc_host/sd/sd:0007/block/mmcblk0
// /sys//devices/dwc2_b/usb1/1-1/1-1.2/1-1.2:1.0/host0/target0:0:0/0:0:0:0/block/sda
status_t GetLogicalPartitionDevice(
    const dev_t device, const std::string& sysPath, std::string& logicalPartitionDev) {
    std::string physicalDev;
    const unsigned int kMajorBlockMmc = 179;
    const unsigned int kMaxNumOfPartition = 20;

    // logical partition dev's major & minor
    unsigned int devMajor = major(device);
    unsigned int devMinor = minor(device);

    if (GetPhysicalDevice(sysPath, physicalDev) != OK) {
        return -1;
    }

    LOG(INFO) << "physical dev: " << physicalDev <<
        ", logical partition dev's major: " << devMajor << ", minor: " << devMinor;

    // For now, assume that MMC devices are SD, and that
    // everything else is USB
    std::string lpDev;
    std::string major, minor;
    for (unsigned int i = 1; i <= kMaxNumOfPartition; i ++) {
        if (devMajor == kMajorBlockMmc) {   // SD
            lpDev =  StringPrintf("%sp%d", physicalDev.c_str(), i);
        } else {    // USB
            lpDev =  StringPrintf("%s%d", physicalDev.c_str(), i);
        }

        if (!access(lpDev.c_str(), F_OK) &&
            readBlockDevMajorAndMinor(lpDev, major, minor) == OK &&
            (int)devMajor == atoi(major.c_str()) &&
            (int)devMinor == atoi(minor.c_str())) {
            logicalPartitionDev = lpDev;
            LOG(INFO) << "find logical partition dev: " << logicalPartitionDev;
            break;
        }
    }

    return OK;
}

// Such as /dev/block/sda is used, return true,otherwise false
// just true,saved sda to physicalDevName
bool IsJustPhysicalDevice(
    const std::string& sysPath, std::string& physicalDevName) {
    std::string major, minor;
    std::string physicalDev;
    std::string logicalPartitionDev;
    const unsigned int kMajorBlockMmc = 179;

    if (GetPhysicalDevice(sysPath, physicalDev) == OK) {
        std::vector<std::string> cmd;
        cmd.push_back(kBlkidPath);
        cmd.push_back("-c");
        cmd.push_back("/dev/null");
        cmd.push_back("-s");
        cmd.push_back("TYPE");
        cmd.push_back("-s");
        cmd.push_back("UUID");
        cmd.push_back("-s");
        cmd.push_back("LABEL");
        cmd.push_back(physicalDev);

        std::vector<std::string> output;
        status_t res = ForkExecvp(cmd, output);
        if (res != OK) {
            LOG(WARNING) << "failed to identify blkid " << physicalDev;
            return false;
        }

        char value[128];
        for (auto line : output) {
            // Extract values from blkid output, if defined
            const char* cline = line.c_str();
            if (!strncmp(cline, physicalDev.c_str(), strlen(physicalDev.c_str()))) {
                if (readBlockDevMajorAndMinor(physicalDev, major, minor) == OK) {
                    logicalPartitionDev = (atoi(major.c_str()) == kMajorBlockMmc) ?
                        StringPrintf("%sp1", physicalDev.c_str()) :
                        StringPrintf("%s1", physicalDev.c_str());
                    if (access(logicalPartitionDev.c_str(), F_OK)) {
                        // And logical partition device doesn't exist,
                        // we're sure physical device is used.
                        // length /dev/block/ = 11,such as sda or mmcblk0,
                        // we get as physical device name.
                        physicalDevName = StringPrintf("%s", physicalDev.substr(11).c_str());
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

}  // namespace vold
}  // namespace android
