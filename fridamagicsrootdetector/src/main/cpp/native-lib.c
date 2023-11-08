#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <elf.h>
#include <dirent.h>
#include <ctype.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <asm/unistd.h>
#include <android/log.h>

#include "syscall_arch.h"
#include "syscalls.h"
#include "mylibc.h"
#include "errno.h"

#include <sys/sysmacros.h>
#include <sys/system_properties.h>


#include <assert.h>

#include <time.h>
#include <stdarg.h>
#include <signal.h>

#include <sys/time.h>

#include "logging.h"
#include "linux_syscall_support.h"

#define MAX_LINE 512
#define MAX_LENGTH 256
static const char *APPNAME = "THANKS-ROOT_DETECTOR";
static const char *FRIDA_THREAD_GUM_JS_LOOP = "gum-js-loop";
static const char *FRIDA_THREAD_GMAIN = "gmain";
static const char *FRIDA_NAMEDPIPE_LINJECTOR = "linjector";
static const char *PROC_MAPS = "/proc/self/maps";
static const char *PROC_STATUS = "/proc/self/task/%s/status";
static const char *PROC_FD = "/proc/self/fd";
static const char *PROC_TASK = "/proc/self/task";
#define LIBC "libc.so"

//Structure to hold the details of executable section of library
typedef struct stExecSection {
    int execSectionCount;
    unsigned long offset[2];
    unsigned long memsize[2];
    unsigned long checksum[2];
    unsigned long startAddrinMem;
} execSection;


#define NUM_LIBS 2

//Include more libs as per your need, but beware of the performance bottleneck especially
//when the size of the libraries are > few MBs
static const char *libstocheck[NUM_LIBS] = {"libnative-lib.so", LIBC};
static execSection *elfSectionArr[NUM_LIBS] = {NULL};


#ifdef _32_BIT
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
#elif _64_BIT
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
#endif

static inline void parse_proc_maps_to_fetch_path(char **filepaths);

static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection);

static inline void detect_frida_loop(void *pargs);

static inline bool
scan_executable_segments(char *map, execSection *pTextSection, const char *libraryName);

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len);

static inline unsigned long checksum(void *buffer, size_t len);

static inline void detect_frida_threads();

static inline void detect_frida_namedpipe();

static inline void detect_frida_memdiskcompare();

static int fridaThread = -1;
static int fridaPipe = -1;
static int fridaDisk = -1;
static JNIEnv *environment;
static jobject object;
//Upon loading the library, this function annotated as constructor starts executing
__attribute__((constructor))
void init() {

    char *filePaths[NUM_LIBS];
    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "2 Value of errno: %d\n ",errno);
    parse_proc_maps_to_fetch_path(filePaths);
    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        " 3Value of errno: %d\n ",errno);
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Libc[%x][%x][%x][%x][%x][%x]", __NR_openat,
                        __NR_lseek, __NR_read, __NR_close, __NR_readlinkat, __NR_nanosleep);
    for (int i = 0; i < NUM_LIBS; i++) {
        fetch_checksum_of_library(filePaths[i], &elfSectionArr[i]);
        if (filePaths[i] != NULL)
            free(filePaths[i]);
    }
  __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "Library Load start frida-Magisk");


}


void throwThrowableError( )
{
    jclass Exception = (*environment)->FindClass(environment,"java/lang/Throwable");
    if(Exception==NULL){
        (*environment)->FatalError(environment,"Fatal error");
    }else{
        (*environment)->ThrowNew(environment,Exception, "fatal error");
    }

}

jboolean handleError(){
    jboolean isAnyError = false;
    jboolean ifExceptionPending =(*environment)->ExceptionCheck(environment);

    jthrowable exObj = (*environment)->ExceptionOccurred(environment);

    if(ifExceptionPending||exObj||errno==SIGSEGV||errno==SIGABRT){
        isAnyError=true;
    }
    return isAnyError;

}

__attribute__((always_inline))
static inline void parse_proc_maps_to_fetch_path(char **filepaths) {
    int fd = 0;
    char map[MAX_LINE];
    int counter = 0;
    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {

        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
            for (int i = 0; i < NUM_LIBS; i++) {
                if (my_strstr(map, libstocheck[i]) != NULL) {
                    char tmp[MAX_LENGTH] = "";
                    char path[MAX_LENGTH] = "";
                    char buf[5] = "";
                    sscanf(map, "%s %s %s %s %s %s", tmp, buf, tmp, tmp, tmp, path);
                    if (buf[2] == 'x') {
                        size_t size = my_strlen(path) + 1;
                        filepaths[i] = malloc(size);
                        my_strlcpy(filepaths[i], path, size);
                        counter++;
                    }
                }
            }
            if (counter == NUM_LIBS)
                break;
        }
        my_close(fd);
    }
}

__attribute__((always_inline))
static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection) {

    Elf_Ehdr ehdr;
    Elf_Shdr sectHdr;
    int fd;
    int execSectionCount = 0;
    fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return NULL;
    }

    my_read(fd, &ehdr, sizeof(Elf_Ehdr));
    my_lseek(fd, (off_t) ehdr.e_shoff, SEEK_SET);

    unsigned long memsize[2] = {0};
    unsigned long offset[2] = {0};


    for (int i = 0; i < ehdr.e_shnum; i++) {
        my_memset(&sectHdr, 0, sizeof(Elf_Shdr));
        my_read(fd, &sectHdr, sizeof(Elf_Shdr));

//        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SectionHeader[%d][%ld]", sectHdr.sh_name, sectHdr.sh_flags);

        //Typically PLT and Text Sections are executable sections which are protected
        if (sectHdr.sh_flags & SHF_EXECINSTR) {
//            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SectionHeader[%d][%ld]", sectHdr.sh_name, sectHdr.sh_flags);

            offset[execSectionCount] = sectHdr.sh_offset;
            memsize[execSectionCount] = sectHdr.sh_size;
            execSectionCount++;
            if (execSectionCount == 2) {
                break;
            }
        }
    }
    if (execSectionCount == 0) {
        __android_log_print(ANDROID_LOG_WARN, APPNAME, "No executable section found. Suspicious");
        my_close(fd);
        return false;
    }
    //This memory is not released as the checksum is checked in a thread
    *pTextSection = malloc(sizeof(execSection));

    (*pTextSection)->execSectionCount = execSectionCount;
    (*pTextSection)->startAddrinMem = 0;
    for (int i = 0; i < execSectionCount; i++) {
        my_lseek(fd, offset[i], SEEK_SET);
        uint8_t *buffer = malloc(memsize[i] * sizeof(uint8_t));
        my_read(fd, buffer, memsize[i]);
        (*pTextSection)->offset[i] = offset[i];
        (*pTextSection)->memsize[i] = memsize[i];
        (*pTextSection)->checksum[i] = checksum(buffer, memsize[i]);
        free(buffer);
//        __android_log_print(ANDROID_LOG_WARN, APPNAME, "ExecSection:[%d][%ld][%ld][%ld]", i,
//                            offset[i],
//                            memsize[i], (*pTextSection)->checksum[i]);
    }

    my_close(fd);
    return true;
}


void detect_frida_loop(void *pargs) {
    struct timespec timereq;
    timereq.tv_sec = 5; //Changing to 5 seconds from 1 second
    timereq.tv_nsec = 0;
    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                       "detect frida  act starts.");
    fridaThread=-1;
    fridaPipe=-1;
    fridaDisk=-1;
    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "6 Value of errno: %d\n ",errno);

    jboolean isExceptionFound1=handleError();
    if(isExceptionFound1){
        __android_log_print(ANDROID_LOG_WARN, APPNAME,
                            "Exception found %d\n ",errno);
        throwThrowableError();
    }
    else{
        detect_frida_threads();
        jboolean isExceptionFound2=handleError();
        if(isExceptionFound2){
            throwThrowableError();
        }
        else{
            detect_frida_namedpipe();
            jboolean isExceptionFound3=handleError();
            if(isExceptionFound3){
                throwThrowableError();
            }else{
                detect_frida_memdiskcompare();
            }
        }
    }





}

__attribute__((always_inline))
static inline bool
scan_executable_segments(char *map, execSection *pElfSectArr, const char *libraryName) {
    unsigned long start, end;
    char buf[MAX_LINE] = "";
    char path[MAX_LENGTH] = "";
    char tmp[100] = "";

    sscanf(map, "%lx-%lx %s %s %s %s %s", &start, &end, buf, tmp, tmp, tmp, path);
    //__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Map [%s]", map);

    if (buf[2] == 'x') {
        if (buf[0] == 'r') {
            uint8_t *buffer = NULL;

            buffer = (uint8_t *) start;
            for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
                if (start + pElfSectArr->offset[i] + pElfSectArr->memsize[i] > end) {
                    if (pElfSectArr->startAddrinMem != 0) {
                        buffer = (uint8_t *) pElfSectArr->startAddrinMem;
                        pElfSectArr->startAddrinMem = 0;
                        break;
                    }
                }
            }
            for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
                unsigned long output = checksum(buffer + pElfSectArr->offset[i],
                                                pElfSectArr->memsize[i]);
//                __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Checksum:[%ld][%ld]", output,
//                                    pElfSectArr->checksum[i]);

                if (output != pElfSectArr->checksum[i]) {
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,
                                        "Executable Section Manipulated, "
                                        "maybe due to Frida or other hooking framework."
                                        "Act Now!!!");
                }
            }

        } else {

            char ch[10] = "", ch1[10] = "";
            __system_property_get("ro.build.version.release", ch);
            __system_property_get("ro.system.build.version.release", ch1);
            int version = my_atoi(ch);
            int version1 = my_atoi(ch1);
            if (version < 10 || version1 < 10) {
                __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Suspicious to get XOM in "
                                                                  "version < Android10");
            } else {
                if (0 == my_strncmp(libraryName, LIBC, my_strlen(LIBC))) {
                    //If it is not readable, then most likely it is not manipulated by Frida
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "LIBC Executable Section"
                                                                      " not readable! ");

                } else {
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Suspicious to get XOM "
                                                                      "for non-system library on "
                                                                      "Android 10 and above");
                }
            }
        }
        return true;
    } else {
        if (buf[0] == 'r') {
            pElfSectArr->startAddrinMem = start;
        }
    }
    return false;
}

__attribute__((always_inline))
static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;

    my_memset(buf, 0, max_len);

    do {
        ret = my_read(fd, &b, 1);

        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }

        if (b == '\n') {
            return bytes_read;
        }

        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);

    return bytes_read;
}

__attribute__((always_inline))
static inline unsigned long checksum(void *buffer, size_t len) {
    unsigned long seed = 0;
    uint8_t *buf = (uint8_t *) buffer;
    size_t i;
    for (i = 0; i < len; ++i)
        seed += (unsigned long) (*buf++);
    return seed;
}

__attribute__((always_inline))
static inline void detect_frida_threads() {
//    __android_log_print(ANDROID_LOG_WARN, APPNAME,
//                        "frida crashing/aborting ");

    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "7 Value of errno: %d\n ",errno);
    DIR *dir = opendir(PROC_TASK);
    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "8 Value of errno: %d\n ",errno);
    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";
            __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                "9 Value of errno: %d\n ",errno);
            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }
            snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);
            __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                "10 Value of errno: %d\n ",errno);
            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                "11 Value of errno: %d\n ",errno);
            if (fd != 0) {
                char buf[MAX_LENGTH] = "";
                read_one_line(fd, buf, MAX_LENGTH);
                if (my_strstr(buf, FRIDA_THREAD_GUM_JS_LOOP) ||
                    my_strstr(buf, FRIDA_THREAD_GMAIN)) {
                    //Kill the thread. This freezes the app. Check if it is an anticpated behaviour
                    //int tid = my_atoi(entry->d_name);
                    //int ret = my_tgkill(getpid(), tid, SIGSTOP);
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "Frida specific thread found. Act now!!!");
                    fridaThread=1;
                }
                my_close(fd);
            }

        }
        __android_log_print(ANDROID_LOG_WARN, APPNAME,
                            "frida thread finish");
        closedir(dir);

    }
}

__attribute__((always_inline))
static inline void detect_frida_namedpipe() {

    DIR *dir = opendir(PROC_FD);
    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            struct stat filestat;
            char buf[MAX_LENGTH] = "";
            char filePath[MAX_LENGTH] = "";
            snprintf(filePath, sizeof(filePath), "/proc/self/fd/%s", entry->d_name);

            lstat(filePath, &filestat);

            if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
                //TODO: Another way is to check if filepath belongs to a path not related to system or the app
                my_readlinkat(AT_FDCWD, filePath, buf, MAX_LENGTH);
                if (NULL != my_strstr(buf, FRIDA_NAMEDPIPE_LINJECTOR)) {
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "Frida specific named pipe found. Act now!!!");
                    fridaPipe=1;
                }
            }

        }
    }
    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "frida pipe finish");
    closedir(dir);
}

__attribute__((always_inline))
static inline void detect_frida_memdiskcompare() {

    int fd = 0;
    char map[MAX_LINE];
    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {

        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
            for (int i = 0; i < NUM_LIBS; i++) {
                if (my_strstr(map, libstocheck[i]) != NULL) {
                    if (true == scan_executable_segments(map, elfSectionArr[i], libstocheck[i])) {
                        break;
                    }
                }
            }
        }
    } else {
        __android_log_print(ANDROID_LOG_WARN, APPNAME,
                            "Error opening /proc/self/maps. That's usually a bad sign.");
        fridaDisk=1;

    }

    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "frida disk finish");
    my_close(fd);
}

//Magisk Code

#define TAG "MagiskDetector"
static dev_t scan_mountinfo() {
    int major = 0;
    int minor = 0;
    char line[PATH_MAX];
    char mountinfo[] = "/proc/self/mountinfo";
    int fd = sys_open(mountinfo, O_RDONLY, 0);
    if (fd < 0) {
        LOGE("cannot open %s", mountinfo);
        return 0;
    }
    FILE *fp = fdopen(fd, "r");
    if (fp == NULL) {
        LOGE("cannot open %s", mountinfo);
        close(fd);
        return 0;
    }
    while (fgets(line, PATH_MAX - 1, fp) != NULL) {
        if (strstr(line, "/ /data ") != NULL) {
            sscanf(line, "%*d %*d %d:%d", &major, &minor);
        }
    }
    fclose(fp);
    return makedev(major, minor);
}

static int scan_maps(dev_t data_dev) {
    int module = 0;
    char line[PATH_MAX];
    char maps[] = "/proc/self/maps";
    int fd = sys_open(maps, O_RDONLY, 0);
    if (fd < 0) {
        LOGE("cannot open %s", maps);
        return -1;
    }
    FILE *fp = fdopen(fd, "r");
    if (fp == NULL) {
        LOGE("cannot open %s", maps);
        close(fd);
        return -1;
    }
    while (fgets(line, PATH_MAX - 1, fp) != NULL) {
        if (strchr(line, '/') == NULL) continue;
        if (strstr(line, " /system/") != NULL ||
            strstr(line, " /vendor/") != NULL ||
            strstr(line, " /product/") != NULL ||
            strstr(line, " /system_ext/") != NULL) {
            int f;
            int s;
            char p[PATH_MAX];
            sscanf(line, "%*s %*s %*s %x:%x %*s %s", &f, &s, p);
            if (makedev(f, s) == data_dev) {
                LOGW("Magisk module file %x:%x %s", f, s, p);
                module++;
            }
        }
    }
    fclose(fp);
    return module;
}

static int scan_status() {
    if (getppid() == 1) return -1;
    int pid = -1;
    char line[PATH_MAX];
    char maps[] = "/proc/self/status";
    int fd = sys_open(maps, O_RDONLY, 0);
    if (fd < 0) {
        LOGE("cannot open %s", maps);
        return -1;
    }
    FILE *fp = fdopen(fd, "r");
    if (fp == NULL) {
        LOGE("cannot open %s", maps);
        close(fd);
        return -1;
    }
    while (fgets(line, PATH_MAX - 1, fp) != NULL) {
        if (strncmp(line, "TracerPid", 9) == 0) {
            pid = atoi(&line[10]);
            break;
        }
    }
    fclose(fp);
    return pid;
}

static int scan_path() {
    char *path = getenv("PATH");
    char *p = strtok(path, ":");
    char supath[PATH_MAX];
    do {
        sprintf(supath, "%s/su", p);
        if (access(supath, F_OK) == 0) {
            LOGW("Found su at %s", supath);
            return 1;
        }
    } while ((p = strtok(NULL, ":")) != NULL);
    return 0;
}

static int su = -1;
static int magiskhide = -1;


static jint haveSu(JNIEnv *env __unused, jobject clazz __unused) {
    jboolean isExceptionFound3=handleError();
    if(isExceptionFound3){
        throwThrowableError();
        return -1;
    }else{
        su = scan_path();
        return su;
    }

}


static jint haveMagiskHide(JNIEnv *env __unused, jobject clazz __unused) {
    jboolean isExceptionFound3=handleError();
    if(isExceptionFound3){
        throwThrowableError();
        return -1;
    }else{
        magiskhide = scan_status();
        return magiskhide;
    }

}


static jint haveMagicMount(JNIEnv *env __unused, jobject clazz __unused) {
    jboolean isExceptionFound3=handleError();
    if(isExceptionFound3){
        throwThrowableError();
        return -1;
    }else{
        dev_t data_dev = scan_mountinfo();
        if (data_dev == 0) return -1;
        return scan_maps(data_dev);
    }

}


static void abortApp(JNIEnv *env __unused, jobject clazz __unused) {
    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "Root  found. Act now!!!");
    abort();
}





static jboolean detectFrida(JNIEnv *_env , jobject clazz) {

    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                            "1frida detect");
    environment=_env;

    jboolean isExceptionFound=handleError();

    if(isExceptionFound){
        throwThrowableError();
    }
    else{
        detect_frida_loop(NULL);
    }

    if(fridaThread>0||fridaPipe>0||fridaDisk>0){
        return true;
    }
    else{
        return false;
    }


}


jint JNI_OnLoad(JavaVM *jvm, void *v __unused) {


    JNIEnv *env;
    jclass clazz;

    if ((*jvm)->GetEnv(jvm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    if ((clazz = (*env)->FindClass(env, "com/example/toastmylibrary/MagiskDetector")) ==
        NULL) {
        return JNI_ERR;
    }
    environment=env;
    object=clazz;



    JNINativeMethod methods[] = {
            {"haveSu", "()I", haveSu},
            {"haveMagiskHide", "()I", haveMagiskHide},
            {"haveMagicMount", "()I", haveMagicMount},
            {"abortApp", "()V", abortApp},
            {"detectFrida", "()Z", detectFrida},
    };

    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                        "onLoad Value of errno: %d\n ",errno);
    if ((*env)->RegisterNatives(env, clazz, methods, 5) < 0) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}