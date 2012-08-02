/* 
 * File:   main.cpp
 * Author: machiry
 *
 * Created on March 13, 2012, 12:00 PM
 */

#include <cstdlib>
#include <stdint.h>
#include <libxml2/libxml/SAX.h>

#include "commonHeaders.h"
#include "sysCallStructs.h"
#include "helper.h"
#include "accessControl.h"
#include "logger.h"
#include "accessPolicyParser.h"
#include "hpwd.hh"

using namespace std;

/*
 * 
 */
void cleanup(void) __attribute__((destructor));
static aclList policy = null;

static void displayUsage(char *progName) {
    fprintf(stderr, "\nUsage %s <pid_of_ftpdeamon> [policyFileName] \n", progName);
    fprintf(stderr, "\t\tpolicyFileName: this has to be absolute path to the file\n");
    fprintf(stderr, "\t\t\tthat contains the access policy information\n");
    fprintf(stderr, "\t\t\tif no policy file is specified default value is policy.xml in CWD\n");
    fprintf(stderr, "\n\t\t\tDeveloped By Machiry Aravind Kumar and Rohan Tahiliani\n");
    exit(-1);
}

void cleanup(void) {
    fprintf(stdout, "\n From  Destructor: Tracing Program Exiting...\n");
    closeLog();
    if (policy) {
        freePolicyList(policy);
        policy = null;
    }
}

char** itoa(int val, int base, char *progName, char *ret[]) {
    char *buf = (char*) malloc(sizeof (char) *32);
    int i = 30;

    for (; val && i; --i, val /= base)
        buf[i] = "0123456789abcdef"[val % base];

    ret[0] = progName;
    ret[1] = &buf[i + 1];
    ret[2] = null;
    return ret;

}

void getdata(pid_t child, long addr, char* str, const int len) {

    typedef union _data {
        long val;
        char chars[sizeof (long) ];
    } Data;
    int actL = 0;
    char message[MCHAR];
    Data data;
    int i = 0;
    int j = 0;
    while (actL < len) {
        if ((data.val = ptrace(PTRACE_PEEKTEXT, child, addr + i * sizeof (long), NULL)) == -1) {
            sprintf(message, "\nFATAL:Unable to get data from process:%d , address:%p\n", child, (void*) (addr + i * sizeof (long)));
            logI(message);
        }
        j = 0;
        for (; j < sizeof (long); ++j, ++str) {
            *str = data.chars[j];
        }
        ++i;
        actL += sizeof (long);
    }
    *str = 0;
}

void getNulTerminatedData(pid_t child, long addr, char* str) {

    typedef union _data {
        long val;
        char chars[sizeof (long) ];
    } Data;
    int actL = 0;
    char message[MCHAR];
    Data data;
    int i = 0;
    int j = 0;
    int nullEnded = 0;
    while (actL < MAXKBUFF) {
        if ((data.val = ptrace(PTRACE_PEEKTEXT, child, addr + i * sizeof (long), NULL)) == -1) {
            sprintf(message, "\nFATAL:Unable to get data from process:%d , address:%p\n", child, (void*) (addr + i * sizeof (long)));
            logI(message);
        }
        j = 0;
        for (; j < sizeof (long); ++j, ++str) {
            *str = data.chars[j];
            if (!data.chars[j]) {
                nullEnded = 1;
                break;
            }
        }
        if (nullEnded) {
            break;
        }

        ++i;
        actL += sizeof (long);
    }

    *str = 0;
}

void dumpCallRegisters(struct user_regs_struct callRegisters) {
    printf("\nEAX=%ld", callRegisters.eax);
    printf("\nEBX=%p", (void*) callRegisters.ebx);
    printf("\nECX=%ld", callRegisters.ecx);
    printf("\nEDX=%ld", callRegisters.edx);
}

int main(int argc, char** argv) {

    pid_t tracedProcess;
    int pStatus;
    int childPid;
    char accessedFileName[MCHAR];
    char accessedFileName2[MCHAR];
    long addr1, addr2;
    char *tempchar;
    sysState callState;
    struct user_regs_struct callRegisters;
    int temp = 0;
    char message[MCHAR];
    Ainfo currAccessNode = null;
    char *ret1[4] = {null, null, null, null};
    if (argc < 2 || argc > 3) {
        displayUsage(argv[0]);
    }
    if (argc > 2) {
        policy = getAccessList(argv[2]);
        if (!policy) {
            fprintf(stderr, "Error:Unable to parse the specified file");
            displayUsage(argv[0]);
        }
    } else {
        policy = getAccessList("policy.xml");
        if (!policy) {
            fprintf(stderr, "Unable to parse the default policy file");
            displayUsage(argv[0]);
        }
    }
    tracedProcess = atoi(argv[1]);

    if (temp = ptrace(PTRACE_ATTACH, tracedProcess, NULL, NULL)) {
        sprintf(message, "\nINI:Problem during trying to Attach to process:%d\nReturn Code:%d\nError No:%d\n", tracedProcess, temp, errno);
        fprintf(stdout, "%s", message);
        exit(ATTACH_FAILED);
    }
    wait(NULL);

    if (temp = ptrace(PTRACE_SYSCALL, tracedProcess, NULL, NULL)) {
        sprintf(message, "\nINI:Problem during trying to trace process:%d\nReturn Code:%d\nError No:%d\n", tracedProcess, temp, errno);
        fprintf(stdout, "%s", message);
        exit(TRACE_FAILED);
    }
    ptrace(PTRACE_GETREGS, tracedProcess, 0, &callRegisters);
    callState.in = 1;
    callState.callNo = callRegisters.orig_eax;
    setEnvironment(tracedProcess);
    sprintf(message, "\nInitialized Tracing To:%d, from:%d\n", tracedProcess, getpid());
    logI(message);
    fprintf(stdout, "%s", message);
    fflush(stdout);
    if (strcmp(getEUserFromPid(tracedProcess), "root")) {
        sprintf(message, "\nTrying to do Hardened Password");
        logI(message);
        fprintf(stdout, "%s", message);
        if (authenticate_user((tempchar=getEUserFromPid(tracedProcess)), "password")) {
            sprintf(message, "\nAuthenticated\n");
            logI(message);
            fprintf(stdout, "%s", message);
        } else {
            sprintf(message, "\nNot Authenticated\n");
            logI(message);
            fprintf(stdout, "%s", message);
            printf("\nExiting the Tracer and the target process as the user is not authenticated\n");
            ptrace(PTRACE_KILL, tracedProcess, null, null);
            exit(-1);
        }
        free(tempchar);
    }
    while (1) {
        temp = waitpid(tracedProcess, &pStatus, 0);
        if (currAccessNode) {
            freeANode(currAccessNode);
            currAccessNode = null;
        }
        if (WIFEXITED(pStatus)) {
            sprintf(message, "Process to be traced,pid:%d has exited", tracedProcess);
            displayExitMessage(message);
            break;
        }
        memset(&callRegisters, 0, sizeof (struct user_regs_struct));
        //Here system call has made by the process being traced

        //1. First get the register contents of the call.
        ptrace(PTRACE_GETREGS, tracedProcess, 0, &callRegisters);

        //check if the system call is made..if yes then 
        //implement access control
        //monitored the call it self
        if (callState.in && callRegisters.orig_eax != callState.callNo) {
            sprintf(message, "Syscall:%ld Entered", callRegisters.orig_eax);
            addr1 = 0;
            addr2 = 0;
            callState.callNo = callRegisters.orig_eax;
            logI(message);
            switch (callRegisters.orig_eax) {
                    //here we need to handle the start of the syscall
                case SYS_clone:
                case SYS_fork:
                case SYS_vfork:
                    sprintf(message, "\nIn Fork during entry:%ld\n", callRegisters.eax);
                    fprintf(stdout, "%s", message);
                    fflush(stdout);
                    break;

                    //file open
                case SYS_open:
                case SYS_openat:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    currAccessNode = getAccessNode(accessedFileName, null, callRegisters.ecx, tracedProcess);
                    printf("\nAccessed File:%s", accessedFileName);
                    currAccessNode->mode = getAccessMode(callRegisters.ecx);
                    dumpCallRegisters(callRegisters);
                    addr1 = EBX * 4;
                    break;

                case SYS_readlink:
                case SYS_readlinkat:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    currAccessNode = getAccessNode(accessedFileName, null, READLINK, tracedProcess);
                    addr1 = EBX * 4;
                    break;

                case SYS_symlink:
                case SYS_symlinkat:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    getNulTerminatedData(tracedProcess, callRegisters.ecx, accessedFileName2);
                    currAccessNode = getAccessNode(accessedFileName, accessedFileName2, SYMLINK, tracedProcess);
                    addr1 = 4 * EBX;
                    addr2 = 4 * ECX;
                    break;

                    //file create
                case SYS_creat:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    currAccessNode = getAccessNode(accessedFileName, null, WRITE, tracedProcess);
                    addr1 = 4 * EBX;
                    break;

                    //creating a directory
                case SYS_mkdir:
                case SYS_mkdirat:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    printf("\nAccessed File:%s\n", accessedFileName);
                    currAccessNode = getAccessNode(accessedFileName, null, WRITE, tracedProcess);
                    addr1 = 4 * EBX;
                    break;

                case SYS_rmdir:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    currAccessNode = getAccessNode(accessedFileName, null, WRITE, tracedProcess);
                    addr1 = 4 * EBX;
                    break;

                    //renaming directory
                case SYS_rename:
                case SYS_renameat:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    getNulTerminatedData(tracedProcess, callRegisters.ecx, accessedFileName2);
                    currAccessNode = getAccessNode(accessedFileName, accessedFileName2, RENAME, tracedProcess);
                    addr1 = 4 * EBX;
                    addr2 = 4 * ECX;
                    break;

                    //modifying file state
                case SYS_chroot:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    currAccessNode = getAccessNode(accessedFileName, null, WRITESTATS, tracedProcess);
                    addr1 = 4 * EBX;
                    break;

                    //accessing file state
                case SYS_lstat:
                    getNulTerminatedData(tracedProcess, callRegisters.ebx, accessedFileName);
                    currAccessNode = getAccessNode(accessedFileName, null, READSTATS, tracedProcess);
                    addr1 = 4 * EBX;
                    break;
            }
            fflush(stdout);
            if (currAccessNode) {
                sprintf(message, "\nAccess Node Created For user: %s\nCurr Dir:%s\nfor files, file1:%s,file2:%s for mode:%d", currAccessNode->userName, currAccessNode->cwd, currAccessNode->fileName1, currAccessNode->fileName2, currAccessNode->mode);
                logI(message);
                fprintf(stdout, "%s", message);
                fflush(stdout);

                if (checkAccess(policy, currAccessNode)) {
                    sprintf(message, "\nACCESS GRANTED :For : %s\nCurr Dir:%s\nfor files, file1:%s,file2:%s for mode:%d", currAccessNode->userName, currAccessNode->cwd, currAccessNode->fileName1, currAccessNode->fileName2, currAccessNode->mode);
                    logI(message);
                } else {
                    denyAccess(addr1, addr2, currAccessNode);
                    sprintf(message, "\nACCESS DENIED: For : %s\nCurr Dir:%s\nfor files, file1:%s,file2:%s for mode:%d", currAccessNode->userName, currAccessNode->cwd, currAccessNode->fileName1, currAccessNode->fileName2, currAccessNode->mode);
                    logI(message);
                }
            }
            callState.in = 0;
        } else {
            callState.in = 1;
            sprintf(message, "Syscall:%ld returned", callRegisters.orig_eax);
            logI(message);
            switch (callRegisters.orig_eax) {
                    //here we need to handle the fork
                case SYS_clone:
                case SYS_fork:
                case SYS_vfork:
                    //Oh Yes.process called fork.
                    //Now fork yourself to handle the child

                    sprintf(message, "\nIn Fork during return:%ld\n", callRegisters.eax);
                    logI(message);
                    fprintf(stdout, "%s", message);
                    fflush(stdout);
                    if (((long) callRegisters.eax) > 0) {
                        temp = callRegisters.eax;
                        ret1[1] = null;
                        itoa(temp, 10, argv[0], ret1);
                        if (argc > 2) {
                            ret1[2] = argv[2];
                        }
                        childPid = fork();
                        if (!childPid) {
                            //INVOKE yourself to handle the newly created process
                            execvp(argv[0], ret1);
                            fprintf(stderr, "\nFATAL: This should never have printed.\n..Unable to create process to trace the newly created process\n");
                            exit(EXE_FAILED);
                        } else {
                            sprintf(message, "Created New Track Process:%d", childPid);
                            logI(message);
                            fprintf(stdout, "%s", message);
                        }
                    }
                    break;

            }
        }

        if (temp = ptrace(PTRACE_SYSCALL, tracedProcess, NULL, NULL)) {
            sprintf(message, "\nProblem during trying to trace process at last:%d\nReturn Code:%d", tracedProcess, temp);
            fprintf(stderr, "%s", message);
            logI(message);
            exit(TRACE_FAILED);
        }
        fflush(stdout);
    }
    ptrace(PTRACE_DETACH, tracedProcess, NULL, NULL);
    return (EXIT_SUCCESS);
}



