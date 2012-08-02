#include "commonHeaders.h"
#include "accessControl.h"
#include "helper.h"
#include "accessPolicy.h"

static Ainfo createNewNode();

Ainfo getAccessNode(const char *file1, const char *file2, int mode, pid_t pid) {
    Ainfo node = createNewNode();
    node->cwd = getCWDFromPid(pid);
    node->userName = getEUserFromPid(pid);
    node->groupName = getEGroupFromPid(pid);
    node->fileOwner = getFileOwner(file1);
    if (file1[0] == '/') {
        node->fileName1 = (char*) malloc((strlen(file1) + 1) * sizeof (char));
        strcpy(node->fileName1, file1);
    } else {
        node->fileName1 = (char*) malloc((strlen(node->cwd) + strlen(file1) + 2) * sizeof (char));
        strcpy(node->fileName1, node->cwd);
        strcat(node->fileName1, "/");
        strcat(node->fileName1, file1);
    }

    //Not every access node has file2
    if (file2) {
        if (file2[0] == '/') {
            node->fileName2 = (char*) malloc((strlen(file2) + 1) * sizeof (char));
            strcpy(node->fileName2, file2);
        } else {
            node->fileName2 = (char*) malloc((strlen(node->cwd) + strlen(file2) + 2) * sizeof (char));
            strcpy(node->fileName2, node->cwd);
            strcat(node->fileName2, "/");
            strcat(node->fileName2, file2);
        }
    }
    node->mode = mode;

    node->pid = pid;
    return node;
}

static Ainfo createNewNode() {
    Ainfo node = (Ainfo) malloc(sizeof (AinfoNode));
    node->fileName1 = null;
    node->fileName2 = null;
    node->mode = defMode;
    node->userName = null;
    node->cwd = null;
    node->groupName = null;
    node->fileOwner = null;
    node->pid = -1;
    return node;
}

void freeANode(Ainfo node) {
    if (node) {
        if (node->fileName1) {
            free(node->fileName1);
            node->fileName1 = null;
        }
        if (node->fileName2) {
            free(node->fileName2);
            node->fileName2 = null;
        }
        if (node->userName) {
            free(node->userName);
            node->userName = null;
        }
        if (node->cwd) {
            free(node->cwd);
            node->cwd = null;
        }
        if (node->groupName) {
            free(node->groupName);
            node->groupName = null;
        }
        if(node->fileOwner) {
            free(node->fileOwner);
            node->fileOwner = null;
        }
        node->pid = -1;
    }
}

int denyAccess(long addr1, long addr2, Ainfo node) {
    //Set the user data to null
    //the file anchored should be null
    if (node->fileName1) {
        ptrace(PTRACE_POKEUSER, node->pid, addr1, 0);
    }
    if (node->fileName2) {
        ptrace(PTRACE_POKEUSER, node->pid, addr2, 0);
    }
}

int checkAccess(aclList policy, Ainfo node) {
    //This is the main heart of the code
    //where we enforce the access policy 
    //on the accessed file

    //BUG1: if the file path contains some unexpanded environment variables
    //how to get those? those will be defined in the context of the tracked process

    //BUG2: we are assuming all relative paths to be resolved with respect to CWD, this might not be true
    //if $PATH comes in to play
    uint allow = 1;
    char *temp = null;
    uint entryPresent = 0;
    uint modeSet = 0;
    ulong longestMatchingEntry=0;
    ulong targetMode = 0;
    if (policy) {
        policyPtr currAcl = policy->front;
        while (currAcl != null) {
            if (temp = strstr(node->fileName1, currAcl->fileName)) {
                printf("\nFound Matching:%s\n", currAcl->fileName);
                if (temp == node->fileName1) {
                    //Same file is being accessed so enforce the AP as it is
                    if (!strcmp(node->fileName1, currAcl->fileName)) {
                        
                        if (currAcl->allow) {
                            entryPresent = 1;
                            longestMatchingEntry = strlen(currAcl->fileName);
                        }
                        if (stringPresent(currAcl->users, currAcl->noOfUsers, node->userName) || stringPresent(currAcl->groups, currAcl->noOfGroups, node->groupName)) {
                            targetMode = currAcl->mode;
                            if (targetMode & node->mode) {
                                allow = currAcl->allow;
                                modeSet = 1;
                            }
                            else if(currAcl->allow){
                                allow = 0;
                            }
                                
                        }
                    } else if (isDirectory(currAcl->fileName) && (!(currAcl->allow) || (strlen(currAcl->fileName) > longestMatchingEntry))) {
                        printf("\nDirMatch\n");
                        printf("\nTarget FileNAme:%s\n", node->fileName1);
                        if (node->fileName1[strlen(currAcl->fileName)] == '/') {
                            
                            printf("\nRequested Mode:%u,ACL Mode:%lu\n", node->mode, currAcl->mode);
                            //the user is trying to access a file which is in a folder monitored by the access control
                            if (currAcl->allow) {
                                entryPresent = 1;
                                longestMatchingEntry = strlen(currAcl->fileName);
                            }
                            if (stringPresent(currAcl->groups, currAcl->noOfGroups, node->groupName) || stringPresent(currAcl->users, currAcl->noOfUsers, node->userName)) {
                                targetMode = currAcl->mode;
                                if (targetMode & node->mode) {
                                    allow = currAcl->allow;
                                    modeSet = 1;
                                }
                                else if(currAcl->allow){
                                    allow = 0;
                                }
                            }
                        }
                    }
                }
            }
            if (!allow) {
                break;
            }
            currAcl = currAcl->next;
        }
        if (entryPresent && !modeSet) {
            allow = 0;
        }
    }
    fflush(stdout);
    return allow;
}



