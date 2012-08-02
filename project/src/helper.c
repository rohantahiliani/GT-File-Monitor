#include "commonHeaders.h"
#include "accessMode.h"
#include <sys/stat.h>

char* getUserNameFromId(uint uid) {
    char* user = null;
    char command[MCHAR];
    char delimiter = ':';
    uint usrNameLen = 0;
    int i = 0;
    sprintf(command, "getent passwd %d", uid);
    FILE *fp = popen(command, "r");
    if (fp) {
        if ((fscanf(fp, "%s", command)) != EOF) {
            for (i = 0; i < strlen(command); i++) {
                if (command[i] == delimiter) {
                    usrNameLen = i;
                    break;
                }
            }
            user = (char*) malloc((usrNameLen + 1) * sizeof (char));
            strncpy(user, command, usrNameLen);
            user[usrNameLen] = 0;
            fclose(fp);
        }
    }
    return user;
}

char* getFileOwner(const char *filename){
    struct stat info;
    if(filename && !stat(filename, &info)){
        char *owner = getUserNameFromId(info.st_uid);
        return owner;
    }
    return null;
}

long getUserIDFromName(const char *name) {
    char command[MCHAR];
    long userID = -1;
    sprintf(command, "id -u %s", name);
    FILE *fp = popen(command, "r");
    if (fp) {
        if ((fscanf(fp, "%ld", &userID)) != EOF) {
        } else {
            userID = -1;
        }
        fclose(fp);
    }
    return userID;
}

char* getgroupIDFromName(const char *name) {
    char command[MCHAR];
    char *groupID = null;
    sprintf(command, "id -n -g %s", name);
    FILE *fp = popen(command, "r");
    if (fp) {
        if ((fscanf(fp, "%s", command)) != EOF) {
            groupID = (char*)malloc(sizeof(char)*(strlen(command)+1));
            strcpy(groupID,command);
        } else {
            groupID = null;
        }
        fclose(fp);
    }
    return groupID;
}

char** getgroupMembershipFromName(const char *name, ulong *noOfGps) {
    char command[MCHAR];
    ulong noOfGroups = 0;
    char **membership = null;
    ulong i = 0;
    sprintf(command, "id -G %s|wc -w", name);
    FILE *fp = popen(command, "r");
    if (fp) {
        if ((fscanf(fp, "%ld", &noOfGroups)) != EOF) {
        } else {
            noOfGroups = 0;
        }
        fclose(fp);
    }
    if (noOfGroups > 0) {
        sprintf(command, "id -n -G %s", name);
        fp = popen(command, "r");
        if (fp) {
            membership = (char**) malloc(sizeof(char*) * noOfGroups);
            for (i = 0; i < noOfGroups; i++) {
                if ((fscanf(fp, "%s", command)) != EOF) {
                    membership[i] = (char*)malloc(sizeof(char)*(strlen(command)+1));
                    strcpy(membership[i],command);
                } else {
                    ulong j=0;
                    for(j=0;j<i;j++){
                        free(membership[j]);
                    }
                    free(membership);
                    membership = null;
                    break;
                }
            }
            fclose(fp);
        }
    }
    if(noOfGps){
        if(!membership){
            *noOfGps = 0;
        }
        else{
            *noOfGps = noOfGroups;
        }
    }
    return membership;
}

char* getEUserFromPid(pid_t pid) {
    char* user = null;
    char command[MCHAR];
    char delimiter = ' ';
    uint usrNameLen = 0;
    int i = 0;
    sprintf(command, "ps -f p %d", pid);
    FILE *fp = popen(command, "r");
    if (fp) {
        if (fgets(command, MCHAR - 1, fp) && fgets(command, MCHAR - 1, fp)) {
            for (i = 0; i < strlen(command); i++) {
                if (command[i] == delimiter || command[i] == '\t') {
                    usrNameLen = i;
                    break;
                }
            }
            user = (char*) malloc((usrNameLen + 1) * sizeof (char));
            strncpy(user, command, usrNameLen);
            user[usrNameLen] = '\0';
        }
        fclose(fp);
    }
    return user;
}

char* getEGroupFromPid(pid_t pid) {
    char* group = null;
    char command[MCHAR];
    sprintf(command, "ps -p %d -o group --no-heading", pid);
    FILE *fp = popen(command, "r");
    if (fp) {
        if (fscanf(fp,"%s",command) != EOF) {
            group = (char*) malloc((strlen(command) + 1) * sizeof (char));
            strcpy(group, command);
        }
        fclose(fp);
    }
    return group;
}

int isDirectory(char *fileName){
    int isDir = 0;
    char command[MCHAR];
    sprintf(command, "stat -c %%F %s", fileName);
    FILE *fp = popen(command, "r");
    if (fp) {
        if (fscanf(fp,"%s",command) != EOF) {
            if(!strcmp(command,"directory")){
                isDir = 1;
            }
        }
        fclose(fp);
    }
    return isDir;
}

int stringPresent(char **list,ulong len,char *target){
    ulong i=0;
    for(i=0;i<len;i++){
        if(!strcmp(list[i],target)){
            return 1;
        }
    }
    return 0;
}

char* getCWDFromPid(pid_t pid) {
    char* cwd = NULL;
    char command[MCHAR];
    char delimiter = ':';
    uint usrNameLen = 0;
    int i = 0;
    sprintf(command, "pwdx %d", pid);
    FILE *fp = popen(command, "r");
    if (fp) {
        if (fgets(command, MCHAR - 1, fp)) {
            for (i = 0; i < strlen(command); i++) {
                if (command[i] == delimiter) {
                    usrNameLen = i + 2;
                    break;
                }
            }
            cwd = (char*) malloc((strlen(command)-(usrNameLen) + 1) * sizeof (char));
            strncpy(cwd, command + usrNameLen, strlen(command)-(usrNameLen));
            cwd[strlen(command)-(usrNameLen) - 1] = '\0';
        }
        fclose(fp);
    }
    return cwd;

}

enum ACCESSMODE getAccessMode(unsigned long mode) {
    enum ACCESSMODE targetMode = READ;
    if ((mode & O_RDWR) || (mode & O_WRONLY)) {
        targetMode = WRITE;
    }
    return targetMode;
}
