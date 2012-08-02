/* 
 * File:   accessControl.h
 * Author: machiry
 *
 * Created on February 26, 2012, 3:49 PM
 */

#ifndef ACCESSCONTROL_H
#define	ACCESSCONTROL_H

#ifdef	__cplusplus
extern "C" {
#endif

  
#include "accessMode.h"
#include "accessPolicy.h"
#define defMode 0
    typedef struct accessInfo{
        char *fileName1;
        char *fileName2;
        char *userName;
        char *cwd;
        int pid;
        char *groupName;
        char *fileOwner;
        enum ACCESSMODE mode;
    } AinfoNode,*Ainfo;

    void freeANode(Ainfo node);
    
    Ainfo getAccessNode(const char *file1,const char *file2,int mode,pid_t pid);
    int denyAccess(long addr1,long addr2,Ainfo node);
    int checkAccess(aclList policy,Ainfo node);
#ifdef	__cplusplus
}
#endif

#endif	/* ACCESSCONTROL_H */

