/* 
 * File:   helper.h
 * Author: machiry
 *
 * Created on March 4, 2012, 12:21 AM
 */

#ifndef HELPER_H
#define	HELPER_H

#ifdef	__cplusplus
extern "C" {
#endif
#include "accessControl.h"
char* getUserNameFromId(uint uid);
char* getEUserFromPid(pid_t pid);
enum ACCESSMODE  getAccessMode(int mode);
char* getCWDFromPid(pid_t pid);
char* getEGroupFromPid(pid_t pid);
int isDirectory(char *fileName);
int stringPresent(char **list,ulong len,char *target);
char* getFileOwner(const char *filename);

#ifdef	__cplusplus
}
#endif

#endif	/* HELPER_H */

