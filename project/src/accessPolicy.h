/* 
 * File:   accessPolicy.h
 * Author: machiry
 *
 * Created on March 10, 2012, 5:01 PM
 */

#ifndef ACCESSPOLICY_H
#define	ACCESSPOLICY_H

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct policyElement{
        char **groups;
        char **users;
        char *fileName;
        ulong noOfUsers;
        ulong noOfGroups;
        ulong mode;
        uint allow;
        struct policyElement *next;
    } policyNode,*policyPtr;
    
    typedef struct accessList{
        policyPtr front;
        policyPtr last;
        ulong count;
    } accessListNode,*aclList;



#ifdef	__cplusplus
}
#endif

#endif	/* ACCESSPOLICY_H */

