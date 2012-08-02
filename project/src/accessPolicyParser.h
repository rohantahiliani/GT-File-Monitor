/* 
 * File:   accessPolicyParser.h
 * Author: machiry
 *
 * Created on March 10, 2012, 5:01 PM
 */

#ifndef ACCESSPOLICYPARSER_H
#define	ACCESSPOLICYPARSER_H

#ifdef	__cplusplus
extern "C" {
#endif
#include "accessPolicy.h"
aclList getAccessList(const char *policyfile);
void freePolicyList(aclList ptr);


#ifdef	__cplusplus
}
#endif

#endif	/* ACCESSPOLICYPARSER_H */

