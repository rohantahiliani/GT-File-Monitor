/* 
 * File:   logger.h
 * Author: machiry
 *
 * Created on March 10, 2012, 11:29 AM
 */

#ifndef LOGGER_H
#define	LOGGER_H

#ifdef	__cplusplus
extern "C" {
#endif
#include "commonHeaders.h"
    void logI(const char *message);
    void displayExitMessage(const char *message);
    void setEnvironment(int mypid);
    void closeLog();



#ifdef	__cplusplus
}
#endif

#endif	/* LOGGER_H */

