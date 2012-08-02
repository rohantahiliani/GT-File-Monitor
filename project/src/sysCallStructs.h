/* 
 * File:   sysCallStructs.h
 * Author: machiry
 *
 * Created on February 26, 2012, 2:35 AM
 */

#ifndef SYSCALLSTRUCTS_H
#define	SYSCALLSTRUCTS_H

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct sysCallState{
        int in;
        unsigned long callNo;
    } sysState;


#ifdef	__cplusplus
}
#endif

#endif	/* SYSCALLSTRUCTS_H */

