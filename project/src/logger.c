#include "commonHeaders.h"

static FILE* logger = null;
void logI(const char *message) {
    if (logger) {
        fprintf(logger, "\n%s", message);
        fflush(logger);
    } else {
        fprintf(stderr, "\nFATAL: Trying to log with our setting the environment\nMessage:%s\n", message);
        fflush(stderr);
    }
}

void displayExitMessage(const char *message) {
    char mess[MCHAR];
    sprintf(mess, "\n Exiting monitor\nReason:%s\n", message);
    fprintf(stdout,"%s",mess);
    logI(mess);
    fflush(stdout);
}

void setEnvironment(int mypid) {
    char logName[MCHAR];
    sprintf(logName, "traceLog_%d.txt", mypid);
    logger = fopen(logName, "w");
    if (!logger) {
        printf("\nFATAL:unable to create the logfile:%s\nSo Using Stdout\n", logName);
        logger = stdout;
    }
}

void closeLog(){
     if (logger != null) {
        fflush(logger);
        fclose(logger);
        logger = null;
    }    
}