#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux-x86
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/main.o \
	${OBJECTDIR}/logger.o \
	${OBJECTDIR}/policyParser.o \
	${OBJECTDIR}/accessControl.o \
	${OBJECTDIR}/helper.o


# C Compiler Flags
CFLAGS=-lxml2 -lmcrypt

# CC Compiler Flags
CCFLAGS=-lxml2 -lmcrypt
CXXFLAGS=-lxml2 -lmcrypt

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=hpwd.a

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/gtfmon

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/gtfmon: hpwd.a

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/gtfmon: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/gtfmon ${OBJECTFILES} ${LDLIBSOPTIONS} 

${OBJECTDIR}/main.o: main.cpp 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.cc) -O2 -I/usr/include/libxml2 -MMD -MP -MF $@.d -o ${OBJECTDIR}/main.o main.cpp

${OBJECTDIR}/logger.o: logger.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.c) -O2 -I/usr/include/libxml2 -MMD -MP -MF $@.d -o ${OBJECTDIR}/logger.o logger.c

${OBJECTDIR}/policyParser.o: policyParser.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.c) -O2 -I/usr/include/libxml2 -MMD -MP -MF $@.d -o ${OBJECTDIR}/policyParser.o policyParser.c

${OBJECTDIR}/accessControl.o: accessControl.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.c) -O2 -I/usr/include/libxml2 -MMD -MP -MF $@.d -o ${OBJECTDIR}/accessControl.o accessControl.c

${OBJECTDIR}/helper.o: helper.c 
	${MKDIR} -p ${OBJECTDIR}
	${RM} $@.d
	$(COMPILE.c) -O2 -I/usr/include/libxml2 -MMD -MP -MF $@.d -o ${OBJECTDIR}/helper.o helper.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}
	${RM} ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/gtfmon

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
