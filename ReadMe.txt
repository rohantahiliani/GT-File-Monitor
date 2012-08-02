Dependency:
	Our project depends on the following libraraies and headers, these needs to be present on the system for the project to	compile.
	Libraries:
	
		lxml2 
		lmcrypt
	Headers:
		/usr/include/libxml2

Compiling:
	Browse to [extractDir]/project/src
	Run: ./build.sh

Running:
	Copy the file : [extractDir]/project/hpwd_files/rohan.test to /usr/hpwd/data
	This need to be run with root privilages because of obvious reasons.
	Browse to: [extractDir]/project/src
	Run:
		Usage ./gtfilemon <pid_of_ftpdeamon> [policyFileName] 
	
			policyFileName: this has to be absolute path to the file
				that contains the access policy information
			if no policy file is specified default value is policy.xml in CWD


Disclaimer:
	We ran and tested our code on Ubuntu 10.04 LTS x86 system.As this is the latest and stable version of ubuntu available.
	Since Ubuntu 11.04 there has been changes made to ptrace implementation so we are not sure our code in present form will run on  latest platform.
		More details : refer man page of ptrace by : man ptrace

