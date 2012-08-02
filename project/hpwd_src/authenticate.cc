#include "hpwd.hh"

//---------------------------
// Authenticate User
//---------------------------

bool authenticate_user(string user, string password)
{
	cout<<user<<endl;
	q_prime = stringToBigInteger("1136521230147434397082989483913415651105316240019");
	if(!user_exists(user))
	{
		initialize_user(user, password);
		return true;
	}
	else return validate(user,password);
}

bool user_exists(string user)
{
	fstream file;
	file.open("/usr/hpwd/users",ios::in);
	while(file.good())
	{
		string valid;
		file>>valid;
		if(valid==user)
		{
			file.close();
			return true;
		}
	}
	return false;
}

//---------------------------
// User Authentication Ends
//---------------------------

