#include "hpwd.hh"

//---------------------------
// Initialization Code
//---------------------------

void initialize_user(string user, string password)
{
	fstream file;
	char *data;
	string key;
	string it_path="/usr/hpwd/data/"+user+".itt";
	string ht_path="/usr/hpwd/data/"+user+".htt";

	//Insert User
	file.open("/usr/hpwd/users",ios::out|ios::app);
	file<<user<<endl;
	file.close();

	//Create and Encrypt IT
	createIT(user, it_path);

	data=new char[1024];
	file.open(it_path.c_str(),ios::in);
	file.read(data,1024);
	file.close();

	encryptFile(it_path, data, password);

	//Create and Encrypt HT
	cout<<"Initial Hpwd: "<<f_poly[0]<<endl;

	data=new char[1024];
	data[0]='H';data[1]='T';data[2]='\n';
	for(int i=3;i<h_size;i++) data[i]='\n';

	encryptFile(ht_path, data, bigIntegerToString(BigInteger(f_poly[0])));
}

void createIT(string user, string path)
{
	fstream file;

	//Create I Table
	file.open(path.c_str(),ios::out|ios::app);
	BigInteger alpha[n_features],beta[n_features];
	srand(time(0));
	for(int i=0;i<n_features-1;i++) f_poly[i]=rand();
	file<<"IT"<<endl;
	//for(int i=0;i<n_features;i++) cout<<"FPoly: "<<i<<" "<<f_poly[i]<<endl;
	for(int i=1;i<n_features;i++)
	{
		alpha[i] = y_poly(2*i) + stringToBigInteger(g_prf(2*i)) % q_prime;
		beta[i] = y_poly(2*i+1) + stringToBigInteger(g_prf((2*i)+1)) % q_prime;
		file<<alpha[i]<<endl<<beta[i]<<endl;
	}
	file.close();
}

//---------------------------
// Initialization Ends
//---------------------------

