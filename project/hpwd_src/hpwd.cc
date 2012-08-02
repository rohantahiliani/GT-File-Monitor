#include "hpwd.hh"

//---------------------------
// Verify Login
//---------------------------

bool validate(string user, string password)
{
	fstream file;

	int phi[n_features];
	BigInteger alpha[n_features],beta[n_features],x[n_features],y[n_features];
	BigInteger hpwd_dash=0;
	string read;
	string it_path="/usr/hpwd/data/"+user+".itt";
	string ht_path="/usr/hpwd/data/"+user+".htt";
	string fv_path="/usr/hpwd/data/"+user+".test";
	stringstream dec_data;

	cout<<"Validating "<<user<<" "<<endl;

	//Decrypt Instruction Table
	char* data;
	data=new char[1024];
	decryptFile(it_path, data, password);
	dec_data<<data; dec_data>>read;
	if(read!="IT")
	{
		cout<<"Invalid password. Could not decrypt instruction table."<<endl;
		return false;
	}
	
	//Read Feature Vector
	readFV(fv_path, phi);

	//Read Alpha Beta values from IT
	for(int i=1;i<n_features;i++) 
	{
		dec_data<<data; dec_data>>read;
		alpha[i]=stringToBigInteger(read);

		dec_data<<data; dec_data>>read;
		beta[i]=stringToBigInteger(read);
	}
	file.close();

	//Calculate Hardened Password
	hpwd_dash = calculateHpwd(phi, alpha, beta);

	//Verfiy Hardened Password and accordingly update files if required
	hpwd_dash=verifyHpwd(ht_path, hpwd_dash);
	if(hpwd_dash>=0)
	{
		updateHT(ht_path, phi, hpwd_dash);
		updateIT(ht_path, it_path, hpwd_dash, password);
		return true;
	}
	else
	{
		cout<<"Failed to validate hardened password."<<endl;
		return false;
	}
}

void readFV(string path, int* phi)
{
	fstream file;
	int i=1,iter;
	string temp;

	//Read Feature vector
	srand(time(0));
	iter=rand()%11;
	file.open(path.c_str(),ios::in);
	while(i++<iter) getline(file,temp);
	for(int i=0;i<n_features;i++) file>>phi[i];
	file.close();
}

BigInteger calculateHpwd(int* phi, BigInteger* alpha, BigInteger* beta)
{
	BigInteger hpwd_dash=0,lam,bot;
	BigInteger x[n_features],y[n_features];
	BigInteger vec[n_features][n_features];

	//Calculate x,y depending on value of phi
	for(int i=1;i<n_features;i++)
	{
		if(phi[i]<threshold)
		{
			x[i] = 2*i;
			y[i] = alpha[i] - stringToBigInteger(g_prf(2*i)) % q_prime;
			//cout<<"Alpha "<<x[i]<<" "<<y[i]<<endl;
		}
		else
		{
			x[i] = 2*i+1;
			y[i] = beta[i] - stringToBigInteger(g_prf(2*i+1)) % q_prime;
			//cout<<"Beta "<<x[i]<<" "<<y[i]<<" "<<endl;
		}
	}

	//Calculate differences for efficiency
	for(int i=1;i<n_features;i++)
		for(int j=1;j<n_features;j++)
			vec[i][j]=(i==j)?1:(x[j]-x[i]);

	//Calculate Hpwd'
	for(int i=1;i<n_features;i++)
	{
		lam=1,bot=1;
		for(int j=1;j<n_features;j++) if(i!=j)lam=lam*x[j];
		for(int j=1;j<n_features;j++) if(i!=j)bot=bot*(vec[i][j]);
		lam = lam * y[i];
		lam = lam / bot;
		if(lam%bot>0) lam++;
		hpwd_dash = hpwd_dash + lam;
	}
	return hpwd_dash;
}

BigInteger verifyHpwd(string ht_path, BigInteger hpwd_dash)
{
	//Decrypt and verify HT
	bool cake=false;
	char* data;
	for(int i=-5;i<=5 && !cake;i++)
	{
		data=new char[1024];
		decryptFile(ht_path, data, bigIntegerToString(hpwd_dash+i));
		if(data[0]='H' && data[1]=='T' && data[2]=='\n')
		{
			hpwd_dash+=i;
			cout<<"Valid hardened password: "<<hpwd_dash<<endl;
			cake=true;
			return hpwd_dash;
		}
	}
	return -1;
}

void updateHT(string path, int* phi, BigInteger hpwd)
{
	char* data;
	data=new char[1024];	
	fstream file, out;
	string read;

	decryptFile(path, data, bigIntegerToString(hpwd));

	out.open(path.c_str(), ios::out);
	out<<"HT"<<endl;

	file.open("/usr/hpwd/temp",ios::out);
	file.write(&data[0], 1024);
	file.close();

	file.open("/usr/hpwd/temp",ios::in);
	//Insert new feature vector
	for(int i=0; i<n_features; i++) out<<phi[i]<<" ";
	out<<endl;
	getline(file,read);
	//Insert h_size-1 previous values
	for(int i=0; i<h_size-1; i++)
	{
		getline(file, read);
		out<<read<<endl;
	}
	file.close();
	out.close();
	remove("/usr/hpwd/temp");

	file.open(path.c_str(),ios::in);
	data=new char[1024];
	file.read(data,1024);
	file.close();
	//Print history file
	//cout<<data<<endl;
}

void updateIT(string ht_path, string it_path, BigInteger hpwd, string password)
{
	BigInteger alpha[n_features],beta[n_features];
	int avg[n_features];
	char* data;
	data=new char[1024];	
	fstream file;
	string read;
	int i, temp;
	bool cake=true;

	file.open(ht_path.c_str(), ios::in);
	getline(file,read);
	//Get values from HT
	for(i=0;i<n_features;i++) avg[i]=0;
	for(i=0;i<h_size && cake;i++)
	{
		temp=-1;
		file>>temp;
		if(temp==-1) cake=false;
		else
		{
			avg[0]+=temp;
			for(int j=1;j<n_features;j++) {file>>temp;avg[j]+=temp;}
		}
	}
	file.close();
	if(i>(h_size-2))
	{
		//Calculate average vector
		i--;
		for(int j=0;j<n_features;j++) avg[j]/=i;

		//Generate new random polynomial
		srand(time(0));
		for(i=0;i<n_features-1;i++) f_poly[i]=rand();

		//Create new IT file
		file.open(it_path.c_str(),ios::out);
		file<<"IT"<<endl;

		for(i=1;i<n_features;i++)
		{
			//Update based on average
			alpha[i] = y_poly(2*i) + stringToBigInteger(g_prf(2*i)) % q_prime;
			beta[i] = y_poly(2*i+1) + stringToBigInteger(g_prf((2*i)+1)) % q_prime;
			if(avg[i]<threshold) beta[i] += rand() + 1;
			else alpha[i] += rand() + 1;
			file<<alpha[i]<<endl<<beta[i]<<endl;
		}
		file.close();
		//Get new hpwd
		hpwd=f_poly[0];
		cout<<"New hpwd: "<<hpwd<<endl;

		//Write to file and encrypt IT
		data=new char[1024];
		file.open(it_path.c_str(),ios::in);
		file.read(data,1024);
		file.close();	
		encryptFile(it_path, data, password);
	}
	//Encrypt HT file
	data=new char[1024];
	file.open(ht_path.c_str(),ios::in);
	file.read(data,1024);
	file.close();
	encryptFile(ht_path, data, bigIntegerToString(hpwd));	
}

//---------------------------
// Login Verification Ends
//---------------------------

