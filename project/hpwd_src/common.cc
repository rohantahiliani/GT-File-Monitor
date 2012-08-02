#include "hpwd.hh"

BigInteger q_prime;
const int h_size=20;
const int n_features=8;
const int threshold=5;
int f_poly[8];

string g_prf(int val)
{
	stringstream skey;
	skey<<val;
	int length=skey.str().length();

	SHA1 sha;
	sha.Reset();
	char buffer[length];
	sprintf(buffer,"%d",val);
	sha.Input(buffer,length);
	unsigned digest[5];
	sha.Result(digest);
	string result;
	for(int i=0;i<5;i++)
	{
		memset(&buffer[0],0,sizeof(buffer));
		sprintf(buffer,"%u",digest[i]);
		result.append(buffer);
	}
	return result;
}

BigInteger y_poly(int val)
{
	BigInteger value=val;
	BigInteger ret=f_poly[0];
	for(int i=1;i<8;i++)
	{
		ret+=(value*f_poly[i]);
		value*=val;
	}
	return ret;
}

bool crypt_module(char* data, char* key, int length, int mode)
{
	char iv[]  = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	
	MCRYPT td=mcrypt_module_open(MCRYPT_RIJNDAEL_128,0,MCRYPT_CBC,0);
	if(td==MCRYPT_FAILED) return 0;
	if(mcrypt_generic_init(td,key,length,iv)<0) return 0;
	if(mode==CRYPT_ENCRYPT) {if(mcrypt_generic(td,data,1024)) return 0;}
	else if(mode==CRYPT_DECRYPT) {if(mdecrypt_generic(td,data,1024)) return 0;}
	if(mcrypt_generic_end(td)<0) return 0;
	return 1;
}


bool encryptFile(string path, char* data, string password)
{
	fstream file;
	if(crypt_module(data, (char*)password.c_str(), password.length(), CRYPT_ENCRYPT)){
		cout<<path<<" Encrypted"<<endl;
		file.open(path.c_str(),ios::out|ios::binary);
		file.write(&data[0],1024);
		file.close();
		return true;
	}
	else cout<<"Error encrypting "<<path<<endl;
	return false;
}

bool decryptFile(string path, char* data, string password)
{
	fstream file;
	file.open(path.c_str(),ios::in|ios::binary);
	file.read(data,1024);
	file.close();

	if(crypt_module(data, (char*)password.c_str(), password.length(), CRYPT_DECRYPT)) return true;
	else cout<<"Error decrypting "<<path<<endl;
	return false;
}
