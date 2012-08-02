#include <iostream>
#include <string>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mcrypt.h>

#include "BigIntegerLibrary.hh"
#include "sha1.hh"

#define CRYPT_ENCRYPT 1
#define CRYPT_DECRYPT 0

using namespace std;

extern BigInteger q_prime;
extern const int h_size;
extern const int n_features;
extern const int threshold;
extern int f_poly[];

//Common Functions
string g_prf(int);
BigInteger y_poly(int);
bool crypt_module(char*, char*, int, int);
bool encryptFile(string, char*, string);
bool decryptFile(string, char*, string);

//Hpwd functions
bool authenticate_user(string, string);
bool user_exists(string);
void initialize_user(string, string);
bool validate(string, string);

void createIT(string, string);
void readFV(string, int*);
BigInteger calculateHpwd(int*, BigInteger*, BigInteger*);
BigInteger verifyHpwd(string, BigInteger);
void updateIT(string, string, BigInteger, string);
void updateHT(string, int*, BigInteger);

