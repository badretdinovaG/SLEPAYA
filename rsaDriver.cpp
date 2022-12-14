#include "RSA.h"
#include "BigInt.h"
#include <cmath>
#include<iostream>
#define RAND_LIMIT32 0x7FFFFFFF
using namespace RSAUtil;

int ff(int argc, char*argv[]){      /*********************************************************
     * ������� �������
 * *******************************************************
 */
     unsigned long int *a;
     unsigned long int arr[4];
     a=&arr[0];

       RSA myRSA;
	BigInt message, cipher, deciphered;

       message = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
       message.toULong(a,4);
       cipher = myRSA.encrypt(message);
       deciphered = myRSA.decrypt(cipher);
       std::cout<<*a<<std::endl;
       // std::cout<<"��������� "<<message.toString();
std::cout<<"message: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<std::endl;
return 0;
}


