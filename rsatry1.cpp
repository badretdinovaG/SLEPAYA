#include "RSA.h"
#include "BigInt.h"
#include <cmath>
#include<iostream>
#define RAND_LIMIT32 0x7FFFFFFF
using namespace RSAUtil;

int DD(int argc, char*argv[])
{      /*********************************************************
 * * ������� �������
 * *******************************************************
 */
        unsigned long int *a;
        unsigned long int arr[10];
        a=&arr[0];

	BigInt message, cipher, deciphered;
        BigInt pubkey, privatekey;
        BigInt gnm;

        // RSA myRSA = ����� RSA(11,13);// �� �����������, ��������� ������ N ������ 16 ��
      RSA myRSA(102563,102841);
     RSA newrsa;
     // RSA myRSA = ����� RSA(11,13);// �� �����������, ��������� ������ N ������ 16 ���


       pubkey= myRSA.getPublicKey();
       privatekey = myRSA.getPrivateKey();
       std::cout<<"Public Key ";
       pubkey.toULong(a,4);
       std::cout<<*a<<std::endl;

       privatekey.toULong(a,4);
       std::cout<<"Private Key : "<<*a<<std::endl;



      gnm = myRSA.getModulus();
       std::cout<<"N  in old is"<<gnm.toHexString()<<std::endl;

       newrsa.setN(gnm);
       newrsa.setPublicKey(myRSA.getPublicKey());
      gnm = newrsa.getModulus();
       std::cout<<"N  in new is"<<gnm.toHexString()<<std::endl;
       std::cout<<"Old Pub Key "<<pubkey.toHexString()<<std::endl;
       pubkey= newrsa.getPublicKey();
       std::cout<<"New Pub Key "<<pubkey.toHexString();

      message = 1000;
      // ��������� = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);




  /* ���� = myRSA.encrypt(���������);
   ������������ = myRSA.decrypt(����������);
   std::cout<<"message: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<std::endl;
  */
      return (0);
}

