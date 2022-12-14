#include "RSA.h"
#include "BigInt.h"
#include <cmath>
#include<iostream>
#define RAND_LIMIT32 0x7FFFFFFF
using namespace RSAUtil;

int DD(int argc, char*argv[])
{      /*********************************************************
 * * Простой драйвер
 * *******************************************************
 */
        unsigned long int *a;
        unsigned long int arr[10];
        a=&arr[0];

	BigInt message, cipher, deciphered;
        BigInt pubkey, privatekey;
        BigInt gnm;

        // RSA myRSA = новый RSA(11,13);// не выполняется, поскольку размер N меньше 16 би
      RSA myRSA(102563,102841);
     RSA newrsa;
     // RSA myRSA = новый RSA(11,13);// не выполняется, поскольку размер N меньше 16 бит


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
      // сообщение = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);




  /* шифр = myRSA.encrypt(сообщение);
   расшифровано = myRSA.decrypt(шифрование);
   std::cout<<"message: "<<message.toHexString()<<"\tcipher: "<<cipher.toHexString()<<"\tdeciphered: "<<deciphered.toHexString()<<std::endl;
  */
      return (0);
}

