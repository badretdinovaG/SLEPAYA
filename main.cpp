

#include <stdio.h> 
#include <stdlib.h> 
#include <array>
#include <iostream>
#include <random>
#include <cmath>
#include "RSA.h"
#include "BigInt.h"

#define RAND_LIMIT32 0x7FFFFFFF

using namespace RSAUtil;
using namespace std;

int main(int argc, char *argv[])
{
	
	cout<<"Blind Signature";

	/*
	Шаг 01: Алиса получает открытый ключ и модуль N человека (Боба), который должен подписать сообщени
	*/
	RSA Bob;

	//cout<<"\Открытый ключ (N): "<<Bob.getModulus().toHexString();
	//cout<<"\Открытый ключ (E): "<<Bob.getPublicKey().toHexString();

	/*
	 Шаг 02: получаем случайное число и его обратное по отношению к модулю [Не phi] Боба
	*/
	srand(time(0));
	BigInt random = std::rand();
	//printf("\nRandom: %x",ранд);
	cout<<"\nRandom Number: "<<random.toHexString();

	// Шаг 03: Алиса получает / генерирует сообщение для подписи.

	BigInt message = (rand()%RAND_LIMIT32);

	//printf("\nMessage: %x",сообщение);
	cout<<"\nMessage: "<<message.toHexString();

	/*
	 Шаг 04: Алиса шифрует случайное число с помощью открытого ключа. 
 Шаг 05: Алиса умножает это значение на сообщение.
 Шаг 06: затем Алиса принимает модуль над N
	*/
	
	RSA *rsa_bob = &Bob;
	BigInt after_mul = (rsa_bob->encrypt(random) * message) % rsa_bob->getModulus();

	cout<<"\nAfter Multiplied: "<<after_mul.toHexString();

	/*
	 Шаг 07: Алиса отправляет его Бобу
 Шаг 08: Боб просто расшифровывает полученное значение с помощью закрытого ключа
	*/
	BigInt blind_sig = Bob.decrypt(after_mul);
	// printf("Слепая подпись: %x", blind_sig);
	cout<<"\nBlind signature: "<<blind_sig.toHexString();


	/*
	Шаг 09: Боб отправляет его обратно Алисе
 Шаг 10: Затем Алиса умножает полученное значение на обратное и принимает модуль над N.
	*/
	BigInt sig = (blind_sig * modInverse(random, Bob.getModulus())) % Bob.getModulus();
	//printf("\nSignature: %x",sig);
	cout<<"\nSignature: "<<sig.toHexString();


	/*
	 Шаг 11: Чтобы получить от него исходное сообщение, снова зашифруйте его с помощью открытого ключа Боба.
	*/
	cout<<"\nVerify: "<<message.toHexString()<<" & "<<Bob.encrypt(sig).toHexString();
	//printf("\nVerify: %x & %x",message,sig);
	
	cout<<"\n";
	return 0;
}
