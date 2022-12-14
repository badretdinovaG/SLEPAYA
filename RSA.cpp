#include "RSA.h"
#include "BigInt.h"
#include <cstdlib>
#include <cmath>
#include <limits>
#include <iostream>
#include <ctime>



namespace RSAUtil
{
	#define A_MAX 25
	#define RAND_LIMIT 0xFFFF
	
	
RSA::RSA(int p1, int q1){
	RSA::e = 0;
	RSA::d = 0;
	RSA::p = p1;
	RSA::q = q1;
	
	srand(time(0));
	RSA::n = BigInt(RSA::p)*BigInt(RSA::q);
	RSA::phi = BigInt(((RSA::p)-1))*BigInt(((RSA::q)-1));
}

RSA::RSA(int p1){
	bool isP;
	RSA::e = 0;
	RSA::d = 0;
	RSA::p = p1;
	
	srand(time(0));
	

	// Найдите q, которое является простым и не равно p. Сначала проверьте, что p!= q 

	do{ 
		RSA::q = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT);
		//set the low bit and high bit.
		RSA::q = RSA::q | 0x10001;
		isP = isPrime(RSA::q);
	
	}while((RSA::p==RSA::q) || !isP);
	
	
	RSA::n = BigInt(RSA::p)*BigInt(RSA::q);
	RSA::phi = BigInt(((RSA::p)-1))*BigInt(((RSA::q)-1));
	
}

RSA::RSA()
{
	bool isP;
	RSA::e = 0;
	RSA::d = 0;
	

	//найти p & q, s.t. p!=q && p и q оба простые.
	
	srand(time(0));
	
	
	do{	
		RSA::p = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT);
	
		// Установите младший бит (для нечетности) и старший бит (чтобы убедиться, что он достаточно большой).
		RSA::p = RSA::p | 0x10001;
		isP = isPrime(RSA::p);
	}while(!isP);
	
	
	// Найдите q, которое является простым и не равно p. Проверьте, что p!=q сначала, так как
	//это более простая проверка.
	do{ 
		RSA::q = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT);
		//установите младший бит и старший бит.
		RSA::q = RSA::q | 0x10001;
		isP = isPrime(RSA::q);
	
	}while((RSA::p==RSA::q) || !isP);
	
	
	RSA::n = BigInt(RSA::p)*BigInt(RSA::q);
	RSA::phi = BigInt(((RSA::p)-1))*BigInt(((RSA::q)-1));
}

RSA::~RSA()
{
}
void RSA::setPublicKey(unsigned int pubKey){
	RSA::e = pubKey;
}


void RSA::setN(BigInt B)
{
RSA::n = B;

}



void RSA::setPublicKey(BigInt B)
{
RSA::e = B;
}





int RSA::getP() const{
	return RSA::p;
}
int RSA::getQ() const{
	return RSA::q;
}

BigInt RSA::getPublicKey(){
	// Если e не было установлено, вычислите e, o / w просто верните его.
	if(RSA::e.isZero()){
		calcE();
	}
	return RSA::e;
}

BigInt RSA::getPrivateKey(){
	//Если d не был установлен, вычислите d, o / w просто верните его.
	if(RSA::d.isZero()){
		calcD();
	}
	return RSA::d;
}

BigInt RSA::getPHI() const{
	return RSA::phi;
}
BigInt RSA::getModulus() const{
	return RSA::n;
}

//вычисляет m^e mod n
BigInt RSA::encrypt(BigInt msg){
	BigInt cipher;
	
	if(RSA::e.isZero()){
		calcE();
	}
	cipher = RSAUtil::modPow(msg, RSA::e, RSA::n);
	return cipher;
}

//вычисляет c^ d mod n
BigInt RSA::decrypt(BigInt cipher){
	BigInt message;
	if(RSA::d.isZero()){
		calcD();
	}

	//Выполнить расшифровку
	message = RSAUtil::modPow(cipher, RSA::d, RSA::n);
	
	return message;
}

/** тестовый код от raghu */

/* конец тестового кода*/


	
void RSA::calcE(){
	
	//Найти e такое, что 1 < e < PHI, а e является относительно простым для PHI
	BigInt r;
	unsigned int high, low;
	bool done = false;
	BigInt tempPhi;
	tempPhi = RSA::phi;
	
	while(!done){
		// необходимо сгенерировать 32-34-битное случайное число. 
		// генерировать 32-битное случайное число.
		// добавить 33-й бит. либо 0,1, либо 2.
		low = int(((double)std::rand()/RAND_MAX)*0xFFFFFFFF);
		high = int(((double)std::rand()/RAND_MAX)*0x02);
		r = BigInt(high,low);

		//Убедитесь, что r находится в середине 2/3 PHI.
		if((r>(RSA::phi/6)) && r<((RSA::phi/6)*5) ){
			r |= 0x01;
			done = (gcd(RSA::phi, r) == 1);
		}
	}//завершить цикл во время выполнения.

	RSA::e = r;
}


void RSA::calcD(){

	//Найти d такое, что de = 1 (mod PHI). d существует, если e и PHI являются относительно простыми.
	BigInt response;
	
	if(RSA::e.isZero()){
		calcE();
	}
	
	response = modInverse(RSA::e, RSA::phi);
	RSA::d = response;
}



// Составное тестирование.
bool isPrime(int p){
	
	bool isP;
	//Проверьте, делится ли оно на малое простое число.
	isP = isPrimeDiv(p);
	// Если это не так, проверьте простоту с помощью алгоритма Миллера-Рабина.
	if(isP){
		isP = isPrimeMR(p);
	}
	return isP;
		
}


bool isPrimeMR(int p){
	
	unsigned int a, b, m, j, tempPow2, pow2;
	bool maybePrime = true;
	BigInt z;
	
	// Простая проверка. 
	if(p == 2){
		return true;
	}
	
	// Проверьте наличие четных чисел. 
	if(!(p & 0x1)){
		return false;
	}
	
	// Вычислить m таким образом, чтобы p = 1 + (pow2*m), где pow2 - наибольшая мощность
// из 2, который делит p-1.
	pow2 = 1;
	tempPow2 = 2;
	b = 0;
	while((p-1)%tempPow2 == 0){
		b++;
		pow2 = tempPow2;
		// умножить на 2.
		tempPow2 = tempPow2 << 1;
	}
	
	m = (p-1)/pow2;
	
	int iter = 0;
		while(iter < 5 && maybePrime){
			// a должно быть меньше p.
			do{
		a = int(((double)std::rand()/RAND_MAX)* A_MAX);
			}while(a >= p);
		if(a==0 || a==1){
			a = 2;
		}
	
		j = 0;
		z = RSAUtil::modPow(BigInt(a), BigInt(m), BigInt(p));
	
		if(z==1 || z==(p-1)){
			// p проходит. это может быть простым.
			maybePrime = true;
		}else{
		
		j++;
	
		while(j<b && !(z==(p-1)) && !(z==1)){
			z = modPow(z, (unsigned int)2, (unsigned int)p);
			j++;
		}
		if(z == 1){
			//p не является простым.
			maybePrime = false;
		}
		else if(j == b && !(z == (p-1))){
			//p не является простым.
			maybePrime = false;
		}
		if(z == (p-1)){
			// p может быть простым.
			maybePrime = true;  
		}
		}
		iter ++;
	}//завершить цикл во время выполнения
	
	return maybePrime;
	
}

bool isPrimeDiv(int p){
	// Проверить все простые числа <256.
		// используйте колесо для генерации первых 2000 простых чисел. 
	
	bool response = true;
	int primes[] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251};
	int plength = sizeof(primes)/sizeof(int);
	
		for(int i = 0; i < plength; i++){
		if(p%primes[i] == 0){
			response = false;
			break;
		}
	}
	return response;
}


int gcd(int i, int j){
	if(j == 0){
		return i;
	}
	else{
		return gcd(j, i%j);
	}
	
}

BigInt gcd(BigInt i, BigInt j){
	if(j==0){
		return i;
	}
	else{
		return gcd(j, i%j);
	}
	
}

//расширенный алгоритм Евклида. Найти b s.t. ab = 1 mod m
BigInt modInverse(BigInt a, BigInt m){
	bool neg = false;
	BigInt b;
	BigInt u1,u2,u3,v1,v2,v3,t1,t2,t3,q;
	u1 = 1;
	u2 = 0;
	u3 = m;
	
	v1 = 0;
	v2 = 1;
	v3 = a;
	
	
	while(!((u3%v3).isZero())){
		q = (u3/v3);
		t1 = u1 - (q*v1);
		t2 = u2 - (q*v2);
		t3 = u3 - (q*v3);
		u1 = v1;
		u2 = v2;
		u3 = v3;
		v1 = t1;
		v2 = t2;
		v3 = t3;
		
	}
	
	// v2 является отрицательным
	if (v2[BIGINT_SIZE-1]==1){
		//возьмите комп 2
		v2.flip();
		v2 = v2+1;
		neg = true;
	}
	
	b = v2%m;
	if(neg){
		b = m-b;
	}
	
return b;
}

}
