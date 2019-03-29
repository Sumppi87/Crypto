#include "pch.h"
#include "Crypto.h"
#include "BigInt.h"
#include <iostream>

struct Crypto::PublicKey
{
	BigInt e;
	BigInt n;
	
	Crypto::KeySize keySize;
};

struct Crypto::PrivateKey
{
	BigInt d;
	BigInt n;

	Crypto::KeySize keySize;
};

Crypto::AsymmetricKeys::AsymmetricKeys()
	: privKey(nullptr)
	, pubKey(nullptr) {}

bool Crypto::CreateAsymmetricKeys(const KeySize s, AsymmetricKeys* pKeys)
{
	// TODO: Enumerate return value

	if (pKeys == nullptr)
		return false;

	try
	{
		pKeys->privKey = new PrivateKey();
		pKeys->pubKey = new PublicKey();

		// TODO: Generate random primes
		BigInt p("12131072439211271897323671531612440428472427633701410925634549312301964373042085619324197365322416866541017057361365214171711713797974299334871062829803541");
		BigInt q("12027524255478748885956220793734512128733387803682075433653899983955179850988797899869146900809131611153346817050832096022160146366346391812470987105415233");

		BigInt n = p * q;
		BigInt t = (p - 1) * (q - 1);

		BigInt e(65537);
		uint64_t iters = 0;
		while (n.GreatestCommonDivisor(e, iters) != 1)
		{
			e = e + 1;
			std::cout << "Booboo" << std::endl;
		}

		BigInt d = e.ModuloMultiplicativeInverse(t);

		// private-key(d, n)
		pKeys->privKey->n = n;
		pKeys->privKey->d = d;
		pKeys->privKey->keySize = s;
		// public-key(e, n)
		pKeys->pubKey->n = n;
		pKeys->pubKey->e = e;
		pKeys->pubKey->keySize = s;

		return true;
	}
	catch (const std::invalid_argument& e)
	{
		// TODO: log the error
	}
	catch (const std::logic_error& e)
	{
		// TODO: log the error
	}
	catch (const std::bad_alloc& e)
	{
		// TODO: log the error
	}
	catch (...)
	{
		// TODO: log the error
	}

	delete pKeys->privKey;
	pKeys->privKey = nullptr;
	delete pKeys->pubKey;
	pKeys->pubKey = nullptr;
	return false;
}

bool Crypto::DeleteAsymmetricKeys(AsymmetricKeys* keys)
{
	if (keys == nullptr)
		return false;

	delete keys->privKey;
	keys->privKey = nullptr;
	delete keys->pubKey;
	keys->pubKey = nullptr;
	
	return true;
}

bool Crypto::Encrypt(const PublicKey* key, const Data input, const Data output, uint64_t* pEncryptedBytes)
{
	return false;
}

bool Crypto::Decrypt(const PrivateKey* key, const Data input, const Data output, uint64_t* pDecryptedBytes)
{
	return false;
}
