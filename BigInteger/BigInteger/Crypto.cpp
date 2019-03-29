#include "pch.h"
#include "Crypto.h"
#include "BigInt.h"
#include <iostream>

namespace
{
	// !\brief Encrypted data contains the actual byte count in the block
	// !\details Byte count is written before actual data.
	const uint8_t BLOCK_SIZE_BYTES = 2;

	const uint64_t BlockSize(const Crypto::KeySize keySize)
	{
		switch (keySize)
		{
		case Crypto::KeySize::KS_1024:
			return 128;
		default:
			return 0;
			break;
		}
	}
}

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

Crypto::CryptoRet Crypto::CreateAsymmetricKeys(const KeySize s, AsymmetricKeys* pKeys)
{
	if (pKeys == nullptr)
		return CryptoRet::INVALID_PARAMETER;

	CryptoRet ret = CryptoRet::OK;
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

		ret = CryptoRet::OK;
	}
	catch (const std::invalid_argument& e)
	{
		ret = CryptoRet::INTERNAL_ERROR;
		// TODO: log the error
	}
	catch (const std::logic_error& e)
	{
		ret = CryptoRet::INTERNAL_ERROR;
		// TODO: log the error
	}
	catch (const std::bad_alloc& e)
	{
		ret = CryptoRet::INSUFFICIENT_RESOURCES;
		// TODO: log the error
	}
	catch (...)
	{
		ret = CryptoRet::INTERNAL_ERROR;
		// TODO: log the error
	}

	if (ret != CryptoRet::OK)
	{
		delete pKeys->privKey;
		pKeys->privKey = nullptr;
		delete pKeys->pubKey;
		pKeys->pubKey = nullptr;
	}
	return ret;
}

Crypto::CryptoRet Crypto::DeleteAsymmetricKeys(AsymmetricKeys* keys)
{
	if (keys == nullptr)
		return CryptoRet::INVALID_PARAMETER;

	delete keys->privKey;
	keys->privKey = nullptr;
	delete keys->pubKey;
	keys->pubKey = nullptr;
	
	return CryptoRet::OK;
}

Crypto::CryptoRet Crypto::Encrypt(const PublicKey* key, const Data input, const Data output, uint64_t* pEncryptedBytes)
{
	if (key == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (input.pData == nullptr || input.size == 0)
		return CryptoRet::INVALID_PARAMETER;
	else if (output.pData == nullptr || output.size == 0)
		return CryptoRet::INVALID_PARAMETER;
	else if (pEncryptedBytes == nullptr)
		return CryptoRet::INVALID_PARAMETER;

	const bool inPlace = input.pData == output.pData;

	// BlockSize : ((KeySize / 8) - 2)
	// BlockCount : ceil(input.size / BlockSize)
	// NeededBufferSize : BlockCount * (KeySize / 8)

	const auto blockSize = BlockSize(key->keySize) - 2;
	const auto blockCount = (input.size / blockSize) + ((input.size % blockSize) > 0 ? 1 : 0);
	const auto neededBuffer = blockCount * BlockSize(key->keySize);
	if (neededBuffer > output.size)
		return CryptoRet::INSUFFICIENT_BUFFER;


	return Crypto::CryptoRet::INTERNAL_ERROR;
}

Crypto::CryptoRet Crypto::Decrypt(const PrivateKey* key, const Data input, const Data output, uint64_t* pDecryptedBytes)
{
	return Crypto::CryptoRet::INTERNAL_ERROR;
}
