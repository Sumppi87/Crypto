#include "pch.h"
#include "Crypto.h"
#include "BigInt.h"
#include <iostream>
#include "CryptoUtils.h"

Crypto::AsymmetricKeys::AsymmetricKeys()
	: privKey(nullptr)
	, pubKey(nullptr)
	, keySize(KeySize::KS_1024) {}

Crypto::CryptoRet Crypto::CreateAsymmetricKeys(const KeySize s, AsymmetricKeys* pKeys)
{
	if (pKeys == nullptr)
		return CryptoRet::INVALID_PARAMETER;

	CryptoRet ret = CryptoRet::OK;
	try
	{
		pKeys->privKey = new PrivateKey();
		pKeys->pubKey = new PublicKey();
		pKeys->keySize = s;

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

Crypto::CryptoRet Crypto::Encrypt(const PublicKey* key, const DataIn input, const DataOut output, uint64_t* pEncryptedBytes)
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

	uint16_t blockSizePlain = 0;
	uint16_t blockSizeEncrypted = 0;
	CryptoUtils::BlockSize(key->keySize, &blockSizePlain, &blockSizeEncrypted);
	const auto blockCount = (input.size / blockSizePlain) + ((input.size % blockSizePlain) > 0 ? 1 : 0);
	const auto neededBuffer = blockCount * blockSizeEncrypted;
	if (neededBuffer > output.size)
		return CryptoRet::INSUFFICIENT_BUFFER;

	if (inPlace)
	{
		// TODO
		return Crypto::CryptoRet::INTERNAL_ERROR;
	}
	else
	{
		auto remainingData = input.size;
		for (auto i = 0; i < blockCount; ++i)
		{
			const auto size = uint16_t(remainingData > blockSizePlain ? blockSizePlain : remainingData);
			CryptoUtils::EncryptBlock(*key,
				DataIn(input.pData + (blockSizePlain * i), size),
				DataOut(output.pData + (blockSizeEncrypted * i), blockSizeEncrypted),
				pEncryptedBytes);

			remainingData -= blockSizePlain;
		}
	}

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet Crypto::Decrypt(const PrivateKey* key, const DataIn input, const DataOut output, uint64_t* pDecryptedBytes)
{
	if (key == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (input.pData == nullptr || input.size == 0)
		return CryptoRet::INVALID_PARAMETER;
	else if (output.pData == nullptr || output.size == 0)
		return CryptoRet::INVALID_PARAMETER;
	else if (pDecryptedBytes == nullptr)
		return CryptoRet::INVALID_PARAMETER;

	const bool inPlace = input.pData == output.pData;

	// BlockSize : ((KeySize / 8) - 2)
	// BlockCount : ceil(input.size / BlockSize)
	// NeededBufferSize : BlockCount * (KeySize / 8)

	uint16_t blockSizePlain = 0;
	uint16_t blockSizeEncrypted = 0;
	CryptoUtils::BlockSize(key->keySize, &blockSizePlain, &blockSizeEncrypted);
	const auto blockCount = (input.size / blockSizeEncrypted) + ((input.size % blockSizeEncrypted) > 0 ? 1 : 0);
	const auto neededBuffer = blockCount * blockSizePlain;
	if (neededBuffer > output.size)
		return CryptoRet::INSUFFICIENT_BUFFER;

	if (inPlace)
	{
		// TODO
		return Crypto::CryptoRet::INTERNAL_ERROR;
	}
	else
	{
		for (auto i = 0; i < blockCount; ++i)
		{
			CryptoUtils::DecryptBlock(*key,
				DataIn(input.pData + (blockSizeEncrypted * i), blockSizeEncrypted),
				DataOut(output.pData + (blockSizePlain * i), blockSizePlain),
				pDecryptedBytes);
		}
	}
	return Crypto::CryptoRet::OK;
}
