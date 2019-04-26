#include "Crypto.h"
#include "BigInt.h"
#include "CryptoUtils.h"
#include <iostream>

namespace
{
	//! \brief Defines a default public exponent (e in public key)
	const BigInt DEFAULT_E = BigInt(65537);

	template <typename Buffer1, typename Buffer2>
	bool ValidateBuffers(const Buffer1 input, const Buffer2 output)
	{
		if (input.pData == nullptr || input.size == 0)
			return false;
		else if (output.pData == nullptr || output.size == 0)
			return false;
		else if ((input.pData > output.pData)
			&& ((output.pData + output.size) >= input.pData))
			// Buffers are overlapping
			return false;
		else if ((output.pData > input.pData)
			&& ((input.pData + input.size) >= output.pData))
			// Buffers are overlapping
			return false;
		return true;
	}
}

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

		uint32_t temp = 0;
		BigInt p = CryptoUtils::GenerateRandomPrime(s, temp);
		BigInt q = CryptoUtils::GenerateRandomPrime(s, temp);

		BigInt n = p * q;
		BigInt t = (p - 1) * (q - 1);

		BigInt e = DEFAULT_E;

		uint64_t iters = 0;
		while (t.GreatestCommonDivisor(e, iters) != 1)
		{
			e = e + 1;
			while (!e.IsPrimeNumber())
				e = e + 1;
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

Crypto::CryptoRet Crypto::ExportAsymmetricKeys(AsymmetricKeys* keys,
	const DataOut priv,
	uint16_t* pPrivBytesWritten,
	const DataOut pub,
	uint16_t* pPubBytesWritten)
{
	if (keys == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (pPrivBytesWritten == nullptr || pPubBytesWritten == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!ValidateBuffers(priv, pub))
		return CryptoRet::INVALID_PARAMETER;

	CryptoRet ret = CryptoUtils::WriteKeyToBuffer(keys->pubKey, pub, pPubBytesWritten);
	if (ret == CryptoRet::OK)
	{
		ret = CryptoUtils::WriteKeyToBuffer(keys->privKey, priv, pPrivBytesWritten);
		if (ret != CryptoRet::OK)
		{
			// Clear already written public key
			memset(pub.pData, 0, pub.size);
		}
	}
	return ret;
}

Crypto::CryptoRet Crypto::ImportAsymmetricKeys(AsymmetricKeys* pKeys, const DataIn priv, const DataIn pub)
{
	if (pKeys == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!ValidateBuffers(priv, pub))
		return CryptoRet::INVALID_PARAMETER;

	CryptoRet ret = CryptoRet::OK;
	try
	{
		pKeys->privKey = new PrivateKey();
		pKeys->pubKey = new PublicKey();

		ret = CryptoUtils::ImportKey(pKeys->privKey, priv);
		if (ret == CryptoRet::OK)
		{
			pKeys->keySize = pKeys->privKey->keySize;
			pKeys->pubKey->keySize = pKeys->privKey->keySize;
			ret = CryptoUtils::ImportKey(pKeys->pubKey, pub);
		}
		if (ret == CryptoRet::OK)
			ret = CryptoUtils::ValidateKeys(pKeys);
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

void Crypto::NeededBufferSizeForExport(const KeySize keySize,
	uint16_t* pPrivateKeyBytes,
	uint16_t* pPublicKeyBytes)
{
	if (pPrivateKeyBytes)
		*pPrivateKeyBytes = CryptoUtils::NeededBufferSizePrivate(keySize);
	if (pPublicKeyBytes)
		*pPublicKeyBytes = CryptoUtils::NeededBufferSizePublic(keySize);
}

Crypto::CryptoRet Crypto::Encrypt(const PublicKey* key, const DataIn input, const DataOut output, uint64_t* pEncryptedBytes)
{
	if (key == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!ValidateBuffers(input, output))
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

	Crypto::CryptoRet ret = Crypto::CryptoRet::INTERNAL_ERROR;

	if (inPlace)
	{
		// TODO
		ret = Crypto::CryptoRet::INTERNAL_ERROR;
	}
	else
	{
		auto remainingData = input.size;
		for (auto i = 0; i < blockCount; ++i)
		{
			const auto size = uint16_t(remainingData > blockSizePlain ? blockSizePlain : remainingData);
			auto src = input.pData + (blockSizePlain * i);
			auto dst = output.pData + (blockSizeEncrypted * i);
			ret = CryptoUtils::EncryptBlock(*key,
				DataIn(src, size),
				DataOut(dst, blockSizeEncrypted),
				pEncryptedBytes);

			if (ret != Crypto::CryptoRet::OK)
			{
				*pEncryptedBytes = 0;
				break;
			}

			remainingData -= blockSizePlain;
		}
	}

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet Crypto::Decrypt(const PrivateKey* key, const DataIn input, const DataOut output, uint64_t* pDecryptedBytes)
{
	if (key == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!ValidateBuffers(input, output))
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

	Crypto::CryptoRet ret = Crypto::CryptoRet::INTERNAL_ERROR;
	if (inPlace)
	{
		// TODO
		ret = Crypto::CryptoRet::INTERNAL_ERROR;
	}
	else
	{
		for (auto i = 0; i < blockCount; ++i)
		{
			auto src = input.pData + (blockSizeEncrypted * i);
			auto dst = output.pData + (blockSizePlain * i);
			ret = CryptoUtils::DecryptBlock(*key,
				DataIn(src, blockSizeEncrypted),
				DataOut(dst, blockSizePlain),
				pDecryptedBytes);

			if (ret != Crypto::CryptoRet::OK)
			{
				*pDecryptedBytes = 0;
				break;
			}
		}
	}
	return ret;
}

uint16_t Crypto::GetBlockSizeEncrypted(const KeySize keySize)
{
	uint16_t ret = 0;
	CryptoUtils::BlockSize(keySize, nullptr, &ret);
	return ret;
}

uint16_t Crypto::GetBlockSizePlain(const KeySize keySize)
{
	uint16_t ret = 0;
	CryptoUtils::BlockSize(keySize, &ret, nullptr);
	return ret;
}

uint64_t Crypto::GetBlockCountEncryption(const KeySize keySize, const uint64_t dataSizePlain)
{
	const auto blockSize = GetBlockSizePlain(keySize);
	if (blockSize == 0)
		return 0;

	return (dataSizePlain / blockSize) + (dataSizePlain / blockSize) > 0 ? 1 : 0;
}

uint64_t Crypto::GetBlockCountDecryption(const KeySize keySize, const uint64_t dataSizeEncrypted)
{
	const auto blockSize = GetBlockSizePlain(keySize);
	if (blockSize == 0)
		return 0;
	else if ((dataSizeEncrypted % blockSize) != 0)
		return 0;

	return dataSizeEncrypted / blockSize;
}

uint64_t Crypto::GetBufferSizeEncryption(const KeySize keySize, const uint64_t dataSizePlain)
{
	return GetBlockCountEncryption(keySize, dataSizePlain) * GetBlockSizeEncrypted(keySize);
}

uint64_t Crypto::GetBufferSizeDecryption(const KeySize keySize, const uint64_t dataSizeEncrypted)
{
	return GetBlockCountEncryption(keySize, dataSizeEncrypted) * GetBlockSizeEncrypted(keySize);
}
