#include "Crypto.h"
#include "BigInt.h"
#include "CryptoUtils.h"
#include "TaskManager.h"
#include <iostream>
#include <functional>

namespace
{
	//! \brief Defines a default public exponent (e in public key)
	const BigInt DEFAULT_E(65537);

	template <typename Buffer1, typename Buffer2>
	bool ValidateBuffers(const Buffer1 input, const Buffer2 output)
	{
		if (input.pData == nullptr || input.size == 0U)
			return false;
		else if (output.pData == nullptr || output.size == 0U)
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
	: pubKey(nullptr)
	, privKey(nullptr)
	, keySize(KeySize::KS_1024) {}

Crypto::DataIn::DataIn(const char* data, const uint64_t s)
	: pData(data)
	, size(s) {}

Crypto::DataOut::DataOut(char* data, const uint64_t s)
	: pData(data)
	, size(s) {}

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

		uint32_t temp = 0U;
		BigInt p = CryptoUtils::GenerateRandomPrime(s, temp);
		BigInt q = CryptoUtils::GenerateRandomPrime(s, temp);

		BigInt n = p * q;
		BigInt t = (p - 1U) * (q - 1U);

		BigInt e = DEFAULT_E;

		uint64_t iters = 0U;
		while (t.GreatestCommonDivisor(e, iters) != 1U)
		{
			e = e + 1U;
			while (!e.IsPrimeNumber())
				e = e + 1U;
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
		std::cerr << "std::invalid_argument occured: " << e.what() << std::endl;
	}
	catch (const std::logic_error& e)
	{
		ret = CryptoRet::INTERNAL_ERROR;
		std::cerr << "std::logic_error occured: " << e.what() << std::endl;
	}
	catch (const std::bad_alloc& e)
	{
		ret = CryptoRet::INSUFFICIENT_RESOURCES;
		std::cerr << "std::bad_alloc occured: " << e.what() << std::endl;
	}
	catch (...)
	{
		ret = CryptoRet::INTERNAL_ERROR;
		std::cerr << "Unknown exception occured" << std::endl;
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
			memset(pub.pData, 0U, pub.size);
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
		std::cerr << "std::invalid_argument occured: " << e.what() << std::endl;
	}
	catch (const std::logic_error& e)
	{
		ret = CryptoRet::INTERNAL_ERROR;
		std::cerr << "std::logic_error occured: " << e.what() << std::endl;
	}
	catch (const std::bad_alloc& e)
	{
		ret = CryptoRet::INSUFFICIENT_RESOURCES;
		std::cerr << "std::bad_alloc occured: " << e.what() << std::endl;
	}
	catch (...)
	{
		ret = CryptoRet::INTERNAL_ERROR;
		std::cerr << "Unknown exception occured" << std::endl;
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

	uint16_t blockSizePlain = 0U;
	uint16_t blockSizeEncrypted = 0U;
	CryptoUtils::BlockSize(key->keySize, &blockSizePlain, &blockSizeEncrypted);
	const auto blockCount = (input.size / blockSizePlain) + ((input.size % blockSizePlain) > 0U ? 1U : 0U);
	const auto neededBuffer = blockCount * blockSizeEncrypted;
	if (neededBuffer > output.size)
		return CryptoRet::INSUFFICIENT_BUFFER;

	Crypto::CryptoRet ret = Crypto::CryptoRet::OK;

	if (inPlace)
	{
		// TODO
		ret = Crypto::CryptoRet::INTERNAL_ERROR;
	}
#ifdef USE_THREADS
	else
	{
		std::atomic<uint64_t> remainingData = input.size;
		std::atomic<uint64_t> block = 0U;
		std::atomic<uint64_t> encrypted = 0U;
		auto pBlock = &block;
		auto pRet = &ret;
		auto pRemainingData = &remainingData;
		auto pBytes = &encrypted;
		auto EncryptFunc = [pBlock, pRet, pBytes, pRemainingData,
			input, output, blockCount,
			blockSizeEncrypted, blockSizePlain, key]()
		{
			while (*pRet == Crypto::CryptoRet::OK)
			{
				auto i = (*pBlock)++;
				if (i >= blockCount)
					break;

				uint64_t encryptedBytes = 0U;
				const auto remainingData = pRemainingData->fetch_sub(blockSizePlain);
				const auto size = uint16_t(remainingData > blockSizePlain ? blockSizePlain : remainingData);
				auto src = input.pData + (blockSizePlain * i);
				auto dst = output.pData + (blockSizeEncrypted * i);
				auto ret = CryptoUtils::EncryptBlock(*key,
					DataIn(src, size),
					DataOut(dst, blockSizeEncrypted),
					&encryptedBytes);

				if (ret == Crypto::CryptoRet::OK)
				{
					*pBytes += encryptedBytes;
				}
				else
				{
					*pRet = ret;
					break;
				}

				//*pRemainingData -= blockSizePlain;
			}
		};

		TaskManager::ExecuteFunction(EncryptFunc);

		if (ret == CryptoRet::OK)
			*pEncryptedBytes = encrypted;
	}
#else
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
#endif

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

	uint16_t blockSizePlain = 0U;
	uint16_t blockSizeEncrypted = 0U;
	CryptoUtils::BlockSize(key->keySize, &blockSizePlain, &blockSizeEncrypted);
	const auto blockCount = (input.size / blockSizeEncrypted) + ((input.size % blockSizeEncrypted) > 0 ? 1 : 0);
	const auto neededBuffer = blockCount * blockSizePlain;
	if (neededBuffer > output.size)
		return CryptoRet::INSUFFICIENT_BUFFER;

	Crypto::CryptoRet ret = Crypto::CryptoRet::OK;
	if (inPlace)
	{
		// TODO
		ret = Crypto::CryptoRet::INTERNAL_ERROR;
	}
#ifdef USE_THREADS
	else
	{
		std::atomic<uint64_t> block = 0U;
		std::atomic<uint64_t> decrypted = 0U;
		auto pBlock = &block;
		auto pRet = &ret;
		auto pBytes = &decrypted;
		auto DecryptFunc = [pBlock, pRet, pBytes, input, output, blockCount, blockSizeEncrypted, blockSizePlain, key]()
		{
			while (*pRet == Crypto::CryptoRet::OK)
			{
				auto i = (*pBlock)++;
				if (i >= blockCount)
					break;

				uint64_t bytes = 0U;
				auto src = input.pData + (blockSizeEncrypted * i);
				auto dst = output.pData + (blockSizePlain * i);
				auto ret = CryptoUtils::DecryptBlock(*key,
					DataIn(src, blockSizeEncrypted),
					DataOut(dst, blockSizePlain),
					&bytes);

				if (ret == Crypto::CryptoRet::OK)
				{
					*pBytes += bytes;
				}
				else
				{
					*pRet = ret;
					break;
				}
			}
		};

		TaskManager::ExecuteFunction(DecryptFunc);

		if (ret == CryptoRet::OK)
			*pDecryptedBytes = decrypted;
	}
#else
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
#endif
	return ret;
}

uint16_t Crypto::GetBlockSizeEncrypted(const KeySize keySize)
{
	uint16_t ret = 0U;
	CryptoUtils::BlockSize(keySize, nullptr, &ret);
	return ret;
}

uint16_t Crypto::GetBlockSizePlain(const KeySize keySize)
{
	uint16_t ret = 0U;
	CryptoUtils::BlockSize(keySize, &ret, nullptr);
	return ret;
}

uint64_t Crypto::GetBlockCountEncryption(const KeySize keySize, const uint64_t dataSizePlain)
{
	const auto blockSize = GetBlockSizePlain(keySize);
	if (blockSize == 0U)
		return 0U;

	return (dataSizePlain / blockSize) + (dataSizePlain / blockSize) > 0U ? 1U : 0U;
}

uint64_t Crypto::GetBlockCountDecryption(const KeySize keySize, const uint64_t dataSizeEncrypted)
{
	const auto blockSize = GetBlockSizePlain(keySize);
	if (blockSize == 0U)
		return 0U;
	else if ((dataSizeEncrypted % blockSize) != 0U)
		return 0U;

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
