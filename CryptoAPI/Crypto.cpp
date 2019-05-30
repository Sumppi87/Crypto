#include "Crypto.h"
#include "BigInt.h"
#include "CryptoUtils.h"
#include "TaskManager.h"
#include "SHA3.h"
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

inline Crypto::SHA3_Length GetHashLength(const Crypto::KeySize keysize)
{
	Crypto::SHA3_Length ret = Crypto::SHA3_Length::SHA3_512;
	switch (keysize)
	{
	case Crypto::KeySize::KS_256:
		ret = Crypto::SHA3_Length::SHA3_224;
		break;
	case Crypto::KeySize::KS_512:
		ret = Crypto::SHA3_Length::SHA3_384;
		break;
	case Crypto::KeySize::KS_1024:
	case Crypto::KeySize::KS_2048:
	case Crypto::KeySize::KS_3072:
	case Crypto::KeySize::KS_4096:
		ret = Crypto::SHA3_Length::SHA3_512;
		break;
	default:
		break;
	}
	return ret;
}

inline bool IsValidKeySize(const Crypto::KeySize k)
{
	bool isValid = false;
	switch (k)
	{
	case Crypto::KeySize::KS_256:
	case Crypto::KeySize::KS_512:
	case Crypto::KeySize::KS_1024:
	case Crypto::KeySize::KS_2048:
	case Crypto::KeySize::KS_3072:
	case Crypto::KeySize::KS_4096:
		isValid = true;
		break;
	default:
		break;
	}
	return isValid;
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
	else if (!IsValidKeySize(s))
		return CryptoRet::INVALID_PARAMETER;

	CryptoRet ret = CryptoRet::OK;
	try
	{
		pKeys->privKey = new _PrivateKey();
		pKeys->pubKey = new _PublicKey();
		pKeys->keySize = s;

		BigInt p = CryptoUtils::GenerateRandomPrime(s);
		BigInt q = CryptoUtils::GenerateRandomPrime(s);

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

	DeleteKey(&keys->privKey);
	DeleteKey(&keys->pubKey);

	return CryptoRet::OK;
}

Crypto::CryptoRet Crypto::DeleteKey(PublicKey* publicKey)
{
	if (publicKey == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	delete *publicKey;
	*publicKey = nullptr;
	return CryptoRet::OK;
}

Crypto::CryptoRet Crypto::DeleteKey(PrivateKey* privateKey)
{
	if (privateKey == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	delete *privateKey;
	*privateKey = nullptr;
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
	else if (!IsValidKeySize(keys->keySize))
		return CryptoRet::INVALID_PARAMETER;

	CryptoRet ret = CryptoUtils::WriteKeyToBuffer(keys->pubKey, pub, pPubBytesWritten);
	if (ret == CryptoRet::OK)
	{
		ret = CryptoUtils::WriteKeyToBuffer(keys->privKey, priv, pPrivBytesWritten);
		if (ret != CryptoRet::OK)
		{
			// Clear already written public key
			memset(pub.pData, 0U, pub.size);
			*pPubBytesWritten = 0;
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

	CryptoRet ret = ImportKey(&pKeys->privKey, priv);
	if (ret == CryptoRet::OK)
		ret = ImportKey(&pKeys->pubKey, pub);

	if (ret == CryptoRet::OK)
	{
		pKeys->keySize = pKeys->privKey->keySize;
		ret = CryptoUtils::ValidateKeys(pKeys);
	}

	if (ret != CryptoRet::OK)
	{
		DeleteKey(&pKeys->privKey);
		DeleteKey(&pKeys->pubKey);
	}
	return ret;
}

Crypto::CryptoRet Crypto::ImportKey(PublicKey* pPublicKey, const DataIn pubData)
{
	if (pPublicKey == nullptr)
		return CryptoRet::INVALID_PARAMETER;

	CryptoRet ret = CryptoRet::OK;
	try
	{
		if (*pPublicKey == nullptr)
			*pPublicKey = new _PublicKey();

		ret = CryptoUtils::ImportKey(*pPublicKey, pubData);
		if (ret == CryptoRet::OK)
			ret = CryptoUtils::ValidateKey(*pPublicKey);
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
		delete *pPublicKey;
		*pPublicKey = nullptr;
	}

	return ret;
}

Crypto::CryptoRet Crypto::ImportKey(PrivateKey* pPrivateKey, const DataIn privData)
{
	if (pPrivateKey == nullptr)
		return CryptoRet::INVALID_PARAMETER;

	CryptoRet ret = CryptoRet::OK;
	try
	{
		if (*pPrivateKey == nullptr)
			*pPrivateKey = new _PrivateKey();

		ret = CryptoUtils::ImportKey(*pPrivateKey, privData);
		if (ret == CryptoRet::OK)
			ret = CryptoUtils::ValidateKey(*pPrivateKey);
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
		delete *pPrivateKey;
		*pPrivateKey = nullptr;
	}

	return ret;
}

void Crypto::SetThreadCount(const uint32_t maxThreads)
{
#if defined(USE_THREADS)
	const auto max = std::thread::hardware_concurrency();
	if (maxThreads > max)
		TaskManager::THREADS = max;
	else if (maxThreads < 1)
		TaskManager::THREADS = 1;
	else
		TaskManager::THREADS = maxThreads;
#endif
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

Crypto::CryptoRet Crypto::Encrypt(const PublicKey key, const DataIn input, const DataOut output, uint64_t* pEncryptedBytes)
{
	if (key == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!ValidateBuffers(input, output))
		return CryptoRet::INVALID_PARAMETER;
	else if (pEncryptedBytes == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!IsValidKeySize(key->keySize))
		return CryptoRet::INVALID_PARAMETER;

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

#ifdef USE_THREADS
	const bool inPlace = input.pData == output.pData;
	if (!inPlace)
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
				auto ret = CryptoUtils::EncryptBlock(key,
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
			}
		};

		TaskManager::ExecuteFunction(EncryptFunc);

		if (ret == CryptoRet::OK)
			*pEncryptedBytes = encrypted;
	}
	else // In-place encryption cannot be threaded
#endif
	{
		auto remainingData = input.size;
		for (auto i = blockCount - 1;;)
		{
			const auto size = (remainingData % blockSizePlain) == 0 ? blockSizePlain : (remainingData % blockSizePlain);
			auto src = input.pData + (blockSizePlain * i);
			auto dst = output.pData + (blockSizeEncrypted * i);
			ret = CryptoUtils::EncryptBlock(key,
				DataIn(src, size),
				DataOut(dst, blockSizeEncrypted),
				pEncryptedBytes);

			if (ret != Crypto::CryptoRet::OK)
			{
				*pEncryptedBytes = 0;
				break;
			}

			remainingData -= size;

			if (i > 0)
				--i;
			else
				break;
		}
	}

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet Crypto::Decrypt(const PrivateKey key, const DataIn input, const DataOut output, uint64_t* pDecryptedBytes)
{
	if (key == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!ValidateBuffers(input, output))
		return CryptoRet::INVALID_PARAMETER;
	else if (pDecryptedBytes == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!IsValidKeySize(key->keySize))
		return CryptoRet::INVALID_PARAMETER;

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
#ifdef USE_THREADS
	const bool inPlace = input.pData == output.pData;
	if (!inPlace)
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
				auto ret = CryptoUtils::DecryptBlock(key,
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
	else // In-place decryption cannot be threaded
#endif
	{
		for (size_t i = 0; i < blockCount; ++i)
		{
			auto src = input.pData + (blockSizeEncrypted * i);
			auto dst = output.pData + (blockSizePlain * i);
			ret = CryptoUtils::DecryptBlock(key,
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

	return (dataSizePlain / blockSize) + (dataSizePlain % blockSize) > 0U ? 1U : 0U;
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

uint64_t Crypto::GetBufferSizeForSignature(const KeySize keySize)
{
	return GetBufferSizeEncryption(keySize, static_cast<uint8_t>(GetHashLength(keySize)));
}

Crypto::CryptoRet Crypto::CreateSignature(PrivateKey key,
	std::ifstream& dataStream,
	const DataOut signature)
{
	if (key == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (signature.pData == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!IsValidKeySize(key->keySize))
		return CryptoRet::INVALID_PARAMETER;

	const SHA3_Length hashLength = GetHashLength(key->keySize);
	const uint8_t hashBytes = static_cast<uint8_t>(hashLength);

	uint16_t blockSize = 0U;
	CryptoUtils::BlockSize(key->keySize, nullptr, &blockSize);

	if (blockSize > signature.size)
		return CryptoRet::INSUFFICIENT_BUFFER;

	CryptoRet ret = CryptoRet::OK;
	try
	{
		// Create a hash from the data
		char hashBuffer[64]{}; // 64B is enough for all SHA3 lengths
		SHA3::SHA3Hasher hasher;
		hasher.Process(hashLength, dataStream, hashBuffer);

		// Encrypt the data with private key
		ret = CryptoUtils::CreateSignature(key, DataIn(hashBuffer, hashBytes), signature);
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
	return ret;
}

Crypto::CryptoRet Crypto::CheckSignature(PublicKey key,
	std::ifstream& file,
	const DataIn signature,
	bool& validationResult)
{
	if (key == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (signature.pData == nullptr)
		return CryptoRet::INVALID_PARAMETER;
	else if (!IsValidKeySize(key->keySize))
		return CryptoRet::INVALID_PARAMETER;

	const SHA3_Length hashLength = GetHashLength(key->keySize);
	const uint8_t hashBytes = static_cast<uint8_t>(hashLength);

	uint16_t blockSize = 0U;
	CryptoUtils::BlockSize(key->keySize, nullptr, &blockSize);

	if (blockSize > signature.size)
		return CryptoRet::INSUFFICIENT_BUFFER;

	CryptoRet ret = CryptoRet::OK;
	try
	{
		// Create a hash from the data
		char hashBuffer[64]{}; // 64B is enough for all SHA3 lengths
		SHA3::SHA3Hasher hasher;
		hasher.Process(hashLength, file, hashBuffer);

		// Encrypt the data with private key
		validationResult = CryptoUtils::CheckSignature(key, DataIn(hashBuffer, hashBytes), signature);
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
	return ret;
}
