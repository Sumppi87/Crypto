#include "pch.h"
#include "CryptoUtils.h"
#include "BigInt.h"
#include <iostream>
#include <immintrin.h>

namespace
{
	// !\brief Encrypted data contains the actual byte count in the block
	// !\details Byte count is written before actual data.
	const uint8_t BLOCK_SIZE_BYTES = 2;

	uint16_t KeyBytes(const Crypto::KeySize keySize)
	{
		uint16_t block = 0;
		switch (keySize)
		{
		case Crypto::KeySize::KS_64:
			block = 8;
			break;
		case Crypto::KeySize::KS_128:
			block = 16;
			break;
		case Crypto::KeySize::KS_256:
			block = 32;
			break;
		case Crypto::KeySize::KS_512:
			block = 64;
			break;
		case Crypto::KeySize::KS_1024:
			block = 128;
			break;
		case Crypto::KeySize::KS_2048:
			block = 256;
			break;
		case Crypto::KeySize::KS_3072:
			block = 384;
			break;
		default:
			break;
		}
		return block;
	}

	bool operator>(const BigInt& num, const Crypto::KeySize keysize)
	{
		const auto keyBytes = KeyBytes(keysize);
		return num.GetBitWidth() > (keyBytes * 8);
	}
}

CryptoUtils::RandomGenerator::RandomGenerator()
	: m_gen(std::random_device()()) {}

unsigned char CryptoUtils::RandomGenerator::Random()
{
	// Value range [0...255]
	return m_gen() % (std::numeric_limits<unsigned char>::max() + 1);
}

uint64_t CryptoUtils::RandomGenerator::Random64()
{
	return m_gen();
}

void CryptoUtils::RandomGenerator::RandomData(char* pData, const size_t count)
{
	for (auto i = 0; i < count; ++i)
	{
		pData[i] = Random();
	}
}

void CryptoUtils::RandomGenerator::RandomData(uint64_t* pData, const size_t count)
{
	for (auto i = 0; i < count; ++i)
	{
		pData[i] = Random64();
	}
}

static CryptoUtils::RandomGenerator RAND;

CryptoUtils::RandomGenerator* CryptoUtils::GetRand()
{
	return &RAND;
}

Crypto::CryptoRet CryptoUtils::EncryptBlock(const Crypto::PublicKey& key,
	const Crypto::DataIn input,
	const Crypto::DataOut out,
	uint64_t* pEncryptedBytes)
{
	uint16_t encryptedBlockSize = 0;
	uint16_t decryptedBlockSize = 0;
	BlockSize(key.keySize, &decryptedBlockSize, &encryptedBlockSize);
	if (input.size > decryptedBlockSize)
	{
		_ASSERT(0);
		return Crypto::CryptoRet::INTERNAL_ERROR;
	}

	BigInt data;
	data.Resize(encryptedBlockSize / sizeof(uint64_t));
	memcpy(data.m_vals, &input.size, BLOCK_SIZE_BYTES);
	char* dst = (reinterpret_cast<char*>(data.m_vals) + BLOCK_SIZE_BYTES);
	memcpy(dst, input.pData, input.size);

#ifdef _DEBUG
	std::cout << "Encrypting Block: " << std::string(input.pData, input.size) << std::endl;
#endif

	if (input.size < decryptedBlockSize)
	{
		// TODO: Padding causes some problems -> investigate
		// Padd with some random data
		//RAND.RandomData(dst + input.size + BLOCK_SIZE_BYTES, decryptedBlockSize - input.size);
	}

	BigInt encrypted = data.PowMod(key.e, key.n);
#ifdef _DEBUG
	std::cout << "Encrypted Block: " << encrypted.ToRawData() << std::endl;
#endif

	memcpy(out.pData, encrypted.m_vals, encryptedBlockSize);
	if (pEncryptedBytes)
		*pEncryptedBytes += encryptedBlockSize;

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet CryptoUtils::DecryptBlock(const Crypto::PrivateKey& key,
	const Crypto::DataIn input,
	const Crypto::DataOut out,
	uint64_t* pDecryptedBytes)
{
	uint16_t encryptedBlockSize = 0;
	uint16_t decryptedBlockSize = 0;
	BlockSize(key.keySize, &decryptedBlockSize, &encryptedBlockSize);
	if (input.size > encryptedBlockSize)
	{
		_ASSERT(0);
		return Crypto::CryptoRet::INTERNAL_ERROR;
	}

	BigInt data;
	data.Resize(encryptedBlockSize / sizeof(uint64_t));
	char* dst = reinterpret_cast<char*>(data.m_vals);
	memcpy(dst, input.pData, input.size);

#ifdef _DEBUG
	std::cout << "Decrypting Block: " << std::string(input.pData, input.size) << std::endl;
	const BigInt decrypted = data.PowMod(key.d, key.n);
	std::cout << "Decrypted Block: " << decrypted.ToRawData() << std::endl;
#else
	const BigInt decrypted = data.PowMod(key.d, key.n);
#endif

	uint16_t blockSize = 0;
	const char* decryptedDst = reinterpret_cast<const char*>(decrypted.m_vals);
	memcpy(&blockSize, decryptedDst, BLOCK_SIZE_BYTES);

	if (blockSize == 0 || blockSize > decryptedBlockSize)
	{
		// Something went wrong, block size is invalid
		return Crypto::CryptoRet::INTERNAL_ERROR;
	}

	memcpy(out.pData, (decryptedDst + BLOCK_SIZE_BYTES), blockSize);
	if (pDecryptedBytes)
		*pDecryptedBytes += blockSize;

	return Crypto::CryptoRet::OK;
}

void CryptoUtils::BlockSize(const Crypto::KeySize keySize, uint16_t* pDecrypted, uint16_t* pEncrypted)
{
	const uint16_t block = KeyBytes(keySize);
	if (pEncrypted)
		*pEncrypted = block;
	if (pDecrypted)
		*pDecrypted = block - BLOCK_SIZE_BYTES;
}

BigInt CryptoUtils::GenerateRandomPrime(const Crypto::KeySize keySize, uint32_t& iters)
{
	const uint16_t keyBytes = KeyBytes(keySize) / 2;
	const uint16_t blocks = keyBytes > sizeof(BigInt::Base) ? keyBytes / sizeof(BigInt::Base) : 1;

	BigInt randPrime;
	randPrime.Resize(blocks);

	if (keySize == Crypto::KeySize::KS_64)
	{
		// Generate random data
		RAND.RandomData((char*)randPrime.m_vals, keyBytes);
		if (!randPrime.IsOdd())
			randPrime = randPrime + 1;

		// Make sure the highest bit is set
		randPrime.m_vals[0] |= 1ULL << 31;
	}
	else
	{
		// Generate random data
		RAND.RandomData(randPrime.m_vals, randPrime.CurrentSize());
		if (!randPrime.IsOdd())
			randPrime = randPrime + 1;

		// Make sure the highest bit is set
		randPrime.m_vals[randPrime.CurrentSize() - 1] |= 1ULL << 63;
	}

	const BigInt two(2);
	iters = 1;
	while (!randPrime.IsPrimeNumber())
	{
		//RAND.RandomData(randPrime.m_vals, randPrime.CurrentSize());
		//BigInt::SumWithoutSign(randPrime, two);
		randPrime = randPrime + two;
		++iters;
	}

	if (randPrime > keySize)
	{
		_ASSERT(0);
		std::cerr << "Generated prime number is larger than expected, retry" << std::endl;
		return GenerateRandomPrime(keySize, iters);
	}

	//std::cout << "Prime number generated with :" << iters << " iterations" << std::endl;
	return randPrime;
}
