#include "pch.h"
#include "CryptoUtils.h"
#include "BigInt.h"
#include <random>

namespace
{
	// !\brief Encrypted data contains the actual byte count in the block
	// !\details Byte count is written before actual data.
	const uint8_t BLOCK_SIZE_BYTES = 2;
}

class RandomGenerator
{
public:
	RandomGenerator()
		: m_gen(std::random_device()()) {}

	unsigned char Random()
	{
		// Value range [0...255]
		return m_gen() % (std::numeric_limits<unsigned char>::max() + 1);
	}

	void RandomData(char* pData, const size_t count)
	{
		for (auto i = 0; i < count; ++i)
		{
			pData[i] = Random();
		}
	}

private:
	std::mt19937_64 m_gen;
};

static RandomGenerator RAND;

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

	if (input.size < decryptedBlockSize)
	{
		// Padd with some random data
		RAND.RandomData(dst + input.size, decryptedBlockSize - input.size);
	}

	BigInt encrypted = data.PowMod(key.e, key.n);
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

	const BigInt decrypted = data.PowMod(key.d, key.n);
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
	uint16_t block = 0;
	switch (keySize)
	{
	case Crypto::KeySize::KS_1024:
		block = 128;
	default:
		break;
	}
	if (pEncrypted)
		*pEncrypted = block;
	if (pDecrypted)
		*pDecrypted = block - BLOCK_SIZE_BYTES;
}