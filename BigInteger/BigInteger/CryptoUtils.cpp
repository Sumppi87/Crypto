#include "pch.h"
#include "CryptoUtils.h"
#include "BigInt.h"
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <immintrin.h>

namespace
{
	// !\brief Encrypted data contains the actual byte count in the block
	// !\details Byte count is written before actual data.
	const uint8_t BLOCK_SIZE_BYTES = 2;

	// !\brief 
	// !\details Byte count is written before actual data.
	const uint8_t GUARD_BYTES = 1;

	const std::unordered_map<uint16_t, Crypto::KeySize> PRIVATE_FILESIZES = []()
	{
		std::unordered_map<uint16_t, Crypto::KeySize> ret;
		ret[BUFFER_SIZE_PRIVATE(Crypto::KeySize::KS_64)] = Crypto::KeySize::KS_64;
		ret[BUFFER_SIZE_PRIVATE(Crypto::KeySize::KS_128)] = Crypto::KeySize::KS_128;
		ret[BUFFER_SIZE_PRIVATE(Crypto::KeySize::KS_256)] = Crypto::KeySize::KS_256;
		ret[BUFFER_SIZE_PRIVATE(Crypto::KeySize::KS_512)] = Crypto::KeySize::KS_512;
		ret[BUFFER_SIZE_PRIVATE(Crypto::KeySize::KS_1024)] = Crypto::KeySize::KS_1024;
		ret[BUFFER_SIZE_PRIVATE(Crypto::KeySize::KS_2048)] = Crypto::KeySize::KS_2048;
		ret[BUFFER_SIZE_PRIVATE(Crypto::KeySize::KS_3072)] = Crypto::KeySize::KS_3072;
		return ret;
	}();

	bool GetKeySizeFromBufferSize(const uint16_t size, Crypto::KeySize& keySize)
	{
		auto iter = PRIVATE_FILESIZES.find(size);
		if (iter != PRIVATE_FILESIZES.cend())
		{
			keySize = (*iter).second;
			return true;
		}
		return false;
	}

	bool ParseFromRawData(std::istringstream& input, BigInt& num)
	{
		std::string n;
		if (std::getline(input, n))
		{
			num = BigInt::FromString(n.data());
			return true;
		}
		return false;
	}

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

	bool operator!=(const BigInt& num, const Crypto::KeySize keysize)
	{
		const auto keyBytes = KeyBytes(keysize);
		return num.GetBitWidth() != (keyBytes * 8);
	}

	void WriteNewline(std::ostringstream& buffer)
	{
		buffer << std::endl;
	}

	void WriteNumToBuffer(std::ostringstream& buffer, const BigInt& num, const bool addNewline)
	{
		const auto d = num.ToHex();
		buffer << d;
		if (addNewline)
		{
			WriteNewline(buffer);
		}
	}

	void WriteToBuffer(const BigInt& exponent,
		const BigInt& modulo,
		std::ostringstream& buffer)
	{
		WriteNumToBuffer(buffer, exponent, true);
		WriteNumToBuffer(buffer, modulo, false);
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

Crypto::CryptoRet CryptoUtils::WriteKeyToBuffer(const Crypto::PublicKey* key,
	const Crypto::DataOut out,
	uint16_t* pPubBytesWritten)
{
	Crypto::CryptoRet ret = ValidateKey(key);
	if (ret != Crypto::CryptoRet::OK)
		return ret;
	else if (pPubBytesWritten == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (out.pData == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;

	const uint16_t neededBuffer = NeededBufferSizePublic(key->keySize);
	if (neededBuffer > out.size)
		return Crypto::CryptoRet::INSUFFICIENT_BUFFER;

	std::ostringstream buffer;
	WriteToBuffer(key->n, key->e, buffer);
	const std::string exportedKey = buffer.str();
	if (exportedKey.size() > out.size)
		return Crypto::CryptoRet::INSUFFICIENT_BUFFER;

	memcpy(out.pData, exportedKey.data(), exportedKey.size());
	*pPubBytesWritten = uint16_t(exportedKey.size());

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet CryptoUtils::WriteKeyToBuffer(const Crypto::PrivateKey* key,
	const Crypto::DataOut out,
	uint16_t* pPrivBytesWritten)
{
	Crypto::CryptoRet ret = ValidateKey(key);
	if (ret != Crypto::CryptoRet::OK)
		return ret;
	else if (pPrivBytesWritten == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (out.pData == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;

	const uint16_t neededBuffer = NeededBufferSizePrivate(key->keySize);
	if (neededBuffer > out.size)
		return Crypto::CryptoRet::INSUFFICIENT_BUFFER;

	std::ostringstream buffer;
	WriteToBuffer(key->n, key->d, buffer);
	const std::string exportedKey = buffer.str();
	if (exportedKey.size() > out.size)
		return Crypto::CryptoRet::INSUFFICIENT_BUFFER;

	memcpy(out.pData, exportedKey.data(), exportedKey.size());
	*pPrivBytesWritten = uint16_t(exportedKey.size());

	return Crypto::CryptoRet::OK;
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

	if (input.size < decryptedBlockSize)
	{
		// TODO: Padding causes some problems -> investigate
		// Padd with some random data
		RAND.RandomData(dst + input.size, decryptedBlockSize - input.size);
	}

#ifdef _DEBUG
	std::cout << "Encrypting Data: " << std::string(input.pData, input.size) << std::endl;
	std::cout << "Encrypting Block: " << data.ToHex() << std::endl;
#endif

	BigInt encrypted = data.PowMod(key.e, key.n);
#ifdef _DEBUG
	std::cout << "Encrypted Block: " << encrypted.ToHex() << std::endl;
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
	std::cout << "Decrypting Block: " << data.ToHex() << std::endl;
	const BigInt decrypted = data.PowMod(key.d, key.n);
	std::cout << "Decrypted Block: " << decrypted.ToHex() << std::endl;
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
		*pDecrypted = block - BLOCK_SIZE_BYTES - GUARD_BYTES;
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

BigInt CryptoUtils::GenerateRandomPrime(const size_t bits)
{
	const size_t blocks = bits / (8 * sizeof(BigInt::Base));
	const size_t remBits = bits % (8 * sizeof(BigInt::Base));

	BigInt randPrime;
	randPrime.Resize(blocks > 0 ? blocks : 1);

	// Generate random data
	RAND.RandomData(randPrime.m_vals, randPrime.CurrentSize());
	if (!randPrime.IsOdd())
		randPrime = randPrime + 1;

	// Make sure the highest bit is set
	if (remBits > 0)
	{
		// Bit indexing starts at zero
		randPrime.m_vals[randPrime.CurrentSize() - 1] |= 1ULL << (remBits - 1);

		//And clear remaining bits
		BigInt::Base mask = ~0ULL;
		for (auto i = remBits; i < sizeof(BigInt::Base) * 8; ++i)
		{
			mask &= ~(1ULL << i);
		}
		randPrime.m_vals[randPrime.CurrentSize() - 1] &= mask;
	}
	else
	{
		randPrime.m_vals[randPrime.CurrentSize() - 1] |= 1ULL << 63;
	}

	const BigInt two(2);
	while (!randPrime.IsPrimeNumber())
	{
		randPrime = randPrime + two;
	}

	if (randPrime.GetBitWidth() > bits)
	{
		_ASSERT(0);
		std::cerr << "Generated prime number is larger than expected, retry" << std::endl;
		return GenerateRandomPrime(bits);
	}

	return randPrime;
}

Crypto::CryptoRet CryptoUtils::ValidateKeys(const Crypto::AsymmetricKeys* keys)
{
	if (keys == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (keys->privKey == nullptr || keys->pubKey == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (keys->keySize != keys->privKey->keySize)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (keys->keySize != keys->pubKey->keySize)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (keys->privKey->n != keys->pubKey->n)
		return Crypto::CryptoRet::INVALID_PARAMETER;

	Crypto::CryptoRet ret = ValidateKey(keys->privKey);
	if (ret == Crypto::CryptoRet::OK)
		ret = ValidateKey(keys->pubKey);

	return ret;
}

Crypto::CryptoRet CryptoUtils::ValidateKey(const Crypto::PrivateKey* key)
{
	if (key == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (key->d.IsZero() || !key->d.IsPositive())
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (key->n.IsZero() || !key->n.IsPositive())
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (key->n.GetByteWidth() != key->d.GetByteWidth())
		return Crypto::CryptoRet::INVALID_PARAMETER;

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet CryptoUtils::ValidateKey(const Crypto::PublicKey* key)
{
	if (key == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (key->e.IsZero() || !key->e.IsPositive())
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (key->n.IsZero() || !key->n.IsPositive())
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (!key->e.IsPrimeNumber()) // e-component must always be prime
		return Crypto::CryptoRet::INVALID_PARAMETER;

	return Crypto::CryptoRet::OK;
}

uint16_t CryptoUtils::NeededBufferSizePrivate(const Crypto::KeySize keySize)
{
	return BUFFER_SIZE_PRIVATE(keySize);
}

uint16_t CryptoUtils::NeededBufferSizePublic(const Crypto::KeySize keySize)
{
	return BUFFER_SIZE_PUBLIC(keySize);
}

Crypto::CryptoRet CryptoUtils::ImportPrivateKey(Crypto::AsymmetricKeys* pKeys, const Crypto::DataIn priv)
{
	if (!GetKeySizeFromBufferSize(uint16_t(priv.size), pKeys->keySize))
		return Crypto::CryptoRet::INVALID_PARAMETER;
	pKeys->privKey->keySize = pKeys->keySize;

	std::istringstream input;
	input.str(std::string(priv.pData, priv.size));

	if (!ParseFromRawData(input, pKeys->privKey->n)
		|| !ParseFromRawData(input, pKeys->privKey->d))
	{
		return Crypto::CryptoRet::INVALID_PARAMETER;
	}

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet CryptoUtils::ImportPublicKey(Crypto::AsymmetricKeys* pKeys, const Crypto::DataIn pub)
{
	pKeys->pubKey->keySize = pKeys->keySize;

	std::istringstream input;
	input.str(std::string(pub.pData, pub.size));

	if (!ParseFromRawData(input, pKeys->pubKey->n)
		|| !ParseFromRawData(input, pKeys->pubKey->e))
	{
		return Crypto::CryptoRet::INVALID_PARAMETER;
	}

	return Crypto::CryptoRet::OK;
}
