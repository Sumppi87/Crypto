#include "CryptoUtils.h"
#include "BigInt.h"
#include <iostream>
#include <sstream>
#include <immintrin.h>

namespace
{
// !\brief Encrypted data contains the actual byte count in the block
// !\details Byte count is written before actual data.
const uint8_t BLOCK_SIZE_BYTES = 2U;

// !\brief
// !\details Byte count is wruitten before actual data.
const uint8_t GUARD_BYTES = 1;

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

inline bool GetKeySize(const BigInt& n, Crypto::KeySize& keySize)
{
	bool retVal = true;
	const auto size = n.GetByteWidth();
	auto IsCorrectSize = [size](const auto s)
	{
		return s == size || s == (size + 1);
	};

	if (IsCorrectSize(32U))
	{
		keySize = Crypto::KeySize::KS_256;
	}
	else if (IsCorrectSize(64U))
	{
		keySize = Crypto::KeySize::KS_512;
	}
	else if (IsCorrectSize(128U))
	{
		keySize = Crypto::KeySize::KS_1024;
	}
	else if (IsCorrectSize(256U))
	{
		keySize = Crypto::KeySize::KS_2048;
	}
	else if (IsCorrectSize(384U))
	{
		keySize = Crypto::KeySize::KS_3072;
	}
	else if (IsCorrectSize(512U))
	{
		keySize = Crypto::KeySize::KS_4096;
	}
	else
	{
		retVal = false;
	}
	return retVal;
}

inline uint16_t KeyBytes(const Crypto::KeySize keySize)
{
	uint16_t block = 0U;
	switch (keySize)
	{
	case Crypto::KeySize::KS_256:
		block = 32U;
		break;
	case Crypto::KeySize::KS_512:
		block = 64U;
		break;
	case Crypto::KeySize::KS_1024:
		block = 128U;
		break;
	case Crypto::KeySize::KS_2048:
		block = 256U;
		break;
	case Crypto::KeySize::KS_3072:
		block = 384U;
		break;
	case Crypto::KeySize::KS_4096:
		block = 512U;
		break;
	default:
		break;
	}
	return block;
}

inline bool operator>(const BigInt& num, const Crypto::KeySize keysize)
{
	const auto keyBytes = KeyBytes(keysize);
	return num.GetBitWidth() > (keyBytes * 8U);
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
	return m_gen() % (std::numeric_limits<unsigned char>::max() + 1U);
}

uint64_t CryptoUtils::RandomGenerator::Random64()
{
	return m_gen();
}

void CryptoUtils::RandomGenerator::RandomData(char* pData, const size_t count)
{
	for (size_t i = 0U; i < count; ++i)
	{
		pData[i] = char(Random());
	}
}

void CryptoUtils::RandomGenerator::RandomData(uint64_t* pData, const size_t count)
{
	for (size_t i = 0U; i < count; ++i)
	{
		pData[i] = Random64();
	}
}

static CryptoUtils::RandomGenerator RAND;

CryptoUtils::RandomGenerator* CryptoUtils::GetRand()
{
	return &RAND;
}

Crypto::CryptoRet CryptoUtils::WriteKeyToBuffer(const Crypto::PublicKey key,
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

Crypto::CryptoRet CryptoUtils::WriteKeyToBuffer(const Crypto::PrivateKey key,
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

Crypto::CryptoRet CryptoUtils::EncryptBlock(const Crypto::PublicKey key,
	const Crypto::DataIn input,
	const Crypto::DataOut out,
	uint64_t* pEncryptedBytes)
{
	uint16_t encryptedBlockSize = 0U;
	uint16_t decryptedBlockSize = 0U;
	BlockSize(key->keySize, &decryptedBlockSize, &encryptedBlockSize);
	if (input.size > decryptedBlockSize)
	{
		_ASSERT(0);
		return Crypto::CryptoRet::INTERNAL_ERROR;
	}

	BigInt data;
	data.Resize(encryptedBlockSize / sizeof(uint64_t));
	memcpy(data.m_vals, &input.size, BLOCK_SIZE_BYTES);
	char* dst = (char*)data.m_vals + BLOCK_SIZE_BYTES;
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

	BigInt encrypted = data.PowMod(key->e, key->n);
#ifdef _DEBUG
	std::cout << "Encrypted Block: " << encrypted.ToHex() << std::endl;
#endif

	memcpy(out.pData, encrypted.m_vals, encryptedBlockSize);
	if (pEncryptedBytes)
		*pEncryptedBytes += encryptedBlockSize;

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet CryptoUtils::DecryptBlock(const Crypto::PrivateKey key,
	const Crypto::DataIn input,
	const Crypto::DataOut out,
	uint64_t* pDecryptedBytes)
{
	uint16_t encryptedBlockSize = 0U;
	uint16_t decryptedBlockSize = 0U;
	BlockSize(key->keySize, &decryptedBlockSize, &encryptedBlockSize);
	if (input.size > encryptedBlockSize)
	{
		_ASSERT(0);
		return Crypto::CryptoRet::INTERNAL_ERROR;
	}

	BigInt data;
	data.Resize(encryptedBlockSize / sizeof(uint64_t));
	char* dst = data.m_vals;
	memcpy(dst, input.pData, input.size);

#ifdef _DEBUG
	std::cout << "Decrypting Block: " << data.ToHex() << std::endl;
	const BigInt decrypted = data.PowMod(key->d, key->n);
	std::cout << "Decrypted Block: " << decrypted.ToHex() << std::endl;
#else
	const BigInt decrypted = data.PowMod(key->d, key->n);
#endif

	uint16_t blockSize = 0U;
	const char* decryptedDst = (const char*)decrypted.m_vals;
	memcpy(&blockSize, decryptedDst, BLOCK_SIZE_BYTES);

	if (blockSize == 0U || blockSize > decryptedBlockSize)
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
		*pDecrypted = uint16_t(block - (BLOCK_SIZE_BYTES + GUARD_BYTES));
}

BigInt CryptoUtils::GenerateRandomPrime(const Crypto::KeySize keySize)
{
	const uint16_t keyBytes = KeyBytes(keySize) / 2U;
	const uint16_t blocks = keyBytes > sizeof(BigInt::Base) ? keyBytes / sizeof(BigInt::Base) : 1U;

	BigInt randPrime;
	randPrime.Resize(blocks);

	// Generate random data
	RAND.RandomData((BigInt::Base*)randPrime.m_vals, randPrime.CurrentSize());
	if (!randPrime.IsOdd())
		randPrime = randPrime + 1U;

	// Make sure the highest bit is set
	randPrime.m_vals[randPrime.CurrentSize() - 1U] |= 1ULL << 63U;

	const BigInt two(2U);
	while (!randPrime.IsPrimeNumber())
	{
		randPrime = randPrime + two;
	}

	if (randPrime.GetByteWidth() > keyBytes)
	{
		_ASSERT(0);
		std::cerr << "Generated prime number is larger than expected, retry" << std::endl;
		return GenerateRandomPrime(keySize);
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

Crypto::CryptoRet CryptoUtils::ValidateKey(const Crypto::PrivateKey key)
{
	if (key == nullptr)
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (key->d.IsZero() || !key->d.IsPositive())
		return Crypto::CryptoRet::INVALID_PARAMETER;
	else if (key->n.IsZero() || !key->n.IsPositive())
		return Crypto::CryptoRet::INVALID_PARAMETER;

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet CryptoUtils::ValidateKey(const Crypto::PublicKey key)
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

Crypto::CryptoRet CryptoUtils::ImportKey(Crypto::PrivateKey privKey, const Crypto::DataIn priv)
{
	std::istringstream input;
	input.str(std::string(priv.pData, priv.size));

	if (!ParseFromRawData(input, privKey->n)
		|| !ParseFromRawData(input, privKey->d))
	{
		return Crypto::CryptoRet::INVALID_PARAMETER;
	}
	else if (!GetKeySize(privKey->n, privKey->keySize))
	{
		return Crypto::CryptoRet::INVALID_PARAMETER;
	}
	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet CryptoUtils::ImportKey(Crypto::PublicKey pubKey, const Crypto::DataIn pub)
{
	std::istringstream input;
	input.str(std::string(pub.pData, pub.size));

	if (!ParseFromRawData(input, pubKey->n)
		|| !ParseFromRawData(input, pubKey->e))
	{
		return Crypto::CryptoRet::INVALID_PARAMETER;
	}
	else if (!GetKeySize(pubKey->n, pubKey->keySize))
	{
		return Crypto::CryptoRet::INVALID_PARAMETER;
	}

	return Crypto::CryptoRet::OK;
}

Crypto::CryptoRet CryptoUtils::CreateSignature(Crypto::PrivateKey key,
	const Crypto::DataIn hashedData,
	const Crypto::DataOut signature)
{
	BigInt data = BigInt::FromRawData(hashedData.pData, hashedData.size);
	const auto blockSize = KeyBytes(key->keySize);

	if (blockSize <= GUARD_BYTES)
	{
		return Crypto::CryptoRet::INVALID_PARAMETER;
	}
	// Add some random data after the hash
	else if (hashedData.size < uint16_t(blockSize - GUARD_BYTES))
	{
		data.Resize(blockSize / sizeof(BigInt::Base));
		RAND.RandomData((char*)data.m_vals + hashedData.size, (blockSize - GUARD_BYTES) - hashedData.size);
	}

	BigInt encrypted = data.PowMod(key->d, key->n);
	memcpy(signature.pData, encrypted.m_vals, blockSize);

	return Crypto::CryptoRet::OK;
}

bool CryptoUtils::CheckSignature(Crypto::PublicKey key,
	const Crypto::DataIn hashedData,
	const Crypto::DataIn signature)
{
	const BigInt data = BigInt::FromRawData(signature.pData, signature.size);
	const BigInt decryptedSignature = data.PowMod(key->e, key->n);

	// decrypted signature contains some random data -> discard it
	const BigInt expectedSignature = BigInt::FromRawData(decryptedSignature.m_vals, hashedData.size);

	const BigInt actualSignature = BigInt::FromRawData(hashedData.pData, hashedData.size);

	const bool signaturesMatch = (actualSignature == expectedSignature);
	return signaturesMatch;
}
