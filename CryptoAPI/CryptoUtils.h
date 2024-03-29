#pragma once
#include "Crypto.h"
#include "BigInt.h"
#include <random>

struct Crypto::_PublicKey
{
	BigInt e;
	BigInt n;

	Crypto::KeySize keySize;
};

struct Crypto::_PrivateKey
{
	BigInt d;
	BigInt n;

	Crypto::KeySize keySize;
};

class CryptoUtils
{
public:
	class RandomGenerator
	{
	public:
		RandomGenerator();

		unsigned char Random();

		uint64_t Random64();

		void RandomData(char* pData, const size_t count);
		void RandomData(uint64_t* pData, const size_t count);

	private:
		std::mt19937_64 m_gen;

		RandomGenerator(const RandomGenerator&) = delete;
		RandomGenerator& operator=(const RandomGenerator&) = delete;
		RandomGenerator(const RandomGenerator&&) = delete;
		RandomGenerator& operator=(const RandomGenerator&&) = delete;
	};

	static RandomGenerator* GetRand();

	static Crypto::CryptoRet WriteKeyToBuffer(const Crypto::PublicKey key,
		const Crypto::DataOut out,
		uint16_t* pPubBytesWritten);

	static Crypto::CryptoRet WriteKeyToBuffer(const Crypto::PrivateKey key,
		const Crypto::DataOut out,
		uint16_t* pPrivBytesWritten);

	static Crypto::CryptoRet EncryptBlock(const Crypto::PublicKey key,
		const Crypto::DataIn input,
		const Crypto::DataOut out,
		uint64_t* pEncryptedBytes);

	static Crypto::CryptoRet DecryptBlock(const Crypto::PrivateKey key,
		const Crypto::DataIn input,
		const Crypto::DataOut out,
		uint64_t* pDecryptedBytes);

	static void BlockSize(const Crypto::KeySize keySize, uint16_t* pDecrypted, uint16_t* pEncrypted);

	static BigInt GenerateRandomPrime(const Crypto::KeySize keySize);

	static Crypto::CryptoRet ValidateKeys(const Crypto::AsymmetricKeys* keys);
	static Crypto::CryptoRet ValidateKey(const Crypto::PrivateKey key);
	static Crypto::CryptoRet ValidateKey(const Crypto::PublicKey key);

	static uint16_t NeededBufferSizePrivate(const Crypto::KeySize keySize);
	static uint16_t NeededBufferSizePublic(const Crypto::KeySize keySize);

	static Crypto::CryptoRet ImportKey(Crypto::PrivateKey privKey, const Crypto::DataIn priv);
	static Crypto::CryptoRet ImportKey(Crypto::PublicKey pubKey, const Crypto::DataIn pub);

	static Crypto::CryptoRet CreateSignature(Crypto::PrivateKey privKey,
		const Crypto::DataIn hashedData,
		const Crypto::DataOut signature);

	static bool CheckSignature(Crypto::PublicKey privKey,
		const Crypto::DataIn hashedData,
		const Crypto::DataIn signature);
};
