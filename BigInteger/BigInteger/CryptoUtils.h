#pragma once
#include "Crypto.h"
#include "BigInt.h"
#include <random>

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

		RandomGenerator(const RandomGenerator&&) = delete;
		RandomGenerator& operator=(const RandomGenerator&&) = delete;
	};

	static RandomGenerator* GetRand();

	static Crypto::CryptoRet EncryptBlock(const Crypto::PublicKey& key,
		const Crypto::DataIn input,
		const Crypto::DataOut out,
		uint64_t* pEncryptedBytes);

	static Crypto::CryptoRet DecryptBlock(const Crypto::PrivateKey& key,
		const Crypto::DataIn input,
		const Crypto::DataOut out,
		uint64_t* pDecryptedBytes);

	static void BlockSize(const Crypto::KeySize keySize, uint16_t* pDecrypted, uint16_t* pEncrypted);

	static BigInt GenerateRandomPrime(const Crypto::KeySize keySize, uint32_t& iters);
};

