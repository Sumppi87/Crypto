#pragma once
#include "Crypto.h"
#include "BigInt.h"

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

	static Crypto::CryptoRet EncryptBlock(const Crypto::PublicKey& key,
		const Crypto::DataIn input, 
		const Crypto::DataOut out, 
		uint64_t* pEncryptedBytes);

	static Crypto::CryptoRet DecryptBlock(const Crypto::PrivateKey& key,
		const Crypto::DataIn input,
		const Crypto::DataOut out,
		uint64_t* pDecryptedBytes);

	static void BlockSize(const Crypto::KeySize keySize, uint16_t* pDecrypted, uint16_t* pEncrypted);
};

