#pragma once
#include <cstdint>

class Crypto
{
public:
	struct PublicKey;
	struct PrivateKey;

	enum class KeySize
	{
		KS_1024 = 1024,
	};

	struct AsymmetricKeys
	{
		AsymmetricKeys();

		PublicKey* pubKey;
		PrivateKey* privKey;
	};

	struct Data
	{
		Data()
			: pData(nullptr)
			, size(0) {}
		
		Data(const char* data, const uint64_t s)
			: pData(data)
			, size(s) {}

		const char* pData;
		uint64_t size;
	};

public:
	// !\Brief Generates a random public/private keypair
	// !\param[in] size Keysize
	// !\param[out] pKeys Created keys
	// !\return True if keys were successfully generated
	// !\note Created keys must be destroyed with DeleteAsymmetricKeys
	static bool CreateAsymmetricKeys(const KeySize size, AsymmetricKeys* pKeys);

	// !\Brief Destroys generated keys, i.e. releases allocated memory
	// !\param[in] keys Keys to deallocate
	// !\return True if keys were successfully deallocated
	static bool DeleteAsymmetricKeys(AsymmetricKeys* keys);

	// !\Brief Encrypts data with given public key
	// !\param[in] key Encryption key
	// !\param[in] input Data to encrypt
	// !\param[in] output Buffer to store encrypted data
	// !\param[out] pEncryptedBytes How many encrypted bytes was written to the buffer
	// !\return True if data was succesfully encrypted
	// !\note Function supports in-place encryption
	// !\details Output buffer must be sufficiently large for encrypted data.
	//           Needed buffer size can be calculated with keysize and data size of the input
	//           BlockSize : ((KeySize / 8) - 2)
	//           BlockCount : ceil(input.size / BlockSize)
	//           NeededBufferSize : BlockCount * (KeySize / 8)
	static bool Encrypt(const PublicKey* key, const Data input, const Data output, uint64_t* pEncryptedBytes);

	// !\Brief Decrypts data with the given private key
	// !\param[in] key Decryption key
	// !\param[in] input Data to decrypt
	// !\param[in] output Buffer to store decrypted data
	// !\param[out] pDecryptedBytes How many decrypted bytes was written to the buffer
	// !\return True if data was succesfully decrypted
	// !\note Function supports in-place decryption
	// !\details Output buffer must be sufficiently large for decrypted data.
	//           Needed buffer size can be calculated with keysize and data size of the input
	//           BlockSize : (KeySize / 8)
	//           BlockCount : ceil(input.size / BlockSize)
	//           NeededBufferSize : BlockCount * ((KeySize - 2) / 8)
	static bool Decrypt(const PrivateKey* key, const Data input, const Data output, uint64_t* pDecryptedBytes);
};

