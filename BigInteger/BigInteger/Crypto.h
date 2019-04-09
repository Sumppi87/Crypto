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
		KeySize keySize;
	};

	struct DataIn
	{
		DataIn()
			: pData(nullptr)
			, size(0) {}

		DataIn(const char* data, const uint64_t s)
			: pData(data)
			, size(s) {}

		const char* pData;
		uint64_t size;
	};

	struct DataOut
	{
		DataOut()
			: pData(nullptr)
			, size(0) {}

		DataOut(char* data, const uint64_t s)
			: pData(data)
			, size(s) {}

		char* pData;
		uint64_t size;
	};

	enum class CryptoRet
	{
		OK = 1,
		INSUFFICIENT_BUFFER = -1,
		INSUFFICIENT_RESOURCES = -2,
		INVALID_PARAMETER = -3,
		INTERNAL_ERROR = -4
	};

public:
	// !\Brief Generates a random public/private keypair
	// !\param[in] size Keysize
	// !\param[out] pKeys Created keys
	// !\return CryptoRet::OK if keys were successfully generated
	// !\note Created keys must be destroyed with DeleteAsymmetricKeys
	static CryptoRet CreateAsymmetricKeys(const KeySize size, AsymmetricKeys* pKeys);

	// !\Brief Destroys generated keys, i.e. releases allocated memory
	// !\param[in] keys Keys to deallocate
	// !\return CryptoRet::OK if keys were successfully deallocated
	static CryptoRet DeleteAsymmetricKeys(AsymmetricKeys* keys);

	// !\Brief Encrypts data with given public key
	// !\param[in] key Encryption key
	// !\param[in] input Data to encrypt
	// !\param[in] output Buffer to store encrypted data
	// !\param[out] pEncryptedBytes How many encrypted bytes was written to the buffer
	// !\return CryptoRet::OK if data was succesfully encrypted
	// !\note Function supports in-place encryption: input.pData == output.pData
	//        However, multi-threaded encryption is not supported if in-place encryption is used
	//        When in-place encryption is not used, buffers of input and output shall not overlap
	// !\details Output buffer must be sufficiently large for encrypted data.
	//           Needed buffer size can be calculated with keysize and data size of the input
	//           BlockSize : ((KeySize / 8) - 2)
	//           BlockCount : ceil(input.size / BlockSize)
	//           NeededBufferSize : BlockCount * (KeySize / 8)
	static CryptoRet Encrypt(const PublicKey* key, const DataIn input, const DataOut output, uint64_t* pEncryptedBytes);

	// !\Brief Decrypts data with the given private key
	// !\param[in] key Decryption key
	// !\param[in] input Data to decrypt
	// !\param[in] output Buffer to store decrypted data
	// !\param[out] pDecryptedBytes How many decrypted bytes was written to the buffer
	// !\return CryptoRet::OK if data was succesfully decrypted
	// !\note Function supports in-place decryption: input.pData == output.pData
	//        However, multi-threaded decryption is not supported if in-place decryption is used
	//        When in-place decryption is not used, buffers of input and output shall not overlap
	// !\details Output buffer must be sufficiently large for decrypted data.
	//           Needed buffer size can be calculated with keysize and data size of the input
	//           BlockSize : (KeySize / 8)
	//           BlockCount : ceil(input.size / BlockSize)
	//           NeededBufferSize : BlockCount * ((KeySize - 2) / 8)
	static CryptoRet Decrypt(const PrivateKey* key, const DataIn input, const DataOut output, uint64_t* pDecryptedBytes);
};

