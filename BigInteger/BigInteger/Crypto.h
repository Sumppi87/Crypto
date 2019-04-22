#pragma once
#include <cstdint>

class Crypto
{
public:
	struct PublicKey;
	struct PrivateKey;

	enum class KeySize
	{
		KS_64 = 64,
		KS_128 = 128,
		KS_256 = 256,
		KS_512 = 512,
		KS_1024 = 1024,
		KS_2048 = 2048,
		KS_3072 = 3072
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

#define BUFFER_SIZE_PRIVATE(keySize) (((static_cast<uint16_t>(keySize) / 8) * 2) * 2 + 55)
#define BUFFER_SIZE_PUBLIC(keySize) (((static_cast<uint16_t>(keySize) / 8) * 2) + 57 + 3)

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

	// !\Brief Stores asymmetric keys to output buffer
	// !\param[in] keys Asymmetric key to store
	// !\param[in] priv Buffer to store the private key,
	// Needed buffer size can be calculated with a formula: (keysize / 8) * 2 + 57
	// !\param[out] pPrivBytesWritten Private key bytes written to the buffer
	// !\param[in] pub Buffer to store the public key
	// Needed buffer size can be calculated with a formula: (keysize / 8) + 5 + 57
	// !\param[out] pPubBytesWritten Publis key bytes written to the buffer
	// !\return CryptoRet::OK if keys were successfully stored
	// !\note AsymmetricKeys are not released, keys must be destroyed with DeleteAsymmetricKeys
	static CryptoRet ExportAsymmetricKeys(AsymmetricKeys* keys,
		const DataOut priv,
		uint16_t* pPrivBytesWritten,
		const DataOut pub,
		uint16_t* pPubBytesWritten);

	// !\Brief Calculates the needed buffer size key exporting keys
	// !\param[in] keys Asymmetric key to calculate
	// !\param[out] pPrivateKeyBytes Needed buffer size for private key, optional param
	// !\param[out] pPublicKeyBytes Needed buffer size for public key, optional param
	static void NeededBufferSizeForExport(const KeySize keySize,
		uint16_t* pPrivateKeyBytes,
		uint16_t* pPublicKeyBytes);

	// !\Brief Imports asymmetric keys from buffers
	// !\param[out] Asymmetric key from buffers
	// !\param[in] priv Buffer where the private key is stored
	// !\param[in] priv Buffer where the public key is stored
	// !\return CryptoRet::OK if keys were successfully stored
	// !\note Imported keys must be destroyed with DeleteAsymmetricKeys
	static CryptoRet ImportAsymmetricKeys(AsymmetricKeys* keys, const DataOut priv, const DataOut pub);

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
	//           BlockSize : ((KeySize / 8) - 3)
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
	//           NeededBufferSize : BlockCount * ((KeySize - 3) / 8)
	static CryptoRet Decrypt(const PrivateKey* key, const DataIn input, const DataOut output, uint64_t* pDecryptedBytes);
};

