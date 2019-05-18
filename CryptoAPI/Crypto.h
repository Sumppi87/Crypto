#pragma once
#include <cstdint>
#include <iosfwd>

#if not defined(_M_X64)
#error("only 64bit is supported")
#endif

class Crypto
{
private:
	// Forward declarations of internal structs
	struct _PublicKey;
	struct _PrivateKey;

public:
	// Publically available types and definitions

	//! \brief Pointer definition for public key
	typedef _PublicKey* PublicKey;

	//! \brief Pointer definition for private key
	typedef _PrivateKey* PrivateKey;

	//! \brief Supported key lengths
	enum class KeySize : uint64_t
	{
		KS_256 = 256,
		KS_512 = 512,
		KS_1024 = 1024,
		KS_2048 = 2048,
		KS_3072 = 3072
	};

	//! \brief Container holding both public and private keys
	struct AsymmetricKeys
	{
		AsymmetricKeys();

		PublicKey pubKey;
		PrivateKey privKey;
		KeySize keySize;
	};

	//! \brief Data input for the API, not modifiable
	struct DataIn
	{
		DataIn(const char* data, const uint64_t s);

		const char* pData;
		uint64_t size;
	};

	//! \brief Data output for the API
	struct DataOut
	{
		DataOut(char* data, const uint64_t s);

		char* pData;
		uint64_t size;
	};

	//! \brief Generic return values of the API-functions
	enum class CryptoRet
	{
		OK = 1,
		INSUFFICIENT_BUFFER = -1,
		INSUFFICIENT_RESOURCES = -2,
		INVALID_PARAMETER = -3,
		INTERNAL_ERROR = -4
	};

	enum class SHA3_Length : uint8_t
	{
		SHA3_224 = 28,
		SHA3_256 = 32,
		SHA3_384 = 48,
		SHA3_512 = 64
	};


	//!
	//! Key management related function
	//!
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

	// !\Brief Destroys generated keys, i.e. releases allocated memory
	// !\param[in] keys Keys to deallocate
	// !\return CryptoRet::OK if keys were successfully deallocated
	static CryptoRet DeleteKey(PublicKey* publicKey);

	// !\Brief Destroys generated keys, i.e. releases allocated memory
	// !\param[in] keys Keys to deallocate
	// !\return CryptoRet::OK if keys were successfully deallocated
	static CryptoRet DeleteKey(PrivateKey* privateKey);

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
	static CryptoRet ImportAsymmetricKeys(AsymmetricKeys* keys, const DataIn priv, const DataIn pub);

	// !\Brief Imports asymmetric public key from buffer
	// !\param[out] pPublicKey Imported key from buffer
	// !\param[in] pubData Buffer where the public key is stored
	// !\return CryptoRet::OK if keys were successfully stored
	// !\note Imported key must be destroyed with DeleteKey
	static CryptoRet ImportKey(PublicKey* pPublicKey, const DataIn pubData);

	// !\Brief Imports asymmetric private key from buffer
	// !\param[out] pPrivateKey Imported key from buffer
	// !\param[in] privData Buffer where the private key is stored
	// !\return CryptoRet::OK if keys were successfully stored
	// !\note Imported key must be destroyed with DeleteKey
	static CryptoRet ImportKey(PrivateKey* pPrivateKey, const DataIn privData);

	// !\Brief Sets how many threads to use in threadable operations
	// !\param[in] maxThreads How many threads to use
	// !\return CryptoRet::OK if the limit was set
	static void SetThreadCount(const uint32_t maxThreads);

	//!
	//! Encryption/decryption related function
	//!
public:
	// !\Brief Encrypts data with given public key
	// !\param[in] key Encryption key
	// !\param[in] input Data to encrypt
	// !\param[in] output Buffer to store encrypted data
	// !\param[out] pEncryptedBytes How many encrypted bytes was written to the buffer
	// !\return CryptoRet::OK if data was succesfully encrypted
	// !\note Function supports in-place encryption: input.pData == output.pData
	//        However, multi-threaded encryption is not supported with in-place encryption
	//        When in-place encryption is not used, buffers of input and output shall not overlap
	// !\details Output buffer must be sufficiently large for encrypted data.
	//           Needed buffer size can be calculated with keysize and data size of the input
	//           BlockSize : ((KeySize / 8) - 3)
	//           BlockCount : ceil(input.size / BlockSize)
	//           NeededBufferSize : BlockCount * (KeySize / 8)
	static CryptoRet Encrypt(const PublicKey key, const DataIn input, const DataOut output, uint64_t* pEncryptedBytes);

	// !\Brief Decrypts data with the given private key
	// !\param[in] key Decryption key
	// !\param[in] input Data to decrypt
	// !\param[in] output Buffer to store decrypted data
	// !\param[out] pDecryptedBytes How many decrypted bytes was written to the buffer
	// !\return CryptoRet::OK if data was succesfully decrypted
	// !\note Function supports in-place decryption: input.pData == output.pData
	//        However, multi-threaded decryption is not supported when in-place decryption is used
	//        When in-place decryption is not used, buffers of input and output shall not overlap
	// !\details Output buffer must be sufficiently large for decrypted data.
	//           Needed buffer size can be calculated with keysize and data size of the input
	//           BlockSize : (KeySize / 8)
	//           BlockCount : ceil(input.size / BlockSize)
	//           NeededBufferSize : BlockCount * ((KeySize / 8) - 3)
	static CryptoRet Decrypt(const PrivateKey key, const DataIn input, const DataOut output, uint64_t* pDecryptedBytes);

	//!
	//! Digital data signing related function
	//!
public:
	// !\Brief Creates a digital signature from a file
	// !\param[in] key Asymmetric private key, used the sign the data
	// !\param[in] file File to sign
	// !\param[in] signature Buffer to store signature
	// !\return CryptoRet::OK if signature was succesfully created and stored
	// !\details From the input file, the function creates a SHA-3 hash,
	//           which is then encrypted with the private key.
	static CryptoRet CreateSignature(PrivateKey key,
		std::ifstream& file,
		const DataOut signature);

	// !\Brief Validates a file againts a digital signature
	// !\param[in] key Asymmetric public key, used the validate the data
	// !\param[in] file File to check
	// !\param[in] signature Buffer containing the signature
	// !\param[out] validationResult True if file matched the signature
	// !\return CryptoRet::OK if signature was succesfully checked
	// !\details From the input file, the function creates a SHA-3 hash,
	//           which is then compared to the decrypted signature file.
	static CryptoRet CheckSignature(PublicKey key,
		std::ifstream& file,
		const DataIn signature,
		bool& validationResult);

	// Utilities
public:
	// Macros for calculation needed buffer size for key export
#define BUFFER_SIZE_PRIVATE(keySize) (((static_cast<uint16_t>(keySize) / 8U) * 2U) * 2U + 5U)
#define BUFFER_SIZE_PUBLIC(keySize) (((static_cast<uint16_t>(keySize) / 8U) * 2U) + 5U + 5U)

	static uint16_t GetBlockSizeEncrypted(const KeySize keySize);
	static uint16_t GetBlockSizePlain(const KeySize keySize);

	static uint64_t GetBlockCountEncryption(const KeySize keySize, const uint64_t dataSizePlain);
	static uint64_t GetBlockCountDecryption(const KeySize keySize, const uint64_t dataSizeEncrypted);

	static uint64_t GetBufferSizeEncryption(const KeySize keySize, const uint64_t dataSizePlain);
	static uint64_t GetBufferSizeDecryption(const KeySize keySize, const uint64_t dataSizeEncrypted);

	static uint64_t GetBufferSizeForSignature(const KeySize keySize);

	// !\brief Calculates the encrypted data block size
	// !\param[in] k Used key length
	template<KeySize k>
	struct BlockSizeEncrypted
	{
		static const uint64_t SIZE = static_cast<uint64_t>(k) / 8;
	};

	// !\brief Calculates the plain data block size
	// !\param[in] k Used key length
	template<KeySize k>
	struct BlockSizePlain
	{
		static const uint64_t SIZE = BlockSizeEncrypted<k>::SIZE - 3;
	};

	// !\brief Calculates the block count for encryption
	// !\param[in] k Used key length
	// !\param[in] dataSizePlain The amount of data to encrypt (in bytes)
	template<KeySize k, uint64_t dataSizePlain>
	struct BlockCountEncryption
	{
		static const uint64_t SIZE = (dataSizePlain / BlockSizePlain<k>::SIZE)
			+ ((dataSizePlain % BlockSizePlain<k>::SIZE) > 0 ? 1 : 0);
	};

	// !\brief Calculates the amount of blocks neede for encryption
	// !\param[in] k Used key length
	// !\param[in] size The amount of data to decrypt (in bytes)
	template<KeySize k, uint64_t size>
	struct BlockCountDecryption
	{
		static_assert((size % BlockSizeEncrypted<k>::SIZE) == 0, "");

		static const uint64_t SIZE = (size / BlockSizeEncrypted<k>::SIZE);
	};

	// !\brief Calculates the needed buffer size for encryption
	// !\param[in] k Used key length
	// !\param[in] size The amount of data to encrypt (in bytes)
	template<KeySize k, uint64_t size>
	struct BufferSizeEncryption
	{
		static const uint64_t SIZE = BlockCountEncryption<k, size>::SIZE * BlockSizeEncrypted<k>::SIZE;
	};

	// !\brief Calculates the needed buffer size for decryption
	// !\param[in] k Used key length
	// !\param[in] size The amount of data to decrypt (in bytes)
	template<KeySize k, uint64_t size>
	struct BufferSizeDecryption
	{
		static const uint64_t SIZE = BlockCountDecryption<k, size>::SIZE * BlockSizePlain<k>::SIZE;
	};

private:
	Crypto() = delete;
	~Crypto() = delete;
	Crypto(const Crypto&) = delete;
	Crypto(Crypto&&) = delete;
	Crypto& operator=(const Crypto&) = delete;
	Crypto& operator=(Crypto&&) = delete;
};
