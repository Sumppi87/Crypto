#include "pch.h"
#include "gtest/gtest.h"
#include "../CryptoAPI/Crypto.h"
#include "../CryptoAPI/CryptoUtils.h"

namespace
{
template <Crypto::KeySize k, uint16_t inputDataSize>
void TestInplaceEncryptDecrypt(bool& ret, Crypto::AsymmetricKeys* keys, Crypto::DataIn data)
{
	constexpr auto bufferSize = Crypto::BufferSizeEncryption<k, inputDataSize>::SIZE;
	char buffer[bufferSize]{};
	memcpy(buffer, data.pData, data.size);

	uint64_t encrypted = 0;
	ASSERT_EQ(Crypto::Encrypt(keys->pubKey, Crypto::DataIn(buffer, data.size),
		Crypto::DataOut(buffer, bufferSize), &encrypted),
		Crypto::CryptoRet::OK);

	uint64_t decrypted = 0;
	ASSERT_EQ(Crypto::Decrypt(keys->privKey, Crypto::DataIn(buffer, bufferSize),
		Crypto::DataOut(buffer, bufferSize), &decrypted),
		Crypto::CryptoRet::OK);

	ASSERT_EQ(std::string(data.pData, data.size), std::string(buffer, decrypted));

	ASSERT_EQ(decrypted, inputDataSize);

	ret = true;
}

template <Crypto::KeySize k, uint16_t inputDataSize>
void TestThreadedEncryptDecrypt(bool& ret, Crypto::AsymmetricKeys* keys, Crypto::DataIn data)
{
	constexpr auto bufferSize = Crypto::BufferSizeEncryption<k, inputDataSize>::SIZE;
	char buffer[bufferSize]{};

	uint64_t encrypted = 0;
	ASSERT_EQ(Crypto::Encrypt(keys->pubKey, data,
		Crypto::DataOut(buffer, bufferSize), &encrypted),
		Crypto::CryptoRet::OK);

	constexpr auto sizeForDecryption = Crypto::BufferSizeDecryption<k, bufferSize>::SIZE;
	char bufferDecrypted[sizeForDecryption]{};

	uint64_t decrypted = 0;
	ASSERT_EQ(Crypto::Decrypt(keys->privKey, Crypto::DataIn(buffer, bufferSize),
		Crypto::DataOut(bufferDecrypted, sizeForDecryption), &decrypted),
		Crypto::CryptoRet::OK);

	ASSERT_EQ(std::string(data.pData, data.size), std::string(bufferDecrypted, decrypted));

	ASSERT_EQ(decrypted, inputDataSize);

	ret = true;
}

template <Crypto::KeySize k,
	uint16_t bufferSizePrivate = BUFFER_SIZE_PRIVATE(k),
	uint16_t bufferSizePublic = BUFFER_SIZE_PUBLIC(k)>
	void TestKeyImportExport(Crypto::AsymmetricKeys* keys)
{
	char bufferPrivate[bufferSizePrivate]{};
	char bufferPublic[bufferSizePublic]{};

	uint16_t writtenPrivate = 0, writtenPublic = 0;
	ASSERT_EQ(Crypto::ExportAsymmetricKeys(keys, Crypto::DataOut(bufferPrivate, bufferSizePrivate), &writtenPrivate,
		Crypto::DataOut(bufferPublic, bufferSizePublic), &writtenPublic),
		Crypto::CryptoRet::OK);

	Crypto::AsymmetricKeys importedKeys;
	ASSERT_EQ(Crypto::ImportAsymmetricKeys(&importedKeys, Crypto::DataIn(bufferPrivate, bufferSizePrivate),
		Crypto::DataIn(bufferPublic, bufferSizePublic)),
		Crypto::CryptoRet::OK);

	EXPECT_EQ(importedKeys.keySize, keys->keySize);
	EXPECT_EQ(importedKeys.privKey->keySize, keys->privKey->keySize);
	EXPECT_EQ(importedKeys.privKey->d, keys->privKey->d);
	EXPECT_EQ(importedKeys.privKey->n, keys->privKey->n);

	EXPECT_EQ(importedKeys.pubKey->keySize, keys->pubKey->keySize);
	EXPECT_EQ(importedKeys.pubKey->e, keys->pubKey->e);
	EXPECT_EQ(importedKeys.pubKey->n, keys->pubKey->n);

	EXPECT_EQ(Crypto::DeleteAsymmetricKeys(&importedKeys), Crypto::CryptoRet::OK);
}

template <Crypto::KeySize k>
void TestCrypto(bool& ret)
{
	Crypto::AsymmetricKeys keys;
	ASSERT_EQ(Crypto::CreateAsymmetricKeys(k, &keys), Crypto::CryptoRet::OK);

	TestKeyImportExport<k>(&keys);

	constexpr auto dataLen = 1024;
	char data[dataLen]{};
	CryptoUtils::RandomGenerator gen;
	gen.RandomData(data, dataLen);

	TestThreadedEncryptDecrypt<k, 1024>(ret, &keys, Crypto::DataIn(data, dataLen));
	if (ret)
		TestInplaceEncryptDecrypt<k, 1024>(ret, &keys, Crypto::DataIn(data, dataLen));

	ASSERT_EQ(Crypto::DeleteAsymmetricKeys(&keys), Crypto::CryptoRet::OK);

	ret = true;
}

template <Crypto::KeySize k>
bool TestCrypto(const uint8_t iter, const uint8_t maxIters)
{
	std::cout << "Testing<" << static_cast<uint16_t>(k) << ">"
		<< std::to_string(iter + 1) << "/" << std::to_string(maxIters) << std::endl;

	bool ret = false;
	TestCrypto<k>(ret);

	return ret;
}
}

TEST(CryptoAPITest, CryptoAPITests_Quick)
{
	TestCrypto<Crypto::KeySize::KS_256>(0, 1);
#ifndef _DEBUG
	TestCrypto<Crypto::KeySize::KS_512>(0, 1);
	TestCrypto<Crypto::KeySize::KS_1024>(0, 1);
	TestCrypto<Crypto::KeySize::KS_2048>(0, 1);
#endif
}

#ifndef _DEBUG
TEST(CryptoAPITest, CryptoAPITests_Extended)
{
	for (auto i = 0; i < 25 && TestCrypto<Crypto::KeySize::KS_256>(i, 25); ++i) {}
	for (auto i = 0; i < 15 && TestCrypto<Crypto::KeySize::KS_512>(i, 15); ++i) {}
	for (auto i = 0; i < 5 && TestCrypto<Crypto::KeySize::KS_1024>(i, 5); ++i) {}
	for (auto i = 0; i < 3 && TestCrypto<Crypto::KeySize::KS_2048>(i, 3); ++i) {}
}
#endif
