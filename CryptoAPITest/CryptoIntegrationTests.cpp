#include "pch.h"
#include "gtest/gtest.h"
#include "../CryptoAPI/Crypto.h"
#include "../CryptoAPI/CryptoUtils.h"
#include <cstdio>
#include <fstream>

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
void TestDataSigning(Crypto::AsymmetricKeys* keys)
{
	FILE* tmpFile = std::tmpfile();
	ASSERT_NE(tmpFile, nullptr);
	{
		std::ofstream file(tmpFile);
		char randomData[8192]{};
		CryptoUtils::RandomGenerator gen;
		gen.RandomData(randomData, 8192);
		file.write(randomData, 8192);
	}

	std::ifstream file(tmpFile);
	constexpr auto bufSize = static_cast<uint16_t>(k) / 8;
	char buffer[bufSize]{};
	ASSERT_EQ(Crypto::CreateSignature(keys->privKey, file, Crypto::DataOut(buffer, bufSize)),
		Crypto::CryptoRet::OK);

	bool result = false;
	ASSERT_EQ(Crypto::CheckSignature(keys->pubKey, file, Crypto::DataIn(buffer, bufSize), result),
		Crypto::CryptoRet::OK);

	EXPECT_TRUE(result);
}

template <Crypto::KeySize k>
void TestCrypto(bool& ret)
{
	Crypto::AsymmetricKeys keys;
	ASSERT_EQ(Crypto::CreateAsymmetricKeys(k, &keys), Crypto::CryptoRet::OK) << "Creating asymmetric keys failed";

	TestKeyImportExport<k>(&keys);

	constexpr auto dataLen = 1024;
	char data[dataLen]{};
	CryptoUtils::RandomGenerator gen;
	gen.RandomData(data, dataLen);

	TestThreadedEncryptDecrypt<k, dataLen>(ret, &keys, Crypto::DataIn(data, dataLen));
	if (ret)
		TestInplaceEncryptDecrypt<k, dataLen>(ret, &keys, Crypto::DataIn(data, dataLen));

	TestDataSigning<k>(&keys);

	ASSERT_EQ(Crypto::DeleteAsymmetricKeys(&keys), Crypto::CryptoRet::OK) << "Deleting asymmetric keys failed";

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

template <typename T>
class CryptoAPITest : public ::testing::Test {};

template<Crypto::KeySize k, uint8_t iters>
struct TestRun
{
	static constexpr Crypto::KeySize keySize = k;
	static constexpr uint8_t iterations = iters;
};

#ifndef _DEBUG
using TestRuns = ::testing::Types<TestRun<Crypto::KeySize::KS_256, 25>,
	TestRun<Crypto::KeySize::KS_512, 15>,
	TestRun<Crypto::KeySize::KS_1024, 5>,
	TestRun<Crypto::KeySize::KS_2048, 3>>;
#else
using TestRuns = ::testing::Types<TestRun<Crypto::KeySize::KS_256, 1>>;
#endif
TYPED_TEST_CASE(CryptoAPITest, TestRuns);

TYPED_TEST(CryptoAPITest, CryptoAPITests)
{
	gtest_TypeParam_ param;
	for (auto i = 0; i < param.iterations && TestCrypto<param.keySize>(i, param.iterations); ++i) {}
}
