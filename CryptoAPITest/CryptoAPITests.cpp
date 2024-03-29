#include "pch.h"
#include "gtest/gtest.h"
#include "../CryptoAPI/Crypto.h"
#include "../CryptoAPI/CryptoUtils.h"
#include "../Crypto/FileAccess.h"
#include <cstdio>
#include <fstream>
#include <map>

namespace
{
struct Keys
{
	std::string n; // Modulo
	std::string d; // private exponent
	std::string e; // public exponent
};

std::map<Crypto::KeySize, Keys> KEYS{
	{Crypto::KeySize::KS_256, {
	"0x68FD840A2E92A0BCAE02238FE173595FA94AB5AE83CE0927C0F7B1751FA8FD2F\n", // Modulo
	"0x3415906B7CAF410E5944B65FAA788EDD4373EC89F863DFEC6795122E5A0499", // Private exponent
	"0x10001"}}, // Public exponent
	{Crypto::KeySize::KS_512, {
	"0x899114E719B736DE88DAE9A590228AD956793CB3A40E694CD1F2DAC3F0CA53671C791D3AA7D11854AEF37D6610707046BCAC64DEC7E3CC51A54D52DD186968F5\n", // Modulo
	"0x5C13605342321026A8A1258BAC4A8276EFDB1BD6FD32AC263FCBF5C2FA32E1D901C8B612C3FCA3556AA7FB58ADD890E80947EC4F75B8D92F0230FCC9FBBAD7ED", // Private exponent
	"0x10001"}}, // Public exponent
	{Crypto::KeySize::KS_1024, {
	"0x8FC5CBE0D07416B9988B3028F1DE7AF3FF844A784E4CF07C771F3DA7053CD2F5D99168BA21A735F6FAAE7B9912FB49C85C99096B937786C999D3DC3496973D0DF71208A9DA3F53F7E2F9135B94BAE0D855E03BE75F089A937201722FC8CAADED707098D3858DCF64F48854AEFF871E38CA933041F1FF5BA50A94CB79C0CCCB87\n", // Modulo
	"0x8B6CB2D972ED91782CE19633AED3258367E09FE369739DA7E6518A956533E6157B07537B65D56534FD47A61EFD5469E9FF3A7DF3301032CB60FD1EC874DD77DB894DCF5BDF7DDF8C3E8C2125846638DBDEA4B6ACDA4F75EC903F4C60E931380D1757AE8D2061E0277C5086DB66663593CE4A0EAF87D0D2466709FE2309D0F1F1", // Private exponent
	"0x10001"}}, // Public exponent
	{Crypto::KeySize::KS_2048, {
	"0x8E073498093D30551129DCA015A88FA29587F83E3EF94226E71216DEA21054F3FEC26C43379F5BAA2C7F021C813ACC134199A77950FE9221C778C9B4D10A651E082047DC0D83D9AAB7BEC5097DF80DE5045FB9168F32EB74DA13A5BE3FB06DF0E6EDD451995E69503B20581B45EE66BE0A8B6B2CD40E82DE272006479E9A9E1D6D3AC130E4CBA6196CE06CFAA9B0ADF54A5D1E69A01DDE570DED4CFC74AF47ED2A01DDBE2F1BBB3B15567C2B06404A7EF93F1D4FE4A8B096EC940E2E78664F7F88774FB1D065FEFDF5FEC7E5CBD8DFDAAE2DC7420757415A799E46FFAA1E50EFDE37CE1429D170E6B10CD4CD92B76D269B315BA373B24A1F68D303455B0F3F75\n", // Modulo
	"0x346CE676045B08BF2DC1B50586591D03D78C440EBDF2060014253239E5BA7F913D05892EDA964120B4A20126827130A91EFAD7BDC92EDEC4073C47C02DB55793D94E09186A08B44CF6DC3D20FED5945367E4E98E31378B802B8B3B0FD9B48730781D6BD4DEF6E18AD2F8626D56C7E436DBEF9095108576BB07D82359466B2E578383221407EE3DFADC1F061EE019AB50930EA1241AFCBD8DAE00B5B1F56AE92D5C4BE92B2499FD4ACEE14436DDA30C88B428C64DAEFAEA525EBC261206C672DA78E865AABC54B764CABC315425181F803F81D35D0E5C646B120D73466B66516CBE0B3B4379C9993F57BFEFFC11C682320D21A829D11FF29A181A706673833821", // Private exponent
	"0x10001"}}, // Public exponent
	{Crypto::KeySize::KS_3072, {
	"0xA3F264B7C8E20747FDBBA0AC5652A2D6891C13CC55D08C649AAFF89265BF3A062326089898C21D376513DBDB2CDE2A6FC54025909171DDD01C4C62305CA71BFACD82FC3A3AF85A6F763C8D0253A2A65D20AF538F5DE22E1183C0A6455497AE5908B9F92AFDEB5F5B5D0503FE11A18F40E03A98C748B555C060052282415491A11F566F0905CF392F675F9FCABEEC6CB2A5528056079BB13BEFD0A4806892665C31D47D1E6E63FA2992B78AABE20D91C13A28F3617B1B3AEED38B2FEF029D78DDC1BE96ACF59721E3D9D502929E939C707290BD5E2664AB08E6B5F9810EE110CB8D8B9FA2AFF01DECA8785CCDD809EB90109AAE8E4DDA0FCB4670A218A3BB52EBAF62DB9B0D404B87E74347732744B0F5A0B8978124EC59730C7E87D0E5AFAF41B5828D68F296469D0BC60CFBA1A06E8FF35BBB4AC40E15292AFA4365692E4D0ABE3569F54959C3799D9DF7249F42E7B6FA27AF29F83DD7D3B98051DE9C2AF1ABD0C6013BB0F32239B937277A186C74C57EC89BFDE5C5DCC8BE5D190DCCD0D685\n", // Modulo
	"0x91885A5FCAB2DA43CDB900A7FAF8E01411221B7107BC58E3F56CBFFB34D6CB6B27485BD919C136AE35CBAB1EA47592B625230C3588E6CB4031DE9C4AD1F485A1DD4CA91A07BEEE88832CBCFF93BE8E6F9CD40618FDFE096702CDC0CB4A8C5AF82E06E868817EAEE72B6B885FC0C6E9A36D6896B65094A7CA5D72316FEF0E6337E3D996372C3107524D3155676493FAE99A57E2147C2C78E7FBB9FA4D0286F2D664657BABC7D277FEEF7E7E5A960FF592D14E08BE3FC9AC46D502794A71C7D7C195DABFD609226385AD0448BC3FB40EA21F1DC59FE5214297BC63DDB29D420FAEF7A0F44053D585170CE6E8B2A6A082799918CB6704D707A08D2EF1B7D136A2BAAE7F4E3C202B8EB4A95592B3BE64D5640887C63727DA19859800A41A749D9E82F8AF0432CC567AD09710EC987957393C5254A414A0B600B6A84C0ADD634400887DBFAFA95019402274DBDE45D2025CF89C346A4D7D96B3B3AF476BF8A6BC04DFD77A54E9ADE2794A902F07AE1407420DD3D6D0160996A4C6BC3C6C7F96355801", // Private exponent
	"0x10001"}}, // Public exponent
	{Crypto::KeySize::KS_4096, {
	"0xB603E0F93EC0910A82DAB6430E0E8BF5D8E1B531151EA1E41A2624C6B2A654ACFAB385FF3E632C90E80842F936161B87FC0ACB7E8E7646B01AEDBD73E3F0338236C503A76DA990BDA280E80FC6D29BA4D83810D8D04E0EF53D548AB4EB5DFF79638D5F11D0205FB9E77961A4DD08E7154CE899577FDB70179E1FB8B2C7FE89CE02CF2A0130A55DCF1E33C16A10B05248C9687DC1A26DC6CB7294F9DF170D89F8195567B950AE2699AF6D261CBECE304D990BEE7DC985B099E4520CD3F7AF65135A672E9944E79625387F6D4B4AA1DB81AE708A45E23D404D56D93158F955E10EAAFEA6137E671F3D2906B5EC4C50001F44F65D26D3A1D687A2CB35A3A853F064CAE9BC94C790C4BD6A6F987B0C22A5E32910E170DD016FC92D3B255D74E81966447C1EE181AD171B4653C9687DF8C92FC3EBB445F26579CDF840D5452AEC0EBC9427DF70B10D921EFEAA44F523D7EA7DC6E3B47B16CC1CBB9E45214D2FDB39C88E3895EC222DC5A42B313FDE08B74B4A1452C83575B66BD38B7DBD2A3CAB2152CAF92123184209B5EB40F5AD40EB26828A25FF36B1D6A720B7B033DC4DB9D76DC0BDF9D1A274D8FBBAF788CFFBCBB8ECBADB4D052A0AEA0D544430FA8208CC4CC62A0182F80F378C797F34946AC01497EBFAF295D3ED976481AEC70035B3CE8A20DD4B9A3411EC8B6111FFF875955BF43B192C16C9A30023C50978D9ACED81DD\n", // Modulo
	"0x1C7C94EC4D6EF40452208AE009C62B0F8A27212592699DEAC650EBF6912549215D875554725E312E68B24A5118AEF31620534C2FFD79F36C427AACE90366A7991C9B4F0C1834AEAB8F505F81809B9BB27C08A2525C9FAAE5A4F8A350D77979AF74EE3E4FDA6406B760CBF58548F6C8BBE3B28FB54B147C01A644CEB2646CA902AE1BE0361977F82B9F4D785AF24BB6452008938E07AEE8AB14BECE30A53A003AED3419ACBE3CD35BC041F3F211C6D176839A8373FA634B157ACF80A47822624E5A1AC60744EA7DEC4B605E29A77F978C3F51EBC22E3B69E1F0D2C34F6A8E8F4FAD61777A9B90E629BB4F0A8FF60D9B474992C957774DDFF6907AFF6522C6285C4A3F19168B4DDEC786D0011B507651DB755A802A4BCBEE2219916C44416E382555865E91F00E1EA036D8EAF9354AF945C61EF0927C1111204614DE0048D22C32C9985FB9313A6ABB86D24379D5F70A3B5777979DE97F5CBA06BA80E629FE357F24B43D0B9FA32862A592E598F0F87F24D80E4576527CD20399D5E70047FCEBDA97FA372D283E672985FB90C164390136653D84AF8ED72997C00C5E86905BEF7CE5BA7774A67D9ECDDC3F7FD355C9295C66689573D1AEA4161F6CFBB3C8450E2AB26DE7BF3AEE3E153A28E379DF15750A42B087689E44C40701DB94F76128BFBFCF96D04FECF8356D4837EF298F26EDAB1901F242311CD59183FA1CCCC37B54A1", // Private exponent
	"0x10001"}}, // Public exponent
};

template <Crypto::KeySize k,
	uint16_t bufferSizePrivate = BUFFER_SIZE_PRIVATE(k) + 2,
	uint16_t bufferSizePublic = BUFFER_SIZE_PUBLIC(k) + 2>
	void GetStaticKeys(Keys* keys, Crypto::AsymmetricKeys* cryptoKeys, bool& ret)
{
	char bufferPrivate[bufferSizePrivate]{};
	char bufferPublic[bufferSizePublic]{};
	memcpy(bufferPrivate, keys->n.c_str(), keys->n.size());
	memcpy(bufferPrivate + keys->n.size(), keys->d.c_str(), keys->d.size());

	memcpy(bufferPublic, keys->n.c_str(), keys->n.size());
	memcpy(bufferPublic + keys->n.size(), keys->e.c_str(), keys->e.size());

	EXPECT_EQ(Crypto::ImportAsymmetricKeys(cryptoKeys, Crypto::DataIn(bufferPrivate, bufferSizePrivate),
		Crypto::DataIn(bufferPublic, bufferSizePublic)), Crypto::CryptoRet::OK);
	ret = true;
}
}

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
	ASSERT_EQ(Crypto::Decrypt(keys->privKey, Crypto::DataIn(buffer, encrypted),
		Crypto::DataOut(buffer, bufferSize), &decrypted),
		Crypto::CryptoRet::OK);

	ASSERT_EQ(std::string(data.pData, data.size), std::string(buffer, decrypted));

	ASSERT_EQ(decrypted, data.size);

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
	ASSERT_EQ(Crypto::Decrypt(keys->privKey, Crypto::DataIn(buffer, encrypted),
		Crypto::DataOut(bufferDecrypted, sizeForDecryption), &decrypted),
		Crypto::CryptoRet::OK);

	ASSERT_EQ(std::string(data.pData, data.size), std::string(bufferDecrypted, decrypted));

	ASSERT_EQ(decrypted, data.size);

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
	struct TmpFile
	{
		TmpFile() { tmpFile = std::tmpfile(); }
		~TmpFile() { std::fclose(tmpFile); }
		FILE* tmpFile;
	};
	TmpFile tmpFile;
	ASSERT_NE(tmpFile.tmpFile, nullptr);
	{
		std::ofstream file(tmpFile.tmpFile);
		char randomData[8192]{};
		CryptoUtils::RandomGenerator gen;
		gen.RandomData(randomData, 8192);
		file.write(randomData, 8192);
	}

	std::ifstream file(tmpFile.tmpFile);
	constexpr auto bufSize = static_cast<uint16_t>(k) / 8;
	char buffer[bufSize]{};
	ASSERT_EQ(Crypto::CreateSignature(keys->privKey, file, Crypto::DataOut(buffer, bufSize)),
		Crypto::CryptoRet::OK);

	bool result = false;
	ASSERT_EQ(Crypto::CheckSignature(keys->pubKey, file, Crypto::DataIn(buffer, bufSize), result),
		Crypto::CryptoRet::OK);

	EXPECT_TRUE(result);
}

template <Crypto::KeySize k, uint16_t dataLen>
void TestCrypto(Crypto::AsymmetricKeys* keys, Crypto::DataIn data, bool& ret)
{
	TestKeyImportExport<k>(keys);

	TestThreadedEncryptDecrypt<k, dataLen>(ret, keys, data);
	if (ret)
		TestInplaceEncryptDecrypt<k, dataLen>(ret, keys, data);

	TestDataSigning<k>(keys);
}

template <Crypto::KeySize k>
void TestCrypto(bool& ret)
{
	Crypto::AsymmetricKeys keys;
	ASSERT_EQ(Crypto::CreateAsymmetricKeys(k, &keys), Crypto::CryptoRet::OK) << "Creating asymmetric keys failed";

	constexpr auto dataLen = 1024;
	char data[dataLen]{};
	CryptoUtils::RandomGenerator gen;
	gen.RandomData(data, dataLen);

	TestCrypto<k, dataLen>(&keys, Crypto::DataIn(data, dataLen), ret);

	ASSERT_EQ(Crypto::DeleteAsymmetricKeys(&keys), Crypto::CryptoRet::OK) << "Deleting asymmetric keys failed";

	ret = true;
}

template <Crypto::KeySize k>
void TestCrypto(Keys* keys, bool& ret)
{
	Crypto::AsymmetricKeys cryptoKeys;
	GetStaticKeys<k>(keys, &cryptoKeys, ret);
	if (!ret)
		return;

	const char* data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit,"
		" sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. "
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit,"
		" sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. "
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

	TestCrypto<k, 1024>(&cryptoKeys, Crypto::DataIn(data, strlen(data)), ret);

	ASSERT_EQ(Crypto::DeleteAsymmetricKeys(&cryptoKeys), Crypto::CryptoRet::OK) << "Deleting asymmetric keys failed";
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

template <typename T>
class CryptoAPIBasicTest : public ::testing::Test {};

template<Crypto::KeySize k>
struct BasicTestRun
{
	static constexpr Crypto::KeySize keySize = k;
};

template<Crypto::KeySize k, uint8_t iters>
struct TestRun : public BasicTestRun<k>
{
	static constexpr uint8_t iterations = iters;
};

#ifndef _DEBUG
using TestRuns = ::testing::Types<TestRun<Crypto::KeySize::KS_256, 25>,
	TestRun<Crypto::KeySize::KS_512, 10>,
	TestRun<Crypto::KeySize::KS_1024, 3>,
	TestRun<Crypto::KeySize::KS_2048, 1>,
	TestRun<Crypto::KeySize::KS_3072, 1>,
	TestRun<Crypto::KeySize::KS_4096, 1>>;

using BasicTestRuns = ::testing::Types<BasicTestRun<Crypto::KeySize::KS_256>,
	BasicTestRun<Crypto::KeySize::KS_512>,
	BasicTestRun<Crypto::KeySize::KS_1024>,
	BasicTestRun<Crypto::KeySize::KS_2048>,
	BasicTestRun<Crypto::KeySize::KS_3072>,
	BasicTestRun<Crypto::KeySize::KS_4096>>;
#else
using TestRuns = ::testing::Types<TestRun<Crypto::KeySize::KS_256, 1>>;
using BasicTestRuns = ::testing::Types < BasicTestRun<Crypto::KeySize::KS_256>>;
#endif
TYPED_TEST_CASE(CryptoAPITest, TestRuns);
TYPED_TEST_CASE(CryptoAPIBasicTest, BasicTestRuns);

TYPED_TEST(CryptoAPIBasicTest, NegativeTestsCreateKeys)
{
	gtest_TypeParam_ type;
	// Try with an invalid key-pointer
	EXPECT_EQ(Crypto::CreateAsymmetricKeys(type.keySize, nullptr), Crypto::CryptoRet::INVALID_PARAMETER);

	// Try with an invalid keysize
	Crypto::AsymmetricKeys keys;
	EXPECT_EQ(Crypto::CreateAsymmetricKeys(static_cast<Crypto::KeySize>(0), &keys), Crypto::CryptoRet::INVALID_PARAMETER);
	EXPECT_EQ(keys.privKey, nullptr);
	EXPECT_EQ(keys.pubKey, nullptr);
}

TYPED_TEST(CryptoAPIBasicTest, NegativeTestsDeleteKeys)
{
	gtest_TypeParam_ type;
	// Try with an invalid key-pointer
	EXPECT_EQ(Crypto::DeleteAsymmetricKeys(nullptr), Crypto::CryptoRet::INVALID_PARAMETER);

	// Invalid public/private key
	EXPECT_EQ(Crypto::DeleteKey((Crypto::PublicKey*)nullptr), Crypto::CryptoRet::INVALID_PARAMETER);
	EXPECT_EQ(Crypto::DeleteKey((Crypto::PrivateKey*)nullptr), Crypto::CryptoRet::INVALID_PARAMETER);
}

TYPED_TEST(CryptoAPIBasicTest, NegativeTestsExportKeys)
{
	gtest_TypeParam_ type;
	constexpr auto privSize = BUFFER_SIZE_PRIVATE(type.keySize);
	constexpr auto pubSize = BUFFER_SIZE_PUBLIC(type.keySize);
	char bufPriv[privSize]{};
	char bufPub[pubSize]{};
	Crypto::DataOut priv(bufPriv, privSize);
	Crypto::DataOut pub(bufPub, pubSize);
	uint16_t writtenPriv = 0, writtenPub = 0;
	Crypto::AsymmetricKeys keys;
	bool ret = false;
	GetStaticKeys<type.keySize>(&KEYS.at(type.keySize), &keys, ret);
	ASSERT_TRUE(ret);

	// Try with an invalid key-pointer
	EXPECT_EQ(Crypto::ExportAsymmetricKeys(nullptr, priv, &writtenPriv, pub, &writtenPub),
		Crypto::CryptoRet::INVALID_PARAMETER);
	EXPECT_EQ(writtenPriv, 0);
	EXPECT_EQ(writtenPub, 0);

	EXPECT_EQ(Crypto::ExportAsymmetricKeys(&keys, priv, nullptr, pub, &writtenPub),
		Crypto::CryptoRet::INVALID_PARAMETER);
	EXPECT_EQ(writtenPriv, 0);
	EXPECT_EQ(writtenPub, 0);

	EXPECT_EQ(Crypto::ExportAsymmetricKeys(&keys, priv, &writtenPriv, pub, nullptr),
		Crypto::CryptoRet::INVALID_PARAMETER);
	EXPECT_EQ(writtenPriv, 0);
	EXPECT_EQ(writtenPub, 0);

	EXPECT_EQ(Crypto::ExportAsymmetricKeys(&keys, Crypto::DataOut(bufPriv, privSize - 1), &writtenPriv, pub, &writtenPub),
		Crypto::CryptoRet::INSUFFICIENT_BUFFER);
	EXPECT_EQ(writtenPriv, 0);
	EXPECT_EQ(writtenPub, 0);

	EXPECT_EQ(Crypto::ExportAsymmetricKeys(&keys, Crypto::DataOut(nullptr, privSize), &writtenPriv, pub, &writtenPub),
		Crypto::CryptoRet::INVALID_PARAMETER);
	EXPECT_EQ(writtenPriv, 0);
	EXPECT_EQ(writtenPub, 0);

	EXPECT_EQ(Crypto::ExportAsymmetricKeys(&keys, priv, &writtenPriv, Crypto::DataOut(bufPub, pubSize - 1), &writtenPub),
		Crypto::CryptoRet::INSUFFICIENT_BUFFER);
	EXPECT_EQ(writtenPriv, 0);
	EXPECT_EQ(writtenPub, 0);

	EXPECT_EQ(Crypto::ExportAsymmetricKeys(&keys, priv, &writtenPriv, Crypto::DataOut(nullptr, pubSize), &writtenPub),
		Crypto::CryptoRet::INVALID_PARAMETER);
	EXPECT_EQ(writtenPriv, 0);
	EXPECT_EQ(writtenPub, 0);

	// Cleanup
	ASSERT_EQ(Crypto::DeleteAsymmetricKeys(&keys), Crypto::CryptoRet::OK);
}

TYPED_TEST(CryptoAPIBasicTest, APIBasicTests)
{
	gtest_TypeParam_ type;
	bool ret = false;
	auto param = KEYS.at(type.keySize);
	TestCrypto<type.keySize>(&param, ret);
}

TYPED_TEST(CryptoAPITest, IntegrationTests)
{
	gtest_TypeParam_ param;
	for (auto i = 0; i < param.iterations && TestCrypto<param.keySize>(i, param.iterations); ++i) {}
}
