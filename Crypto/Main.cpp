// BigInteger.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "BigInt.h"
#include "Crypto.h"
#include "CryptoUtils.h"
#include "FileAccess.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <chrono>
#include <functional>
#include "safeint.h"

namespace
{
	const uint16_t ITERS = 1;
	// Returns modulo inverse of a with respect 
	// to m using extended Euclid Algorithm 
	// Assumption: a and m are coprimes, i.e., 
	// gcd(a, m) = 1 
	BigInt modInverse(BigInt a, BigInt m)
	{
		BigInt m0 = m;
		BigInt y = 0, x = 1;

		if (m == 1)
			return 0;

		while (a > 1)
		{
			// q is quotient 
			BigInt q = a / m;
			BigInt t = m;

			// m is remainder now, process same as 
			// Euclid's algo 
			m = a % m, a = t;
			t = y;

			// Update y and x 
			y = x - q * y;
			x = t;
		}

		// Make x positive 
		if (x < 0)
			x = x + m0;

		return x;
	}

	std::string GetFileName(const Crypto::KeySize keysize, const bool isPrivateKey)
	{
		return "key_" + std::to_string(static_cast<unsigned int>(keysize)) + (isPrivateKey ? ".ppk" : ".pub");
	}

	std::string GetFileName(const bool isPrivateKey)
	{
		return std::string("key") + std::string(isPrivateKey ? ".ppk" : ".pub");
	}
}

template< typename T >
std::string NumToHex(const T num, bool padd)
{
	std::stringstream stream;
	stream << std::setfill('0')
		<< std::setw(padd ? sizeof(T) * 2 : 0)
		<< std::hex << num;
	return stream.str();
}

std::string GenerateRandomNumber(const uint64_t bytes)
{
	std::string res("0x");
	const auto count = bytes / sizeof(uint32_t);
	for (auto i = 0; i < count; ++i)
	{
		res.append(NumToHex(rand(), true));
	}

	const size_t bitsInLast = bytes % sizeof(uint32_t);
	if (bitsInLast > 0)
	{
		const auto t = NumToHex(rand(), false);
		res.append(t.begin(), t.begin() + bitsInLast);
	}
	return res;
}

void Compare(const BigInt& v1, const char* h2)
{
	const auto h1 = v1.ToHex();
	if (h1 != h2)
	{
		std::cout << "Error, Hex-values do not match:" << std::endl
			<< "First:  " << h1 << std::endl
			<< "Second: " << h2 << std::endl;
		throw std::logic_error("Invalid Hex-values");
	}
}

void Compare(const BigInt& v1, const BigInt& v2)
{
	const auto h2 = v2.ToHex();
	Compare(v1, h2.c_str());
}

void Test()
{
	BigInt n("0xA01AFEDCBA01");
	BigInt m("0x19F958");
	BigInt s("0x80F958");

	BigInt res("0x103E942EBA76E3E958");

	std::cout << (res / BigInt((uint8_t)2)).ToHex() << std::endl;
	std::cout << (res / BigInt((uint8_t)4)).ToHex() << std::endl;
	std::cout << (res / BigInt((uint8_t)16)).ToHex() << std::endl;


	auto a = (n << 2);
	std::cout << a.ToHex() << std::endl;

	auto c = (s << 10);
	std::cout << c.ToHex() << std::endl;

	Compare(n, (n << 1) >> 1);
	std::cout << n.ToHex() << std::endl;
	std::cout << a.ToHex() << std::endl;
	std::cout << (a >> 8).ToHex() << std::endl;
	std::cout << ((a >> 8) >> 8).ToHex() << std::endl;
	std::cout << (n >> 8).ToHex() << std::endl;

	auto b = (n >> 17);
	std::cout << (n >> 17).ToHex() << std::endl;
	std::cout << (n >> 16).ToHex() << std::endl;
	std::cout << (n >> 9).ToHex() << std::endl;

	n % m;
	std::cout << n.ToHex() << std::endl;

	std::cout << (n - n).ToHex() << std::endl;

	Compare(BigInt("0xFFFFFFFF")
		* BigInt("0xFF0001"),
		BigInt("0xFF0000FF00FFFF"));

	Compare(BigInt("0x100001")
		* BigInt("0x8001"),
		BigInt("0x800108001"));
	Compare(m * n, n * m);
	Compare(m * n, res);
}

void Test2()
{
	const BigInt shifted32("0x841FA01A");
	const BigInt shifted31("0x1083F4035");
	BigInt t8("0x841FA01AFEDCBA01");
	BigInt t16("0x841FA01AFEDCBA01");
	BigInt t32("0x841FA01AFEDCBA01");
	Compare(t8, t16);
	Compare(t16, t32);
	Compare(t8, t32);

	Compare(t8 >> 32, shifted32);
	Compare(t8 >> 31, shifted31);
	Compare(t16 >> 32, shifted32);
	Compare(t16 >> 31, shifted31);
	Compare(t32 >> 32, shifted32);
	Compare(t32 >> 31, shifted31);

	for (uint32_t shift = 1; shift < 33; ++shift)
	{
		Compare(t8 >> shift, t16 >> shift);
		Compare(t16 >> shift, t32 >> shift);
		Compare(t8 >> shift, t32 >> shift);
	}

}

void Test_ModDiv()
{
	Compare(BigInt("0x801") - BigInt("0x2"), "0x7FF");
	{
		BigInt numerator("0x800");
		BigInt div("0x21");

		auto rem = numerator % div;
		auto quot = numerator / div;
		std::cout << quot.ToHex() << std::endl;
		std::cout << rem.ToHex() << std::endl;
	}

	{
		const BigInt numerator("0x109F8F8841FA0197A08DE37ACBFE1DCB211A01");
		const BigInt div("0x716AFC098");

		auto rem = numerator % div;
		auto quot = numerator / div;
		std::cout << quot.ToHex() << std::endl;
		std::cout << rem.ToHex() << std::endl;
	}
}

void TestMulDiv()
{
	uint64_t acc = rand() + 1;

	std::chrono::high_resolution_clock::time_point mulStart = std::chrono::high_resolution_clock::now();

	while (true)
	{
		uint64_t v(rand() + 1);

		uint64_t newAcc = 0;
		if (!msl::utilities::SafeMultiply(v, acc, newAcc))
		{
			break;
		}
		Compare(BigInt(v) * BigInt(acc), BigInt(v * acc));
		acc = newAcc;
	}
	std::chrono::high_resolution_clock::time_point mulEnd = std::chrono::high_resolution_clock::now();
	auto mulDur = std::chrono::duration_cast<std::chrono::microseconds>(mulEnd - mulStart).count();

	std::chrono::high_resolution_clock::time_point divStart = std::chrono::high_resolution_clock::now();

	while (acc > 0)
	{
		uint64_t v(rand() + 1);
		Compare(BigInt(acc) / BigInt(v), BigInt(acc / v));
		acc = acc / v;
	}
	std::chrono::high_resolution_clock::time_point divEnd = std::chrono::high_resolution_clock::now();
	auto divDur = std::chrono::duration_cast<std::chrono::microseconds>(divEnd - divStart).count();

	std::cout << "Mul took: " << mulDur << "us" << std::endl;
	std::cout << "div took: " << divDur << "us" << std::endl;
}

void TestOperands(int64_t v1, int64_t v2)
{
	Compare(BigInt(v1) * BigInt(v2), BigInt(v1 * v2));
	Compare(BigInt(v2) * BigInt(v1), BigInt(v2 * v1));

	Compare(BigInt(v1) - BigInt(v2), BigInt(v1 - v2));
	Compare(BigInt(v2) - BigInt(v1), BigInt(v2 - v1));

	Compare(BigInt(v1) + BigInt(v2), BigInt(v1 + v2));
	Compare(BigInt(v2) + BigInt(v1), BigInt(v2 + v1));

	if (v1 == 0 && v2 == 0)
	{
		return;
	}
	else if (v2 == 0)
	{
		std::swap(v1, v2);
		Compare(BigInt(v1) % BigInt(v2), BigInt(std::abs(v1 % v2)));
		Compare(BigInt(v1) / BigInt(v2), BigInt(v1 / v2));
		return;
	}
	else if (v1 == 0)
	{
		Compare(BigInt(v1) % BigInt(v2), BigInt(std::abs(v1 % v2)));
		Compare(BigInt(v1) / BigInt(v2), BigInt(v1 / v2));
		return;
	}

	Compare(BigInt(v1) % BigInt(v2), BigInt(std::abs(v1 % v2)));
	Compare(BigInt(v2) % BigInt(v1), BigInt(std::abs(v2 % v1)));

	Compare(BigInt(v1) / BigInt(v2), BigInt(v1 / v2));
	Compare(BigInt(v2) / BigInt(v1), BigInt(v2 / v1));

}

void TestWithRand()
{
	union Gen
	{
		Gen()
		{
			t0 = rand() % (UINT8_MAX + 1);
			t1 = rand() % (UINT8_MAX + 1);
			t2 = rand() % (UINT8_MAX + 1);
			t3 = rand() % (UINT8_MAX + 1);
		}

		int value;
		struct
		{
			uint8_t t0;
			uint8_t t1;
			uint8_t t2;
			uint8_t t3;
		};
	};

	for (uint64_t i = 0; i < 10000; ++i)
	{
		int64_t v1 = Gen().value;
		int64_t v2 = Gen().value;

		TestOperands(v1, v2);
	}
}

void TestGCD()
{
	BigInt t1("12131072439211271897323671531612440428472427633701410925634549312301964373042085619324197365322416866541017057361365214171711713797974299334871062829803541");
	BigInt t2("12027524255478748885956220793734512128733387803682075433653899983955179850988797899869146900809131611153346817050832096022160146366346391812470987105415233");
	std::chrono::high_resolution_clock::time_point s = std::chrono::high_resolution_clock::now();

	uint64_t iters = 0;
	auto gcd = t1.GreatestCommonDivisor(t2, iters);

	std::chrono::high_resolution_clock::time_point e = std::chrono::high_resolution_clock::now();
	auto dur = std::chrono::duration_cast<std::chrono::microseconds>(e - s).count();

	std::cout << "Calculating GCD took: "
		<< dur << "us, with '"
		<< iters
		<< "' iterations" << std::endl;
	std::cout << gcd.ToHex() << std::endl;
}

template <Crypto::KeySize keySize,
	uint32_t DATA,
	uint32_t BUF_IN = Crypto::BufferSizeEncryption<keySize, DATA>::SIZE,
	uint32_t BUF_OUT = Crypto::BufferSizeDecryption<keySize, BUF_IN>::SIZE>
	void TestCryptoAPI(Crypto::DataIn rawData, const int iters = ITERS)
{
	//const char* rawData = "Testing1Testing2Testing3Testing4Testing5Testing6Testing7Testing8Testing9Testing0Testing1Testing2Testing3Testing4Testing5Testin";
	std::string data(rawData.pData, rawData.size);

	BigInt keyGenerationSum;
	BigInt encryptionSum;
	BigInt decryptionSum;
	auto failCount = 0;
	for (int i = 0; i < iters; ++i)
	{
		Crypto::AsymmetricKeys keys;
		std::chrono::high_resolution_clock::time_point keygen_start = std::chrono::high_resolution_clock::now();
		auto res = Crypto::CreateAsymmetricKeys(keySize, &keys);
		std::chrono::high_resolution_clock::time_point keygen_end = std::chrono::high_resolution_clock::now();

		char bufferEncrypted[BUF_IN] = {};
		char bufferDecrypted[BUF_OUT] = {};

		uint64_t encrypted = 0;

		std::chrono::high_resolution_clock::time_point encryption_start = std::chrono::high_resolution_clock::now();
		auto resEnc = Crypto::Encrypt(keys.pubKey, rawData, Crypto::DataOut(bufferEncrypted, BUF_IN), &encrypted);
		std::chrono::high_resolution_clock::time_point encryption_end = std::chrono::high_resolution_clock::now();

		uint64_t decrypted = 0;

		std::chrono::high_resolution_clock::time_point decryption_start = std::chrono::high_resolution_clock::now();
		auto resDec = Crypto::Decrypt(keys.privKey, Crypto::DataIn(bufferEncrypted, encrypted), Crypto::DataOut(bufferDecrypted, BUF_OUT), &decrypted);
		std::chrono::high_resolution_clock::time_point decryption_end = std::chrono::high_resolution_clock::now();

		auto encryption = std::chrono::duration_cast<std::chrono::milliseconds>(encryption_end - encryption_start).count();
		auto decryption = std::chrono::duration_cast<std::chrono::milliseconds>(decryption_end - decryption_start).count();
		auto keyGeneration = std::chrono::duration_cast<std::chrono::milliseconds>(keygen_end - keygen_start).count();

		encryptionSum = encryptionSum + encryption;
		decryptionSum = decryptionSum + decryption;
		keyGenerationSum = keyGenerationSum + keyGeneration;

		const std::string decryptedData(bufferDecrypted, decrypted);

		if (decryptedData != data)
		{
			//std::cout << "Something went wrong, somewhere.." << std::endl;
			++failCount;
		}
		else
		{
			//std::cout << "OK!" << std::endl;
		}

		Crypto::DeleteAsymmetricKeys(&keys);
	}

	std::cout << "Failures: " << failCount << "/" << iters << std::endl;
	std::cout << "Key-generation (" << (uint32_t)keySize << "b) took (avg): " << (keyGenerationSum / iters).ToDec() << "ms" << std::endl;
	std::cout << "Encryption took (avg): " << (encryptionSum / iters).ToDec() << "ms" << std::endl;
	std::cout << "Decryption took (avg): " << (decryptionSum / iters).ToDec() << "ms" << std::endl;
}

void Test_EncryptionDecryption()
{
	const char* rawData = "Testing1Testing2Testing3Testing4Testing5Testing6Testing7Testing8Testing9Testing0Testing1Testing2Testing3Testing4Testing5Testin";
	BigInt data = BigInt::FromRawData(rawData, strlen(rawData));
	const std::string fromRawData = data.ToRawData();

	BigInt p("12131072439211271897323671531612440428472427633701410925634549312301964373042085619324197365322416866541017057361365214171711713797974299334871062829803541");
	BigInt q("12027524255478748885956220793734512128733387803682075433653899983955179850988797899869146900809131611153346817050832096022160146366346391812470987105415233");

	BigInt n = p * q;
	BigInt t = (p - 1) * (q - 1);

	BigInt e(65537);
	uint64_t iters = 0;
	while (t.GreatestCommonDivisor(e, iters) != 1)
	{
		e = e + 1;
		std::cout << "Booboo" << std::endl;
	}
	// public-key(e, n)
	BigInt d = e.ModuloMultiplicativeInverse(t);

	/*
	Encryption:

		m^e mod n
		Decryption:

		c^d mod n
	*/

	BigInt encryptionSum;
	BigInt decryptionSum;
	for (int i = 0; i < ITERS; ++i)
	{
		std::chrono::high_resolution_clock::time_point encryption_start = std::chrono::high_resolution_clock::now();
		BigInt encrypted = data.PowMod(e, n);
		std::chrono::high_resolution_clock::time_point encryption_end = std::chrono::high_resolution_clock::now();

		//const std::string encryptedData = encrypted.ToRawData();

		std::chrono::high_resolution_clock::time_point decryption_start = std::chrono::high_resolution_clock::now();
		BigInt decrypted = encrypted.PowMod(d, n);
		std::chrono::high_resolution_clock::time_point decryption_end = std::chrono::high_resolution_clock::now();

		auto encryption = std::chrono::duration_cast<std::chrono::microseconds>(encryption_end - encryption_start).count();
		auto decryption = std::chrono::duration_cast<std::chrono::microseconds>(decryption_end - decryption_start).count();

		encryptionSum = encryptionSum + encryption;
		decryptionSum = decryptionSum + decryption;

		//std::cout << "Encryption took :" << encryption << "us" << std::endl;
		//std::cout << "Decryption took :" << decryption << "us" << std::endl;

		const std::string decryptedData = decrypted.ToRawData();

		{
			// yeaah
			//std::cout << "Successfully encrypted '" << rawData << "'"
				//<< std::endl << "And decrypted it: '" << decryptedData << "'" << std::endl;
		}

		if (decryptedData != rawData)
		{
			std::cout << "Something went wrong, somewhere.." << std::endl;
		}
	}

	std::cout << "Encryption took (avg): " << (encryptionSum / ITERS).ToDec() << "us" << std::endl;
	std::cout << "Decryption took (avg): " << (decryptionSum / ITERS).ToDec() << "us" << std::endl;
	std::cout << "Keysize :" << n.GetBitWidth() << " bits" << std::endl;
	std::cout << "Keysize :" << n.CurrentSize() * sizeof(BigInt::Base) << " Bytes" << std::endl;
}

void Test_PrimeGeneration(const Crypto::KeySize keysize)
{
	//const char* rawData = "Testing1Testing2Testing3Testing4Testing5Testing6Testing7Testing8Testing9Testing0Testing1Testing2Testing3Testing4Testing5Testin";
	//const std::string fromRawData(rawData, strlen(rawData));

	auto rand = CryptoUtils::GetRand();

	for (int i = 1; i <= ITERS; ++i)
	{
		char rawData[273] = {};
		rand->RandomData(rawData, 273);
		std::string fromRawData(rawData, 273);

		uint32_t iters = 0;
		BigInt p = CryptoUtils::GenerateRandomPrime(keysize, iters);
		BigInt q = CryptoUtils::GenerateRandomPrime(keysize, iters);

		auto EncryptionTest = [keysize, i, &rawData, &fromRawData, &p, &q]()
		{
			Crypto::AsymmetricKeys k;
			k.keySize = keysize;
			Crypto::PrivateKey priv;
			Crypto::PublicKey pub;
			k.privKey = &priv;
			k.pubKey = &pub;
			priv.keySize = keysize;
			pub.keySize = keysize;

			BigInt n = p * q;
			BigInt t = (p - 1) * (q - 1);

			BigInt e(3);
			//BigInt e(65537);
			uint64_t iterss = 0;
			while (t.GreatestCommonDivisor(e, iterss) != 1)
			{
				e = e + 1;
				while (!e.IsPrimeNumber())
					e = e + 1;
				//std::cout << "Booboo" << std::endl;
			}
			// public-key(e, n)
			BigInt d = e.ModuloMultiplicativeInverse(t);
			pub.e = e;
			pub.n = n;
			priv.d = d;
			priv.n = n;

			char encrypted[512] = {};
			char decrypted[512] = {};
			uint64_t encryptedBytes = 0;
			uint64_t decryptedBytes = 0;
			auto encryptRet = Crypto::Encrypt(k.pubKey, Crypto::DataIn(rawData, strlen(rawData)), Crypto::DataOut(encrypted, 512), &encryptedBytes);
			auto decryptRet = Crypto::Decrypt(k.privKey, Crypto::DataIn(encrypted, encryptedBytes), Crypto::DataOut(decrypted, 512), &decryptedBytes);

			std::string decryptedData(decrypted, decryptedBytes);
			if (decryptedData != fromRawData)
			{
				return false;
			}
			else
			{
				return true;
			}
		};

		if (!EncryptionTest())
		{
			std::cout << i << ". FAIL" << std::endl;
			/*std::cout << "p: " << p.ToDec() << std::endl;
			std::cout << "q: " << q.ToDec() << std::endl;

			bool succeeded = false;
			auto ii = 0;
			for (; ii < 50; ++ii)
			{
				if (!EncryptionTest())
					std::cout << ii << ". ";
				else
					succeeded = true;
			}

			if (succeeded)
				std::cout << std::endl << "succeeded after " << ii << " attempt" << std::endl << std::endl;
			else
				std::cout << std::endl << "Failed for " << ii << ". times in a row" << std::endl << std::endl;
			*/
		}
		else
		{
			//std::cout << i << ". OK" << std::endl;
			//std::cout << "p: " << p.ToDec() << std::endl;
			//std::cout << "q: " << q.ToDec() << std::endl << std::endl;
		}
	}
}


void Testing(const Crypto::KeySize keysize)
{
	//const char* rawData = "Testing1Testing2Testing3Testing4Testing5Testing6Testing7Testing8Testing9Testing0Testing1Testing2Testing3Testing4Testing5Testin";
	//const char* rawData = "Testing";
	const char* rawData = "Testin";
	const std::string fromRawData(rawData, strlen(rawData));

	for (int i = 1; i <= ITERS; ++i)
	{
		//uint32_t iters = 0;
		//BigInt p = CryptoUtils::GenerateRandomPrime(keysize, iters);
		//BigInt q = CryptoUtils::GenerateRandomPrime(keysize, iters);
		BigInt p(2360893169ULL);
		BigInt q(2754862849ULL);

		Crypto::AsymmetricKeys k;
		k.keySize = keysize;
		Crypto::PrivateKey priv;
		Crypto::PublicKey pub;
		k.privKey = &priv;
		k.pubKey = &pub;
		priv.keySize = keysize;
		pub.keySize = keysize;

		BigInt n = p * q;
		BigInt t = (p - 1) * (q - 1);

		BigInt e(3);
		//BigInt e(65539);
		uint64_t iterss = 0;
		while (t.GreatestCommonDivisor(e, iterss) != 1)
		{
			e = e + 1;
			while (!e.IsPrimeNumber())
				e = e + 1;

			//std::cout << "Booboo" << std::endl;
		}
		// public-key(e, n)
		BigInt d = e.ModuloMultiplicativeInverse(t);
		pub.e = e;
		pub.n = n;
		priv.d = d;
		priv.n = n;

		char encrypted[512] = {};
		char decrypted[512] = {};
		uint64_t encryptedBytes = 0;
		uint64_t decryptedBytes = 0;
		auto encryptRet = Crypto::Encrypt(k.pubKey, Crypto::DataIn(rawData, strlen(rawData)), Crypto::DataOut(encrypted, 512), &encryptedBytes);
		auto decryptRet = Crypto::Decrypt(k.privKey, Crypto::DataIn(encrypted, encryptedBytes), Crypto::DataOut(decrypted, 512), &decryptedBytes);

		std::string decryptedData(decrypted, decryptedBytes);
		if (decryptedData != fromRawData)
		{
			std::cerr << "ERR!" << std::endl;
			//std::cout << p.ToDec() << " : " << q.ToDec() << "  ERR!! " << i << "." << std::endl;
		}
		else
		{
			//std::cout << "OK!! " << p.ToDec() << " : " << q.ToDec() << std::endl;
		}
	}
}

void RSA_Small()
{
	BigInt p(11);
	BigInt q(13);

	BigInt n = p * q;
	BigInt t = (p - 1) * (q - 1);

	std::cout << "Keysize :" << n.GetBitWidth() << " bits" << std::endl;
	std::cout << "Keysize :" << n.CurrentSize() * sizeof(BigInt::Base) << " Bytes" << std::endl;

	BigInt e(7);
	uint64_t iters = 0;
	while (n.GreatestCommonDivisor(e, iters) != 1)
	{
		e = e + 1;
		while (!e.IsPrimeNumber())
			e = e + 1;
		std::cout << "Booboo" << std::endl;
	}
	// public-key(e, n)
	BigInt d = e.ModuloMultiplicativeInverse(t);

	const char* rawData = "Test";
	BigInt data = BigInt::FromRawData(rawData, strlen(rawData));
	const std::string fromRawData = data.ToRawData();


	std::chrono::high_resolution_clock::time_point encryption_start = std::chrono::high_resolution_clock::now();
	BigInt encrypted = data.PowMod(e, n);
	std::chrono::high_resolution_clock::time_point encryption_end = std::chrono::high_resolution_clock::now();

	const std::string encryptedData = encrypted.ToRawData();

	std::chrono::high_resolution_clock::time_point decryption_start = std::chrono::high_resolution_clock::now();
	BigInt decrypted = encrypted.PowMod(d, n);
	std::chrono::high_resolution_clock::time_point decryption_end = std::chrono::high_resolution_clock::now();

	auto encryption = std::chrono::duration_cast<std::chrono::microseconds>(encryption_end - encryption_start).count();
	auto decryption = std::chrono::duration_cast<std::chrono::microseconds>(decryption_end - decryption_start).count();

	std::cout << "Encryption took :" << encryption << "us" << std::endl;
	std::cout << "Decryption took :" << decryption << "us" << std::endl;

	const std::string decryptedData = decrypted.ToRawData();

	if (decryptedData == rawData)
	{
		// yeaah
		std::cout << "Successfully encrypted '" << rawData << "'"
			<< std::endl << "And decrypted it: '" << decryptedData << "'" << std::endl;
	}
	else
	{
		std::cout << "Something went wrong, somewhere.." << std::endl;
	}
}

void TestInPlaceSubs()
{
	BigInt a("-0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFFFFFF7FFFFFFFFFFFFFFFF000000000000101F0000000FFFFFFFF");
	BigInt b("0x80000000000000008000000000000000F000000000000010F0000000FFFFFFFF");
	BigInt res("-0x10000000000000000000000000000000000000000000000000000000000000000E000000000000112E0000001FFFFFFFE");

	//BigInt::Substract(a, b);
	//Compare(a, res);
}

void TestKeyGeneration(const Crypto::KeySize keysize)
{
	uint32_t iters = 0;
	std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
	const BigInt prime = CryptoUtils::GenerateRandomPrime(keysize, iters);
	std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();

	auto dur = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
	auto dur_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	std::cout << "Key generation(" << (uint32_t)keysize << "B / "
		<< prime.GetBitWidth() << "B) took: " << dur << " s"
		<< " And " << uint32_t(dur_us / iters) << " us per iteration"
		<< std::endl;
	std::cout << "Generated prime: " << prime.ToDec() << std::endl;
}

template <Crypto::KeySize k,
	uint16_t priv = BUFFER_SIZE_PRIVATE(k),
	uint16_t pub = BUFFER_SIZE_PUBLIC(k)>
	void Test()
{
	Crypto::AsymmetricKeys keys;
	Crypto::CreateAsymmetricKeys(k, &keys);

	char bufferPub[pub] = {};
	char bufferPriv[priv] = {};

	uint16_t privateBytes = 0;
	uint16_t publicBytes = 0;
	Crypto::NeededBufferSizeForExport(k, &privateBytes, &publicBytes);

	uint16_t writtenPriv = 0;
	uint16_t writtenPub = 0;
	const Crypto::CryptoRet ret = Crypto::ExportAsymmetricKeys(&keys,
		Crypto::DataOut(bufferPriv, priv), &writtenPriv,
		Crypto::DataOut(bufferPub, pub), &writtenPub);

	std::cout << "Public key(" << static_cast<uint16_t>(k) << "b)"
		<< " Template: '" << pub
		<< "' Function: '" << publicBytes
		<< "' Written: '" << writtenPub << "'"
		<< std::endl;
	std::cout << "Private key(" << static_cast<uint16_t>(k) << "b)"
		<< " Template: '" << priv
		<< "' Function: '" << privateBytes
		<< "' Written: '" << writtenPriv << "'"
		<< std::endl;

	auto WriteKeyToFile = [](const char* buffer, const uint16_t bytes, const bool isPrivate)
	{
		bool ret = false;
		std::ofstream stream;
		if (OpenForWrite(GetFileName(isPrivate), stream)
			&& !stream.bad())
		{
			stream.write(buffer, bytes);
			ret = !stream.bad();
			stream.flush();
			ret &= !stream.bad();
			stream.close();
		}
		return ret;
	};

	if (!WriteKeyToFile(bufferPriv, writtenPriv, true)
		|| !WriteKeyToFile(bufferPub, writtenPub, false))
	{
		std::cerr << "Error in writing keys to file" << std::endl;
	}

	Crypto::DeleteAsymmetricKeys(&keys);
}

void TestKeyImport(Crypto::DataIn rawData, std::string& data)
{
	auto ReadKeyFromFile = [](char* buffer, uint16_t& bytes, const bool isPrivate)
	{
		bool ret = false;

		std::ifstream stream;
		if (OpenForRead(GetFileName(isPrivate), stream)
			&& !stream.bad())
		{
			std::filebuf* pbuf = stream.rdbuf();
			bytes = uint16_t(pbuf->sgetn(buffer, bytes));
			//bytes = uint16_t(stream.readsome(buffer, bytes));
			stream.close();
			ret = bytes > 0;
		}
		return ret;
	};

	uint16_t publicBytes = 2048;
	uint16_t privateBytes = 2048;
	char privateKey[2048] = {};
	char publicKey[2048] = {};
	Crypto::AsymmetricKeys keys;

	Crypto::CryptoRet ret = Crypto::CryptoRet::INTERNAL_ERROR;
	if (ReadKeyFromFile(privateKey, privateBytes, true)
		&& ReadKeyFromFile(publicKey, publicBytes, false))
	{
		ret = Crypto::ImportAsymmetricKeys(
			&keys,
			Crypto::DataIn(privateKey, privateBytes),
			Crypto::DataIn(publicKey, publicBytes));
	}

	char bufferDecrypted[4096] = {};
	uint64_t decrypted = 0;

	auto resDec = Crypto::Decrypt(keys.privKey, rawData, Crypto::DataOut(bufferDecrypted, 4096), &decrypted);
	data = std::string(bufferDecrypted, decrypted);

	Crypto::DeleteAsymmetricKeys(&keys);
}

template <Crypto::KeySize k,
	uint16_t priv = BUFFER_SIZE_PRIVATE(k),
	uint16_t pub = BUFFER_SIZE_PUBLIC(k)>
	void TestKeyExport(Crypto::DataIn data, std::string& encrypted)
{
	Crypto::AsymmetricKeys keys;
	Crypto::CreateAsymmetricKeys(k, &keys);

	char bufferPub[pub] = {};
	char bufferPriv[priv] = {};

	uint16_t privateBytes = 0;
	uint16_t publicBytes = 0;
	Crypto::NeededBufferSizeForExport(k, &privateBytes, &publicBytes);

	char buffer[4096] = {};
	uint64_t encryptedBytes = 0;
	Crypto::Encrypt(keys.pubKey, data, Crypto::DataOut(buffer, 4096), &encryptedBytes);
	encrypted = std::string(buffer, encryptedBytes);

	uint16_t writtenPriv = 0;
	uint16_t writtenPub = 0;
	const Crypto::CryptoRet ret = Crypto::ExportAsymmetricKeys(&keys,
		Crypto::DataOut(bufferPriv, priv), &writtenPriv,
		Crypto::DataOut(bufferPub, pub), &writtenPub);

	auto WriteKeyToFile = [](const char* buffer, const uint16_t bytes, const bool isPrivate)
	{
		bool ret = false;
		std::ofstream stream;
		if (OpenForWrite(GetFileName(isPrivate), stream)
			&& !stream.bad())
		{
			stream.write(buffer, bytes);
			ret = !stream.bad();
			stream.flush();
			ret &= !stream.bad();
			stream.close();
		}
		return ret;
	};

	if (!WriteKeyToFile(bufferPriv, writtenPriv, true)
		|| !WriteKeyToFile(bufferPub, writtenPub, false))
	{
		std::cerr << "Error in writing keys to file" << std::endl;
	}

	Crypto::DeleteAsymmetricKeys(&keys);
}

template <Crypto::KeySize k>
void TestKeyExportImport()
{
	std::string encryptedData;
	std::string decryptedData;
	std::string data("Testing1Testing2Testing3Testing4Testing5Testing6Testing7Testing8Testing9Testing0Testing1Testing2Testing3Testing4Testing5Testin");
	TestKeyExport<k>(Crypto::DataIn(data.data(), data.size()), encryptedData);
	TestKeyImport(Crypto::DataIn(encryptedData.data(), encryptedData.size()), decryptedData);

	if (decryptedData != data)
	{
		std::cerr << "Testing key export/import failed! Keysize:"
			<< std::to_string(static_cast<uint32_t>(k)) << std::endl;
	}
	else
	{
		std::cout << "Testing key export/import succeeded! Keysize:"
			<< std::to_string(static_cast<uint32_t>(k)) << std::endl;
	}
}

template <Crypto::KeySize k,
	uint16_t priv = BUFFER_SIZE_PRIVATE(k),
	uint16_t pub = BUFFER_SIZE_PUBLIC(k)>
	bool ExportKeyToFile(Crypto::AsymmetricKeys* pKeys)
{
	char bufferPub[pub] = {};
	char bufferPriv[priv] = {};

	uint16_t writtenPriv = 0;
	uint16_t writtenPub = 0;
	const Crypto::CryptoRet ret = Crypto::ExportAsymmetricKeys(pKeys,
		Crypto::DataOut(bufferPriv, priv), &writtenPriv,
		Crypto::DataOut(bufferPub, pub), &writtenPub);

	auto WriteKeyToFile = [](const char* buffer, const uint16_t bytes, const bool isPrivate)
	{
		bool ret = false;
		std::ofstream stream;
		if (OpenForWrite(GetFileName(isPrivate), stream)
			&& !stream.bad())
		{
			stream.write(buffer, bytes);
			ret = !stream.bad();
			stream.flush();
			ret &= !stream.bad();
			stream.close();
		}
		return ret;
	};

	if (!WriteKeyToFile(bufferPriv, writtenPriv, true)
		|| !WriteKeyToFile(bufferPub, writtenPub, false))
	{
		std::cerr << "Error in writing keys to file" << std::endl;
		return false;
	}
	return true;
}

template <typename unsigned int BUF_IN, typename unsigned int BUF_OUT>
bool EncryptDecrypt(const bool encrypt,
	Crypto::AsymmetricKeys* pKeys,
	std::ifstream& in,
	std::ofstream& out)
{
	std::filebuf* pbuf = in.rdbuf();
	if (pbuf == nullptr)
	{
		return false;
	}

	uint64_t dataWritten = 0;
	uint64_t dataRead = 0;
	bool ret = true;

	while (in.good() && out.good() && ret)
	{
		char input[BUF_IN] = {}; // Data to encrypt
		char output[BUF_OUT] = {}; // Encrypted data

		const std::streamsize inputLen = pbuf->sgetn(input, BUF_IN);
		if (inputLen <= 0)
			break;

		dataRead += (unsigned int)inputLen;

		uint64_t len = 0;
		Crypto::CryptoRet status = Crypto::CryptoRet::OK;
		if (encrypt)
		{
			status = Crypto::Encrypt(pKeys->pubKey, Crypto::DataIn(input, inputLen),
				Crypto::DataOut(output, BUF_OUT), &len);
		}
		else
		{
			status = Crypto::Decrypt(pKeys->privKey, Crypto::DataIn(input, inputLen),
				Crypto::DataOut(output, BUF_OUT), &len);
		}

		if (status == Crypto::CryptoRet::OK && len > 0)
		{
			dataWritten += len;
			out.write(output, len);
		}
		else
		{
			ret = false;
		}
	}

	return ret;
}

template <Crypto::KeySize k,
	uint16_t BUF_IN = ((static_cast<uint64_t>(k) / 8) - 3) * 10,
	uint16_t BUF_OUT = Crypto::BufferSizeEncryption<k, BUF_IN>::SIZE>
	bool EncryptData(Crypto::AsymmetricKeys* pKeys,
		const std::string& fileToEncrypt,
		const std::string& encryptedFile)
{
	bool ret = false;

	std::ifstream in;
	std::ofstream out;
	if (!OpenForRead(fileToEncrypt, in))
	{
		std::cerr << "Failed to file '" << fileToEncrypt << "' for encryption!" << std::endl;
	}
	else if (!OpenForWrite(encryptedFile, out))
	{
		std::cerr << "Failed to open file '" << encryptedFile << "' for encrypted data!" << std::endl;
	}
	else
	{
		ret = EncryptDecrypt<BUF_IN, BUF_OUT>(true, pKeys, in, out);
	}

	in.close();
	out.flush();
	out.close();

	if (Crypto::DeleteAsymmetricKeys(pKeys) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Deleting Asymmetric keys failed!" << std::endl;
		ret = false;
	}
	return ret;
}

template <Crypto::KeySize k>
bool EncryptData(const std::string& fileToEncrypt, const std::string& encryptedFile)
{
	bool ret = false;
	std::cout << "Generating asymmetric keys... ";
	Crypto::AsymmetricKeys keys;
	if (Crypto::CreateAsymmetricKeys(k, &keys) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Error!" << std::endl;
	}
	else
	{
		std::cout << "Done" << std::endl;
		std::cout << "Storing generated keys to file... ";
		if (ExportKeyToFile<k>(&keys))
		{
			std::cout << "Done" << std::endl;
			std::cout << "Encrypting data... ";
			ret = EncryptData<k>(&keys, fileToEncrypt, encryptedFile);
			if (ret)
				std::cout << "Done" << std::endl;
			else
				std::cerr << "Error!" << std::endl;
		}
		else
		{
			std::cerr << "Error!" << std::endl;
		}
	}
	return ret;
}

bool ImportKeys(Crypto::AsymmetricKeys* pKeys)
{
	auto ReadKeyFromFile = [](char* buffer, uint16_t& bytes, const bool isPrivate)
	{
		bool ret = false;

		std::ifstream stream;
		if (OpenForRead(GetFileName(isPrivate), stream)
			&& !stream.bad())
		{
			std::filebuf* pbuf = stream.rdbuf();
			bytes = uint16_t(pbuf->sgetn(buffer, bytes));
			//bytes = uint16_t(stream.readsome(buffer, bytes));
			stream.close();
			ret = bytes > 0;
		}
		return ret;
	};

	uint16_t publicBytes = 2048;
	uint16_t privateBytes = 2048;
	char privateKey[2048] = {};
	char publicKey[2048] = {};

	Crypto::CryptoRet ret = Crypto::CryptoRet::INTERNAL_ERROR;
	if (ReadKeyFromFile(privateKey, privateBytes, true)
		&& ReadKeyFromFile(publicKey, publicBytes, false))
	{
		ret = Crypto::ImportAsymmetricKeys(
			pKeys,
			Crypto::DataIn(privateKey, privateBytes),
			Crypto::DataIn(publicKey, publicBytes));
	}
	return ret == Crypto::CryptoRet::OK;
}

bool DecryptData(const std::string& fileToDecrypt, const std::string& decryptedFile)
{
	bool ret = false;
	Crypto::AsymmetricKeys keys;
	std::ifstream in;
	std::ofstream out;

	if (!ImportKeys(&keys))
	{
		std::cerr << "Importing keys from files failed" << std::endl;
	}
	else if (!OpenForRead(fileToDecrypt, in))
	{
		std::cerr << "Opening file '" << fileToDecrypt << "' for decryption failed!" << std::endl;
	}
	else if (!OpenForWrite(decryptedFile, out))
	{
		std::cerr << "Opening file '" << decryptedFile << "' for decrypted data failed!" << std::endl;
	}
	else
	{
		switch (keys.keySize)
		{
		case Crypto::KeySize::KS_64:
			ret = EncryptDecrypt<(static_cast<uint64_t>(Crypto::KeySize::KS_64) / 8) * 10,
				Crypto::BufferSizeDecryption<Crypto::KeySize::KS_64, (static_cast<uint64_t>(Crypto::KeySize::KS_64) / 8) * 10>::SIZE>
				(false, &keys, in, out);
			break;
		case Crypto::KeySize::KS_128:
			ret = EncryptDecrypt<(static_cast<uint64_t>(Crypto::KeySize::KS_128) / 8) * 10,
				Crypto::BufferSizeDecryption<Crypto::KeySize::KS_128, (static_cast<uint64_t>(Crypto::KeySize::KS_128) / 8) * 10>::SIZE>
				(false, &keys, in, out);
			break;
		case Crypto::KeySize::KS_256:
			ret = EncryptDecrypt<(static_cast<uint64_t>(Crypto::KeySize::KS_256) / 8) * 10,
				Crypto::BufferSizeDecryption<Crypto::KeySize::KS_256, (static_cast<uint64_t>(Crypto::KeySize::KS_256) / 8) * 10>::SIZE>
				(false, &keys, in, out);
			break;
		case Crypto::KeySize::KS_512:
			ret = EncryptDecrypt<(static_cast<uint64_t>(Crypto::KeySize::KS_512) / 8) * 10,
				Crypto::BufferSizeDecryption<Crypto::KeySize::KS_512, (static_cast<uint64_t>(Crypto::KeySize::KS_512) / 8) * 10>::SIZE>
				(false, &keys, in, out);
			break;
		case Crypto::KeySize::KS_1024:
			ret = EncryptDecrypt<(static_cast<uint64_t>(Crypto::KeySize::KS_1024) / 8) * 10,
				Crypto::BufferSizeDecryption<Crypto::KeySize::KS_1024, (static_cast<uint64_t>(Crypto::KeySize::KS_1024) / 8) * 10>::SIZE>
				(false, &keys, in, out);
			break;
		case Crypto::KeySize::KS_2048:
			ret = EncryptDecrypt<(static_cast<uint64_t>(Crypto::KeySize::KS_2048) / 8) * 10,
				Crypto::BufferSizeDecryption<Crypto::KeySize::KS_2048, (static_cast<uint64_t>(Crypto::KeySize::KS_2048) / 8) * 10>::SIZE>
				(false, &keys, in, out);
			break;
		case Crypto::KeySize::KS_3072:
			ret = EncryptDecrypt<(static_cast<uint64_t>(Crypto::KeySize::KS_3072) / 8) * 10,
				Crypto::BufferSizeDecryption<Crypto::KeySize::KS_3072, (static_cast<uint64_t>(Crypto::KeySize::KS_3072) / 8) * 10>::SIZE>
				(false, &keys, in, out);
			break;
		default:
			break;
		}
	}

	in.close();
	out.flush();
	out.close();

	if (Crypto::DeleteAsymmetricKeys(&keys) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Deleting Asymmetric keys failed!" << std::endl;
		ret = false;
	}

	return ret;
}

int main(int argc, char** argv)
{
	if (argc != 2)
		return -1;
	else if (std::string(argv[1]) == "encrypt")
		return EncryptData<Crypto::KeySize::KS_64>("test.cpp", "test.cpp.enc");
	else if (std::string(argv[1]) == "decrypt")
		return DecryptData("test.cpp.enc", "test_decrypted.cpp");
	return -1;

	TestKeyExportImport<Crypto::KeySize::KS_64>();
	TestKeyExportImport<Crypto::KeySize::KS_128>();
	TestKeyExportImport<Crypto::KeySize::KS_256>();
	TestKeyExportImport<Crypto::KeySize::KS_512>();
	TestKeyExportImport<Crypto::KeySize::KS_1024>();
	TestKeyExportImport<Crypto::KeySize::KS_2048>();
	TestKeyExportImport<Crypto::KeySize::KS_3072>();
	return 0;
	Test<Crypto::KeySize::KS_64>();
	Test<Crypto::KeySize::KS_128>();
	Test<Crypto::KeySize::KS_256>();
	Test<Crypto::KeySize::KS_512>();
	Test<Crypto::KeySize::KS_1024>();
	Test<Crypto::KeySize::KS_2048>();
	Test<Crypto::KeySize::KS_3072>();
	return 0;

	/*auto rand = CryptoUtils::GetRand();
	//for (int i = 0; i < 100; ++i)
	{
#define BUFFER 139520
		char data[BUFFER] = {};
		rand->RandomData(data, BUFFER);
		Crypto::DataIn rawData(data, BUFFER);
		TestCryptoAPI<Crypto::KeySize::KS_64, BUFFER>(rawData);
		TestCryptoAPI<Crypto::KeySize::KS_128, BUFFER>(rawData);
		TestCryptoAPI<Crypto::KeySize::KS_256, BUFFER>(rawData);
		TestCryptoAPI<Crypto::KeySize::KS_512, BUFFER>(rawData);
		TestCryptoAPI<Crypto::KeySize::KS_1024, BUFFER>(rawData);
		TestCryptoAPI<Crypto::KeySize::KS_2048, BUFFER>(rawData);
	}*/

	return 0;

	Testing(Crypto::KeySize::KS_64);

	//return 0;

	//TestKeyGeneration(Crypto::KeySize::KS_128);
	//TestKeyGeneration(Crypto::KeySize::KS_256);
	//TestKeyGeneration(Crypto::KeySize::KS_512);
	//while(true)
	//	TestKeyGeneration(Crypto::KeySize::KS_2048);
		//TestKeyGeneration(Crypto::KeySize::KS_1024);
		//TestKeyGeneration(Crypto::KeySize::KS_256);
	//TestKeyGeneration(Crypto::KeySize::KS_3072);

	TestInPlaceSubs();
	{
		Compare(BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80FF0000FF00FFFF")
			+ BigInt("0x8000000000FF0001"),
			BigInt("0x20000000000000000000000000000000000FF000100000000"));

		{ // Same values, but reversed
			Compare(BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80FF0000FF00FFFF")
				+ BigInt("0x8000000000FF0001"),
				BigInt("0x10000000000000000000000000000000000FF000100000000"));

			Compare(BigInt("0x8000000000FF0001")
				+ BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80FF0000FF00FFFF"),
				BigInt("0x10000000000000000000000000000000000FF000100000000"));
		}
		Compare(BigInt("0x7FFFFFFFFFFFFFFF7FFFFFFFFFFFFFFF800000000000000080000000000000008000000000000000")
			+ BigInt("0x80000000000000008000000000000000800000000000000070000000000000008000000000000000"),
			BigInt("0x1000000000000000000000000000000000000000000000000F0000000000000010000000000000000"));

		Compare(BigInt("0xFFFFFFFFFFFFFFFF7FFFFFFFFFFFFFFF8000000000000000F000000000000001F0000000FFFFFFFF")
			+ BigInt("0xFFFFFFFF0000000080000000000000009000000000000000F000000000000001F0000000FFFFFFFF"),
			BigInt("0x1FFFFFFFF0000000000000000000000001000000000000001E000000000000003E0000001FFFFFFFE"));

		Compare(BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFFFFFF7FFFFFFFFFFFFFFFF000000000000101F0000000FFFFFFFF")
			+ BigInt("0x80000000000000008000000000000000F000000000000010F0000000FFFFFFFF"),
			BigInt("0x10000000000000000000000000000000000000000000000000000000000000000E000000000000112E0000001FFFFFFFE"));

		Compare(BigInt("-0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFFFFFF7FFFFFFFFFFFFFFFF000000000000101F0000000FFFFFFFF")
			- BigInt("0x80000000000000008000000000000000F000000000000010F0000000FFFFFFFF"),
			BigInt("-0x10000000000000000000000000000000000000000000000000000000000000000E000000000000112E0000001FFFFFFFE"));
	}
	{
		BigInt t("0xFEDCBA09876543211234567890ABCDEF12FEDCBA09876543211234567890ABCDEF");
		auto t_ = t.GetBitWidth();
		BigInt a = t >> 65;
		auto a_ = a.GetBitWidth();
		BigInt b = t >> 1;
		auto b_ = b.GetBitWidth();
		BigInt c = t >> 63;
		auto c_ = c.GetBitWidth();
	}
	{
		BigInt i("0xFEDCBA09876543211234567890ABCDEF");
		i.GetBitWidth();
		BigInt one = i >> 65;
		BigInt four = i << 4;
		BigInt eigth = i << 8;
		std::cout << i.ToHex() << std::endl;
		std::cout << one.ToHex() << std::endl;
		std::cout << four.ToHex() << std::endl;
		std::cout << eigth.ToHex() << std::endl;
	}
	{
		BigInt i("0x18000000000000001");
		BigInt ii = i + i;
		Compare(ii, i * 2);
		Compare(ii, "0x30000000000000002");
		auto shifted = i >> 8;
		BigInt test(0x100);
		BigInt c = test >> 1;
		BigInt a = test << 64;
		BigInt b = a >> 64;
		Compare(test, b);
	}
	RSA_Small();

	Compare(BigInt("0x109F8F8841FA0197A08DE37ACBFE1DCB211A01") -
		BigInt("0x0C7D9FFF01AFC0A7A08DE37ACBFE1DCB211A01"),
		"0x421EF89404A40F00000000000000000000000");
	{
		//Compare(BigInt("98304723987409653892365982365982") - BigInt("89738549738549734985734773498753"),
		//	BigInt("8566174248859918906631208867229"));
	}

	TestGCD();
	auto a = BigInt(6298) % BigInt(6298);
	BigInt res("0x299");
	auto t = res.PowMod("0x10", "0x123");
	Compare(t, "0x100");

	auto B10 = BigInt("1234567890");
	auto B16 = BigInt("0x499602D2");
	Compare(B10, B16);
	TestMulDiv();

	TestWithRand();

	Test_ModDiv();
	Test2();
	Test();

	//std::cout << std::endl << "Test implementation" << std::endl;
	//Test_EncryptionDecryption();
}
