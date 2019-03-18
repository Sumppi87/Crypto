// BigInteger.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "BigInt.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <chrono>
#include <functional>
#include "safeint.h"

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

void Test_RSA()
{
	const char* rawData = "Testing testing !";
	BigInt data = BigInt::FromRawData(rawData, strlen(rawData));
	const std::string fromRawData = data.ToRawData();

	BigInt p("12131072439211271897323671531612440428472427633701410925634549312301964373042085619324197365322416866541017057361365214171711713797974299334871062829803541");
	BigInt q("12027524255478748885956220793734512128733387803682075433653899983955179850988797899869146900809131611153346817050832096022160146366346391812470987105415233");

	BigInt n = p * q;
	BigInt t = (p - 1) * (q - 1);

	BigInt e(65537);
	uint64_t iters = 0;
	while (n.GreatestCommonDivisor(e, iters) != 1)
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
	for (int i = 0; i < 100; ++i)
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

		std::cout << "Encryption took :" << encryption << "us" << std::endl;
		std::cout << "Decryption took :" << decryption << "us" << std::endl;

		const std::string decryptedData = decrypted.ToRawData();

		{
			// yeaah
			std::cout << "Successfully encrypted '" << rawData << "'"
				<< std::endl << "And decrypted it: '" << decryptedData << "'" << std::endl;
		}

		if (decryptedData != rawData)
		{
			std::cout << "Something went wrong, somewhere.." << std::endl;
		}
	}

	std::cout << "Encryption took (avg): " << (encryptionSum / 100).ToDec() << "us" << std::endl;
	std::cout << "Decryption took (avg): " << (decryptionSum / 100).ToDec() << "us" << std::endl;
	std::cout << "Keysize :" << n.GetBitWidth() << " bits" << std::endl;
	std::cout << "Keysize :" << n.CurrentSize() * sizeof(BigInt::Base) << " Bytes" << std::endl;
}

void RSA_Small()
{
	BigInt p(11);
	BigInt q(13);

	BigInt n = p * q;
	BigInt t = (p - 1) * (q - 1);

	BigInt e(7);
	uint64_t iters = 0;
	while (n.GreatestCommonDivisor(e, iters) != 1)
	{
		e = e + 1;
		std::cout << "Booboo" << std::endl;
	}
	// public-key(e, n)
	BigInt d = e.ModuloMultiplicativeInverse(t);

	const char* rawData = "Testing testing !";
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

int main()
{
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

	Test_RSA();

	return 0;
	/**/
	BigInt base8("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
	const BigInt mul8("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

	if (base8 > mul8)
	{

	}
	if (base8 < mul8)
	{

	}
	if (base8 >= mul8)
	{

	}
	if (base8 <= mul8)
	{

	}
	if (base8 != mul8)
	{

	}
	if (base8 == mul8)
	{

	}

	std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
	for (auto i = 0; i < 17; ++i)
	{
		base8 + mul8;
	}
	std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

	auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

	BigInt base32("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
	const BigInt mul32("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

	std::chrono::high_resolution_clock::time_point t3 = std::chrono::high_resolution_clock::now();

	for (auto i = 0; i < 17; ++i)
	{
		base32 + mul32;
	}
	std::chrono::high_resolution_clock::time_point t4 = std::chrono::high_resolution_clock::now();

	auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();

	std::cout << "With u8: " << duration1 << std::endl;
	std::cout << "With u32: " << duration2 << std::endl;
	/**/

	/*
	for (auto i = 0; i < 11; ++i)
	{
		test * BigInt((uint16_t)721);
		std::cout << test.ToHex().c_str() << std::endl;
	}*/


	/*BigInt res((uint16_t)62208);

	for (auto i = 0; i < 21; ++i)
	{
		res * BigInt((uint16_t)62208);
		std::cout << res.ToHex().c_str() << std::endl;
	}*/
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
