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
	std::string GetFileName(const Crypto::KeySize keysize, const bool isPrivateKey)
	{
		return "key_" + std::to_string(static_cast<unsigned int>(keysize)) + (isPrivateKey ? ".ppk" : ".pub");
	}

	std::string GetFileName(const bool isPrivateKey)
	{
		return std::string("key") + std::string(isPrivateKey ? ".ppk" : ".pub");
	}

	bool GetKeySize(const std::string& str, Crypto::KeySize& keySize)
	{
		auto num = std::stoi(str);
		bool retVal = true;
		switch (num)
		{
		case 64:
			keySize = Crypto::KeySize::KS_64;
			break;
		case 128:
			keySize = Crypto::KeySize::KS_128;
			break;
		case 256:
			keySize = Crypto::KeySize::KS_256;
			break;
		case 512:
			keySize = Crypto::KeySize::KS_512;
			break;
		case 1024:
			keySize = Crypto::KeySize::KS_1024;
			break;
		case 2048:
			keySize = Crypto::KeySize::KS_2048;
			break;
		case 3072:
			keySize = Crypto::KeySize::KS_3072;
			break;
		default:
			retVal = false;
			break;
		}
		return retVal;
	}
}

bool ExportKeyToFile(Crypto::AsymmetricKeys* pKeys)
{
	char* bufferPub = new char[BUFFER_SIZE_PUBLIC(pKeys->keySize)];
	memset(bufferPub, 0, BUFFER_SIZE_PUBLIC(pKeys->keySize));
	char* bufferPriv = new char[BUFFER_SIZE_PRIVATE(pKeys->keySize)];
	memset(bufferPriv, 0, BUFFER_SIZE_PRIVATE(pKeys->keySize));

	uint16_t writtenPriv = 0;
	uint16_t writtenPub = 0;
	const Crypto::CryptoRet ret = Crypto::ExportAsymmetricKeys(pKeys,
		Crypto::DataOut(bufferPriv, BUFFER_SIZE_PRIVATE(pKeys->keySize)), &writtenPriv,
		Crypto::DataOut(bufferPub, BUFFER_SIZE_PUBLIC(pKeys->keySize)), &writtenPub);

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

	bool retVal = true;
	if (ret != Crypto::CryptoRet::OK)
	{
		retVal = false;
	}
	else if (!WriteKeyToFile(bufferPriv, writtenPriv, true)
		|| !WriteKeyToFile(bufferPub, writtenPub, false))
	{
		std::cerr << "Error in writing keys to file" << std::endl;
		retVal = false;
	}

	delete[] bufferPub;
	delete[] bufferPriv;

	return retVal;
}

bool EncryptDecrypt(const bool encrypt,
	Crypto::AsymmetricKeys* pKeys,
	std::ifstream& in,
	std::ofstream& out,
	const bool inPlace = false)
{
	std::filebuf* pbuf = in.rdbuf();
	if (pbuf == nullptr)
	{
		return false;
	}

	uint64_t dataWritten = 0;
	uint64_t dataRead = 0;
	bool ret = true;

	const auto blockSizeInput = encrypt ? Crypto::GetBlockSizePlain(pKeys->keySize) : Crypto::GetBlockSizeEncrypted(pKeys->keySize);
	const auto blockSizeOutput = encrypt ? Crypto::GetBlockSizeEncrypted(pKeys->keySize) : Crypto::GetBlockSizePlain(pKeys->keySize);
	const auto blocks = 1000U;

	char* input = nullptr;
	char* output = nullptr;
	if (!inPlace)
	{
		input = new char[blocks * blockSizeInput];
		output = new char[blocks * blockSizeOutput];
	}
	else if (blockSizeInput > blockSizeOutput)
	{
		input = new char[blocks * blockSizeInput];
		output = input;
	}
	else
	{
		output = new char[blocks * blockSizeOutput];
		input = output;
	}

	while (in.good() && out.good() && ret)
	{
		memset(input, 0, blocks * blockSizeInput);
		memset(output, 0, blocks * blockSizeOutput);

		const std::streamsize inputLen = pbuf->sgetn(input, blocks * blockSizeInput);
		if (inputLen <= 0)
			break;

		dataRead += (unsigned int)inputLen;

		uint64_t len = 0U;
		Crypto::CryptoRet status = Crypto::CryptoRet::OK;
		if (encrypt)
		{
			status = Crypto::Encrypt(pKeys->pubKey, Crypto::DataIn(input, uint64_t(inputLen)),
				Crypto::DataOut(output, blocks * blockSizeOutput), &len);
		}
		else
		{
			status = Crypto::Decrypt(pKeys->privKey, Crypto::DataIn(input, uint64_t(inputLen)),
				Crypto::DataOut(output, blocks * blockSizeOutput), &len);
		}

		if (status == Crypto::CryptoRet::OK && len > 0U)
		{
			dataWritten += len;
			out.write(output, std::streamsize(len));
		}
		else
		{
			ret = false;
		}
	}

	if (!inPlace)
		delete[] output;
	delete[] input;

	return ret;
}

bool GenerateKeys(const Crypto::KeySize keySize)
{
	bool ret = false;
	std::cout << "Generating asymmetric keys... ";
	Crypto::AsymmetricKeys keys;
	const auto keyGen_start = std::chrono::high_resolution_clock::now();

	if (Crypto::CreateAsymmetricKeys(keySize, &keys) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Error!" << std::endl;
	}
	else
	{
		const auto keyGen_end = std::chrono::high_resolution_clock::now();
		auto keyGen_dur = std::chrono::duration_cast<std::chrono::milliseconds>(keyGen_end - keyGen_start).count();

		std::cout << "Done (" << keyGen_dur << "ms)" << std::endl;
		std::cout << "Storing generated keys to file... ";
		if (ExportKeyToFile(&keys))
		{
			std::cout << "Done" << std::endl;
			ret = true;
		}
		else
		{
			std::cerr << "Error!" << std::endl;
		}
	}
	return ret;
}

template <class KeyType>
bool ImportKey(KeyType* key, const std::string& keyFile)
{
	auto ReadKeyFromFile = [&keyFile](char* buffer, uint16_t& bytes)
	{
		bool ret = false;

		std::ifstream stream;
		if (OpenForRead(keyFile, stream)
			&& !stream.bad())
		{
			std::filebuf* pbuf = stream.rdbuf();
			bytes = uint16_t(pbuf->sgetn(buffer, bytes));
			stream.close();
			ret = bytes > 0;
		}
		return ret;
	};

	uint16_t bufferSize = 2048;
	char buffer[2048] = {};

	Crypto::CryptoRet ret = Crypto::CryptoRet::INTERNAL_ERROR;
	if (ReadKeyFromFile(buffer, bufferSize))
	{
		ret = Crypto::ImportKey(key, Crypto::DataIn(buffer, bufferSize));
	}
	return ret == Crypto::CryptoRet::OK;
}

bool DecryptData(const std::string& fileToDecrypt, const std::string& decryptedFile)
{
	bool ret = false;
	Crypto::AsymmetricKeys keys;
	std::ifstream in;
	std::ofstream out;

	std::cout << "Importing asymmetric private key... ";
	if (!ImportKey(&keys.privKey, GetFileName(true)))
	{
		std::cerr << "Error!" << std::endl;
	}
	else
	{
		std::cout << "Done" << std::endl;
		std::cout << "Opening encrypted & target file... ";
		if (!OpenForRead(fileToDecrypt, in))
		{
			std::cerr << "Error! Opening file '" << fileToDecrypt << "' for decryption failed!" << std::endl;
		}
		else if (!OpenForWrite(decryptedFile, out))
		{
			std::cerr << "Error! Opening file '" << decryptedFile << "' for decrypted data failed!" << std::endl;
		}
		else
		{
			std::cout << "Done" << std::endl;
			std::cout << "Decrypting the file... ";
			const auto start = std::chrono::high_resolution_clock::now();
#if defined(USE_THREADS)
			const bool inPlace = false;
#else
			const bool inPlace = true;
#endif
			ret = EncryptDecrypt(false, &keys, in, out, inPlace);
			const auto end = std::chrono::high_resolution_clock::now();
			const auto keyGen_start = std::chrono::high_resolution_clock::now();
			const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

			if (ret)
				std::cout << "Done (" << duration << "ms)" << std::endl;
			else
				std::cerr << "Error!" << std::endl;
		}
	}

	in.close();
	out.flush();
	out.close();

	if (Crypto::DeleteKey(&keys.privKey) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Deleting Asymmetric private key failed!" << std::endl;
		ret = false;
	}

	return ret;
}

bool EncryptData(const std::string& fileToEncrypt, const std::string& encryptedFile)
{
	bool ret = false;
	Crypto::AsymmetricKeys keys;
	std::ifstream in;
	std::ofstream out;

	std::cout << "Importing asymmetric public key... ";
	if (!ImportKey(&keys.pubKey, GetFileName(false)))
	{
		std::cerr << "Error!" << std::endl;
	}
	else
	{
		std::cout << "Done" << std::endl;
		std::cout << "Opening unencrypted & target file... ";
		if (!OpenForRead(fileToEncrypt, in))
		{
			std::cerr << "Error! Opening file '" << fileToEncrypt << "' for encryption failed!" << std::endl;
		}
		else if (!OpenForWrite(encryptedFile, out))
		{
			std::cerr << "Error! Opening file '" << encryptedFile << "' for encrypted data failed!" << std::endl;
		}
		else
		{
			std::cout << "Done" << std::endl;
			std::cout << "Encrypting the file... ";
			const auto start = std::chrono::high_resolution_clock::now();
#if defined(USE_THREADS)
			const bool inPlace = false;
#else
			const bool inPlace = true;
#endif
			ret = EncryptDecrypt(true, &keys, in, out, inPlace);
			const auto end = std::chrono::high_resolution_clock::now();
			const auto keyGen_start = std::chrono::high_resolution_clock::now();
			const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

			if (ret)
				std::cout << "Done (" << duration << "ms)" << std::endl;
			else
				std::cerr << "Error!" << std::endl;
		}
	}

	in.close();
	out.flush();
	out.close();

	if (Crypto::DeleteKey(&keys.pubKey) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Deleting Asymmetric public key failed!" << std::endl;
		ret = false;
	}

	return ret;
}

int main(int argc, char** argv)
{
	if (argc < 2)
		return -1;
	else if (std::string(argv[1]) == "create_keys")
	{
		Crypto::KeySize keySize;
		if (argc < 2)
		{
			std::cerr << "Error, no keysize provided" << std::endl;
		}
		else if (GetKeySize(argv[2], keySize))
		{
			return GenerateKeys(keySize);
		}
		else
			std::cerr << "Error, invalid keysize" << std::endl;
	}
	else if (std::string(argv[1]) == "encrypt")
		return EncryptData("test.cpp", "test.cpp.enc");
	else if (std::string(argv[1]) == "decrypt")
		return DecryptData("test.cpp.enc", "test_decrypted.cpp");
	else if (std::string(argv[1]) == "test")
	{
		Crypto::KeySize keySize;
		if (GetKeySize(argv[2], keySize))
		{
			BigInt sum;
			for (auto i = 0; i < 25; ++i)
			{
				Crypto::AsymmetricKeys keys;

				const auto start = std::chrono::high_resolution_clock::now();
				Crypto::CreateAsymmetricKeys(keySize, &keys);
				const auto end = std::chrono::high_resolution_clock::now();
				const auto keyGen_start = std::chrono::high_resolution_clock::now();
				const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

				std::cout << "Key generation took: " << duration << " ms" << std::endl;

				sum = sum + duration;
				Crypto::DeleteAsymmetricKeys(&keys);
			}
			std::cout << "Key generation took (avg) : " << (sum / 25).ToDec() << " ms" << std::endl;
		}
	}
	else
		std::cerr << "Error, unknown command" << std::endl;
	return -1;
}
