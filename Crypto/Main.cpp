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

	const auto blockSizeInput = encrypt ? Crypto::GetBlockSizePlain(pKeys->keySize) : Crypto::GetBlockSizeEncrypted(pKeys->keySize);
	const auto blockSizeOutput = encrypt ? Crypto::GetBlockSizeEncrypted(pKeys->keySize) : Crypto::GetBlockSizePlain(pKeys->keySize);
	const auto blocks = 1000U;
	char* input = new char[blocks * blockSizeInput];
	char* output = new char[blocks * blockSizeOutput];

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

	delete[] input;
	delete[] output;

	return ret;
}

bool EncryptData(Crypto::AsymmetricKeys* pKeys,
	const std::string& fileToEncrypt,
	const std::string& encryptedFile)
{
	bool ret = false;

	std::ifstream in;
	std::ofstream out;
	if (!OpenForRead(fileToEncrypt, in))
	{
		std::cerr << "Failed to open file '" << fileToEncrypt << "' for encryption!" << std::endl;
	}
	else if (!OpenForWrite(encryptedFile, out))
	{
		std::cerr << "Failed to open file '" << encryptedFile << "' for encrypted data!" << std::endl;
	}
	else
	{
		ret = EncryptDecrypt(true, pKeys, in, out);
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

bool EncryptData(const Crypto::KeySize keySize, const std::string& fileToEncrypt, const std::string& encryptedFile)
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
			std::cout << "Encrypting data... ";
			const auto encryption_start = std::chrono::high_resolution_clock::now();

			ret = EncryptData(&keys, fileToEncrypt, encryptedFile);

			const auto encryption_end = std::chrono::high_resolution_clock::now();
			auto encryption_dur = std::chrono::duration_cast<std::chrono::milliseconds>(encryption_end - encryption_start).count();

			if (ret)
				std::cout << "Done (" << encryption_dur << "ms)" << std::endl;
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

	std::cout << "Importing asymmetric keys... ";
	if (!ImportKeys(&keys))
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
			ret = EncryptDecrypt(false, &keys, in, out);
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

	if (Crypto::DeleteAsymmetricKeys(&keys) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Deleting Asymmetric keys failed!" << std::endl;
		ret = false;
	}

	return ret;
}

int main(int argc, char** argv)
{
	if (argc < 2)
		return -1;
	else if (std::string(argv[1]) == "encrypt")
	{
		Crypto::KeySize keySize;
		if (GetKeySize(argv[2], keySize))
		{
			return EncryptData(keySize, "test.cpp", "test.cpp.enc");
		}
		else
			std::cerr << "Error, invalid keysize" << std::endl;
	}
	else if (std::string(argv[1]) == "decrypt")
		return DecryptData("test.cpp.enc", "test_decrypted.cpp");
	else
		std::cerr << "Error, unknown command" << std::endl;
	return -1;
}
