// BigInteger.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "SHA3.h"
#include "BigInt.h"
#include "Crypto.h"
#include "CryptoUtils.h"
#include "FileAccess.h"
#include "CommandParser.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <sstream>
#include <string>
#include <chrono>
#include <functional>
#include <map>
#include <unordered_set>
#include "safeint.h"

namespace
{
	std::string GetFileName(const std::string& filepath, const bool isPrivateKey)
	{
		return filepath + std::string(isPrivateKey ? ".ppk" : ".pub");
	}
}

bool ExportKeyToFile(Crypto::AsymmetricKeys* pKeys, const std::string& filepath)
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

	auto WriteKeyToFile = [filepath](const char* buffer, const uint16_t bytes, const bool isPrivate)
	{
		bool ret = false;
		std::ofstream stream;
		if (OpenForWrite(GetFileName(filepath, isPrivate), stream)
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

bool GenerateKeys(const Crypto::KeySize keySize, const std::string& filepath)
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
		if (ExportKeyToFile(&keys, filepath))
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

bool DecryptData(const std::string& keyFile, const std::string& fileToDecrypt, const std::string& decryptedFile)
{
	bool ret = false;
	Crypto::AsymmetricKeys keys;
	std::ifstream in;
	std::ofstream out;

	std::cout << "Importing asymmetric private key... ";
	if (!ImportKey(&keys.privKey, keyFile))
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

bool EncryptData(const std::string& keyFile, const std::string& fileToEncrypt, const std::string& encryptedFile)
{
	bool ret = false;
	Crypto::AsymmetricKeys keys;
	std::ifstream in;
	std::ofstream out;

	std::cout << "Importing asymmetric public key... ";
	if (!ImportKey(&keys.pubKey, keyFile))
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

bool SignData(const std::string& keyFile, const std::string& fileToSign, const std::string& signatureFile)
{
	bool ret = false;
	Crypto::AsymmetricKeys keys;
	std::ifstream in;
	std::ofstream out;

	std::cout << "Importing asymmetric private key... ";
	if (!ImportKey(&keys.privKey, keyFile))
	{
		std::cerr << "Error!" << std::endl;
	}
	else
	{
		std::cout << "Done" << std::endl;
		std::cout << "Opening file to sign & signature file... ";
		if (!OpenForRead(fileToSign, in))
		{
			std::cerr << "Error! Opening file '" << fileToSign << "' for signing failed!" << std::endl;
		}
		else if (!OpenForWrite(signatureFile, out))
		{
			std::cerr << "Error! Opening file '" << signatureFile << "' for storing the signature failed!" << std::endl;
		}
		else
		{
			std::cout << "Done" << std::endl;
			std::cout << "Creating the signature... ";
			const auto start = std::chrono::high_resolution_clock::now();
			const auto bufferSize = Crypto::GetBufferSizeForSignature(keys.privKey->keySize);
			char* buffer = new char[bufferSize] {};
			ret = Crypto::CreateSignature(keys.privKey, in, Crypto::DataOut(buffer, bufferSize)) == Crypto::CryptoRet::OK;

			const auto end = std::chrono::high_resolution_clock::now();
			const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

			if (ret)
			{
				out.write(buffer, bufferSize);
				std::cout << "Done (" << duration << "ms)" << std::endl;
			}
			else
				std::cerr << "Error!" << std::endl;

			delete[] buffer;
		}
	}

	if (Crypto::DeleteKey(&keys.privKey) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Deleting Asymmetric private key failed!" << std::endl;
		ret = false;
	}

	return ret;
}

bool ValidateSignature(const std::string& keyFile, const std::string& fileToCheck, const std::string& signatureFile)
{
	bool ret = false;
	Crypto::AsymmetricKeys keys;
	std::ifstream file;
	std::ifstream signature;

	std::cout << "Importing asymmetric public key... ";
	if (!ImportKey(&keys.pubKey, keyFile))
	{
		std::cerr << "Error!" << std::endl;
	}
	else
	{
		std::cout << "Done" << std::endl;
		std::cout << "Opening file to sign & signature file... ";
		if (!OpenForRead(fileToCheck, file))
		{
			std::cerr << "Error! Opening file '" << fileToCheck << "' for signature checking failed!" << std::endl;
		}
		else if (!OpenForRead(signatureFile, signature))
		{
			std::cerr << "Error! Opening the signature file '" << signatureFile << "' failed!" << std::endl;
		}
		else
		{
			std::cout << "Done" << std::endl;
			std::cout << "Checking the signature... ";
			const auto start = std::chrono::high_resolution_clock::now();
			const auto bufferSize = Crypto::GetBufferSizeForSignature(keys.pubKey->keySize);
			char* buffer = new char[bufferSize] {};
			signature.read(buffer, bufferSize);
			bool match = false;
			ret = Crypto::CheckSignature(keys.pubKey, file, Crypto::DataIn(buffer, bufferSize), match) == Crypto::CryptoRet::OK;

			const auto end = std::chrono::high_resolution_clock::now();
			const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

			if (ret && match)
			{
				std::cout << "Signature matches (" << duration << "ms)" << std::endl;
			}
			else
				std::cerr << "Error!" << std::endl;

			delete[] buffer;
		}
	}

	if (Crypto::DeleteKey(&keys.privKey) != Crypto::CryptoRet::OK)
	{
		std::cerr << "Deleting Asymmetric private key failed!" << std::endl;
		ret = false;
	}

	return ret;
}

int main(int argc, char** argv)
{
	if (argc == 3 && argv[1] == std::string("hash"))
	{
		std::ifstream stream;
		if (OpenForRead(argv[2], stream))
		{
			SHA3::SHA3Hasher hasher;
			char hash[64] {};
			hasher.Process(Crypto::SHA3_Length::SHA3_512, stream, hash);
			std::cout << BigInt::FromRawData(hash, 64).ToHex() << std::endl;
			return 1;
		}
		return -1;
	}
	Commands commands;
	if (!CommandParser(argc, argv).ReadCommands(commands))
	{
		return -1;
	}

	bool ret = true;
	const auto primaryParams = commands.primaryCmd.cmdParams;

	auto threadCountIter = commands.otherCmds.find(Command::THREAD_COUNT);
	if (threadCountIter != commands.otherCmds.end())
	{
		const uint32_t threads = (*threadCountIter).second.cmdParams.at(0).GetValue<uint64_t>();
		Crypto::SetThreadCount(threads);
	}

	switch (commands.primaryCmd.cmdInfo.command)
	{
	case Command::HELP:
		if (commands.primaryCmd.cmdParams.size() == 0)
		{
			CommandParser::PrintHelp();
		}
		else
		{
			CommandParser::PrintDetailedHelp(primaryParams.front().GetValue<std::string>());
		}
		break;
	case Command::GENERATE_KEYS:
		ret = GenerateKeys(primaryParams.at(0).GetValue<Crypto::KeySize>(),
			primaryParams.at(1).GetValue<std::string>());
		break;
	case Command::ENCRYPT:
	{
		auto subCmdIter = commands.otherCmds.find(Command::LOAD_PUBLIC_KEY);
		if (subCmdIter == commands.otherCmds.end())
		{
			std::cerr << "Invalid LOAD_PUBLIC_KEY command!";
			break;
		}
		const CommandData data = (*subCmdIter).second;
		ret = EncryptData(data.cmdParams.at(0).GetValue<std::string>(),
			primaryParams.at(0).GetValue<std::string>(),
			primaryParams.at(1).GetValue<std::string>());
		break;
	}
	case Command::DECRYPT:
	{
		auto subCmdIter = commands.otherCmds.find(Command::LOAD_PRIVATE_KEY);
		if (subCmdIter == commands.otherCmds.end())
		{
			std::cerr << "Invalid LOAD_PRIVATE_KEY command!";
			break;
		}
		const CommandData data = (*subCmdIter).second;
		ret = DecryptData(data.cmdParams.at(0).GetValue<std::string>(),
			primaryParams.at(0).GetValue<std::string>(),
			primaryParams.at(1).GetValue<std::string>());
		break;
	}
	case Command::CREATE_SIGNATURE:
	{
		auto subCmdIter = commands.otherCmds.find(Command::LOAD_PRIVATE_KEY);
		if (subCmdIter == commands.otherCmds.end())
		{
			std::cerr << "Invalid LOAD_PRIVATE_KEY command!";
			break;
		}
		const CommandData data = (*subCmdIter).second;
		ret = SignData(data.cmdParams.at(0).GetValue<std::string>(),
			primaryParams.at(0).GetValue<std::string>(),
			primaryParams.at(1).GetValue<std::string>());
		break;
	}
	case Command::VALIDATE_SIGNATURE:
	{
		auto subCmdIter = commands.otherCmds.find(Command::LOAD_PUBLIC_KEY);
		if (subCmdIter == commands.otherCmds.end())
		{
			std::cerr << "Invalid LOAD_PUBLIC_KEY command!";
			break;
		}
		const CommandData data = (*subCmdIter).second;
		ret = ValidateSignature(data.cmdParams.at(0).GetValue<std::string>(),
			primaryParams.at(0).GetValue<std::string>(),
			primaryParams.at(1).GetValue<std::string>());
		break;
	}
	case Command::LOAD_PRIVATE_KEY:
	case Command::LOAD_PUBLIC_KEY:
	case Command::THREAD_COUNT:
		ret = false;
		break;
	default:
		break;
	}

	return ret == true ? 1 : -1;
}
