// BigInteger.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "BigInt.h"
#include "Crypto.h"
#include "CryptoUtils.h"
#include "FileAccess.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <sstream>
#include <string>
#include <chrono>
#include <functional>
#include <map>
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

	// Command layout, in bits
	// | 7           4 | 3           0 |
	// < params count >< command id    >
	constexpr const uint8_t ONE_PARAM = (1 << 4);
	constexpr const uint8_t TWO_PARAMS = (1 << 5) | ONE_PARAM;
	enum Command
	{
		HELP = 0,
		DETAILS = 1 | ONE_PARAM,
		GENERATE_KEYS = 2 | ONE_PARAM,
		STORE_KEYS = 3 | ONE_PARAM,
		LOAD_PRIVATE_KEY = 4 | ONE_PARAM,
		LOAD_PUBLIC_KEY = 5| ONE_PARAM,
		ENCRYPT = 6 | TWO_PARAMS,
		DECRYPT = 7 | TWO_PARAMS,
#if defined(USE_THREADS)
		THREAD_COUNT = 8 | ONE_PARAM,
#endif
	};

	const std::map<std::string, Command> COMMAND_MAP =
	{
		std::make_pair("help", Command::HELP),
		std::make_pair("details", Command::DETAILS),
		std::make_pair("generate_keys", Command::GENERATE_KEYS),
		std::make_pair("store_keys", Command::STORE_KEYS),
		std::make_pair("load_private", Command::LOAD_PRIVATE_KEY),
		std::make_pair("load_public", Command::LOAD_PUBLIC_KEY),
		std::make_pair("encrypt", Command::ENCRYPT),
		std::make_pair("decrypt", Command::DECRYPT),
#if defined(USE_THREADS)
		std::make_pair("threads", Command::THREAD_COUNT)
#endif
	};

	const std::map<Command, std::string> COMMAND_HELP =
	{
		std::make_pair(Command::GENERATE_KEYS, "<key width>"),
		std::make_pair(Command::STORE_KEYS, "<filename/path>"),
		std::make_pair(Command::LOAD_PRIVATE_KEY, "<file>"),
		std::make_pair(Command::LOAD_PUBLIC_KEY, "<file>"),
		std::make_pair(Command::ENCRYPT, "<file to encrypt> <encrypted file>"),
		std::make_pair(Command::DECRYPT, "<file to decrypt> <decrypted file>"),
#if defined(USE_THREADS)
		std::make_pair(Command::THREAD_COUNT, []()
		{
			std::stringstream s;
			s << "<Threads [1..." << std::thread::hardware_concurrency() << "]>";
			return s.str();
		}())
#endif
	};

	const std::map<Command, std::string> COMMAND_DETAILED_HELP =
	{
		std::make_pair(Command::GENERATE_KEYS, "<specify a key length to use, e.g. 1024>"),
		std::make_pair(Command::STORE_KEYS, "<filename to store the keys, e.g. C:/Data/key (public key is exported as *.pub and private *.ppk)>"),
		std::make_pair(Command::LOAD_PRIVATE_KEY, "<file from where to load a private key. Can be absolute or relative filepath, e.g. C:/Data/key.ppk>"),
		std::make_pair(Command::LOAD_PUBLIC_KEY, "<file where to load a public key. Can be absolute or relative filepath, e.g. C:/Data/key.pub>"),
		std::make_pair(Command::ENCRYPT, "<file to encrypt, can be absolute or relative filepath> <encrypted file, can be absolute or relative filepath>"),
		std::make_pair(Command::DECRYPT, "<file to decrypt, can be absolute or relative filepath> <decrypted file, can be absolute or relative filepath>"),
#if defined(USE_THREADS)
		std::make_pair(Command::THREAD_COUNT, []()
		{
			std::stringstream s;
			s << "<how many threads to utilize in operations, must be between [1..." << std::thread::hardware_concurrency() << "]>";
			return s.str();
		}())
#endif
	};

	constexpr const char CMD_START = '[';
	constexpr const char CMD_END = ']';
	const std::string CMD_PREFIX("--");

	std::string GetCommandHelp(const Command command, const std::string& cmd_str)
	{
		std::stringstream s;
		s << CMD_START;
		s << CMD_PREFIX << cmd_str;

		auto iter = COMMAND_HELP.find(command);
		if (iter != COMMAND_HELP.end())
		{
			s << " ";
			s << (*iter).second;
		}
		s << CMD_END;
		return s.str();
	}

	void PrintHelp()
	{
		std::cout << "Usage: " << std::endl;
		for (auto iter = COMMAND_MAP.begin(); iter != COMMAND_MAP.end(); ++iter)
		{
			std::cout << "     " << GetCommandHelp((*iter).second, (*iter).first) << std::endl;
		}
	}

	void PrintDetailedHelp(const std::string command)
	{
		auto iter = COMMAND_MAP.find(command);
		if (iter != COMMAND_MAP.end())
		{
			std::cout << "Usage of '" << command << "'" << std::endl;
			std::cout << CMD_START;
			std::cout << CMD_PREFIX << command;

			auto iter_detail = COMMAND_DETAILED_HELP.find((*iter).second);
			if (iter_detail != COMMAND_DETAILED_HELP.end())
			{
				std::cout << " ";
				std::cout << (*iter_detail).second;
			}
			std::cout << CMD_END << std::endl;
		}
		else
		{
			std::cerr << "Unknown command: " << command << std::endl;
		}
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
