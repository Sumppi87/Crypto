#include "CommandParser.h"
#include <thread>
#include <sstream>
#include <iostream>
#include <iomanip>

namespace
{
	constexpr const char* CMD_START = "[";
	constexpr const char* CMD_END = "]";
	constexpr const char* OPTIONAL_START = "{";
	constexpr const char* OPTIONAL_END = "}";
	const std::string CMD_PREFIX("--");

	const std::list<Command> COMMANDS = {
		Command::HELP,
		Command::GENERATE_KEYS,
		Command::LOAD_PRIVATE_KEY,
		Command::LOAD_PUBLIC_KEY,
		Command::ENCRYPT,
		Command::DECRYPT,
		Command::CREATE_SIGNATURE,
		Command::VALIDATE_SIGNATURE,
#if defined(USE_THREADS)
		Command::THREAD_COUNT,
#endif
	};

	constexpr bool PRIMARY_CMD = true;

	const std::map<Command, CmdInfo> CMD_INFO =
	{
	{Command::HELP, {Command::HELP, true, { {0, {}}, {1, {ParamType::STRING}} }, {}, "{<detailed help about command>}", "This help"}},


	{Command::GENERATE_KEYS, {Command::GENERATE_KEYS, true, { {2, {ParamType::KEYSIZE, ParamType::STRING}} }, {{Command::THREAD_COUNT, false}},
			"<key width> <filename/path>",
			"<specify a key length to use, e.g. 1024> <filename to store the keys, e.g. C:/Data/key"
			" (public key is exported as *.pub and private *.ppk)>"}},

	{Command::LOAD_PRIVATE_KEY, {Command::LOAD_PRIVATE_KEY, false, { {1, {ParamType::STRING}} }, {},
			"<filename/path>",
			"<file from where to load a private key. Can be absolute or relative filepath, e.g. C:/Data/key.ppk>"}},

	{Command::LOAD_PUBLIC_KEY, {Command::LOAD_PUBLIC_KEY, false, { {1, {ParamType::STRING}} }, {},
			"<filename/path>",
			"<file from where to load a public key. Can be absolute or relative filepath, e.g. C:/Data/key.ppk>"}},

	{Command::ENCRYPT, {Command::ENCRYPT, true, { {2, {ParamType::STRING, ParamType::STRING}} }, {{Command::LOAD_PUBLIC_KEY, true}, {Command::THREAD_COUNT, false}},
			"<file to encrypt> <encrypted file>",
			"<file to encrypt, can be absolute or relative filepath> <encrypted file, can be absolute or relative filepath>"}},

	{Command::DECRYPT, {Command::DECRYPT, true, { {2, {ParamType::STRING, ParamType::STRING}} }, {{Command::LOAD_PRIVATE_KEY, true}, {Command::THREAD_COUNT, false}},
			"<file to decrypt> <decrypted file>",
			"<file to decrypt, can be absolute or relative filepath> <decrypted file, can be absolute or relative filepath>"}},

	{Command::CREATE_SIGNATURE, {Command::CREATE_SIGNATURE, true, { {2, {ParamType::STRING, ParamType::STRING}} }, {{Command::LOAD_PRIVATE_KEY, true}},
			"<file to sign> <created signature>",
			"<file to sign, can be absolute or relative filepath> <created signature file, can be absolute or relative filepath>"}},

	{Command::VALIDATE_SIGNATURE, {Command::VALIDATE_SIGNATURE, true, { {2, {ParamType::STRING, ParamType::STRING}} }, {{Command::LOAD_PUBLIC_KEY, true}},
			"<signature file> <file to validate>",
			"<signature file, can be absolute or relative filepath> <file to be validated againts the signature, can be absolute or relative filepath>"}},

#if defined(USE_THREADS)

	{Command::THREAD_COUNT, {Command::THREAD_COUNT, false, { {1, {ParamType::THREAD_COUNT}} }, {}, []()
			{
				std::stringstream s;
				s << "<Threads [1..." << std::thread::hardware_concurrency() << "]>";
				return s.str();
			}(), []()
			{
				std::stringstream s;
				s << "<how many threads to utilize in operations, must be between [1..." << std::thread::hardware_concurrency() << "]>";
				return s.str();
			}()}},
#endif
	};

	const std::map<std::string, Command> COMMAND_MAP =
	{
		std::make_pair("help", Command::HELP),
		std::make_pair("generate_keys", Command::GENERATE_KEYS),
		std::make_pair("load_private", Command::LOAD_PRIVATE_KEY),
		std::make_pair("load_public", Command::LOAD_PUBLIC_KEY),
		std::make_pair("encrypt", Command::ENCRYPT),
		std::make_pair("decrypt", Command::DECRYPT),
		std::make_pair("sign_file", Command::CREATE_SIGNATURE),
		std::make_pair("signature_check", Command::VALIDATE_SIGNATURE),
#if defined(USE_THREADS)
		std::make_pair("threads", Command::THREAD_COUNT)
#endif
	};

	bool StringToNumber(const std::string& s, uint64_t& val)
	{
		bool ret = false;
		try
		{
			std::string::size_type size;
			val = std::stoull(s, &size);
			if (s.size() == size)
			{
				ret = true;
			}
		}
		catch (...)
		{
		}
		return ret;
	}

	bool GetKeySize(const uint64_t value, Crypto::KeySize& keySize)
	{
		bool retVal = true;
		switch (value)
		{
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

CommandParser::CommandParser(const int argc, char** argv)
	: m_argc(argc)
	, m_argv(argv)
{
}

CommandParser::~CommandParser()
{
}

void CommandParser::PrintHelp()
{
	std::cout << "Usage: " << CMD_START << CMD_PREFIX << "'command'" << CMD_END
		<< " <'parameter'> " << OPTIONAL_START << "'optional parameter'" << OPTIONAL_END
		<< " " << OPTIONAL_START << CMD_START << CMD_PREFIX << "'optional command'" << CMD_END << OPTIONAL_END << std::endl;
	for (const Command cmd : COMMANDS)
	{
		std::cout << "       " << GetCommandHelp(cmd) << std::endl;
	}
}
void CommandParser::PrintDetailedHelp(const std::string& command)
{
	auto iter = COMMAND_MAP.find(command);
	if (iter != COMMAND_MAP.end())
	{
		std::cout << "Usage of '" << command << "'" << std::endl;
		std::cout << CMD_START;
		std::cout << CMD_PREFIX << command;

		CmdInfo info;
		if (GetCommandInfo((*iter).second, info) && info.detailedHelp.size() > 0)
		{
			std::cout << " ";
			std::cout << info.detailedHelp;
		}

		std::cout << CMD_END << std::endl;
	}
	else
	{
		std::cerr << "Unknown command: " << command << std::endl;
	}
}

bool CommandParser::ValidateCommands(const Commands& commands)
{
	bool ret = true;
	// Check that all required commands can be found
	for (auto iter = commands.primaryCmd.cmdInfo.relatedCommands.begin()
		 ; iter != commands.primaryCmd.cmdInfo.relatedCommands.end()
		 ; ++iter)
	{
		const Command c = (*iter).first;
		const CmdInfo::is_mandatory required = (*iter).second;
		if (required == false)
			continue; // no need to check the existance of optional parameters

		auto requiredCmdIter = commands.otherCmds.find(c);
		if (requiredCmdIter == commands.otherCmds.end())
		{
			// Primary command is missing a mandatory support command
			std::cerr << "Incorrectly formatted command sequence" << std::endl;
			PrintHelp();
			ret = false;
			break;
		}
	}

	// Also check that no unexpected commands are present
	for (auto iter = commands.otherCmds.begin(); iter != commands.otherCmds.end(); ++iter)
	{
		auto relatedCmd = commands.primaryCmd.cmdInfo.relatedCommands.find((*iter).second.cmdInfo.command);
		if (relatedCmd == commands.primaryCmd.cmdInfo.relatedCommands.end())
		{
			// Unexpected command
			std::cerr << "Incorrectly formatted command sequence" << std::endl;
			PrintHelp();
			ret = false;
			break;
		}
	}
	return ret;
}

bool CommandParser::ReadCommands(Commands& commands)
{
	if (m_argc < 2)
		return false;

	bool ret = true;

	bool primaryCmdFound = false;

	for (auto i = 1; i < m_argc; ++i)
	{
		std::string input(m_argv[i]);
		if (IsCommand(input))
		{
			CommandData cmdData;
			auto iter = COMMAND_MAP.find(input);
			if (iter != COMMAND_MAP.end() && GetCommandInfo((*iter).second, cmdData.cmdInfo))
			{
				if (primaryCmdFound && cmdData.cmdInfo.isPrimaryCommand)
				{
					std::cerr << "Incorrectly formatted command sequence" << std::endl;
					PrintHelp();
					ret = false;
					break;
				}
				else if (!primaryCmdFound && cmdData.cmdInfo.isPrimaryCommand)
				{
					primaryCmdFound = true;
				}

				// read possible parameters
				std::vector<std::string> params;
				ReadParameters(params, i + 1);
				if (!ReadParameters(cmdData.cmdInfo, cmdData.cmdParams, params))
				{
					// Invalid parameters
					PrintDetailedHelp(input);
					ret = false;
					break;
				}

				if (cmdData.cmdInfo.isPrimaryCommand)
					commands.primaryCmd = cmdData;
				else if (commands.otherCmds.find(cmdData.cmdInfo.command) == commands.otherCmds.end())
					commands.otherCmds.emplace(cmdData.cmdInfo.command, cmdData);
				else
				{
					std::cerr << "Incorrectly formatted command sequence" << std::endl;
					PrintHelp();
					ret = false;
					break;
				}
				i += (int)cmdData.cmdParams.size();
			}
			else
			{
				std::cerr << "Unknown command: " << input << std::endl;
				PrintHelp();
				ret = false;
				break;
			}
		}
		else
		{
			std::cerr << "Incorrectly formatted command sequence" << std::endl;
			PrintHelp();

			ret = false;
			break;
		}
	}
	if (!primaryCmdFound && ret)
	{
		ret = false;
		std::cerr << "Incorrectly formatted command sequence" << std::endl;
		PrintHelp();
	}
	else if (ret)
	{
		ret = ValidateCommands(commands);
	}

	if (!ret)
		commands = Commands();
	return ret;
}

std::string CommandParser::GetCommandStr(const Command cmd)
{
	for (auto iter = COMMAND_MAP.begin(); iter != COMMAND_MAP.end(); ++iter)
	{
		if ((*iter).second == cmd)
			return (*iter).first;
	}
	return "Unkown command";
}

bool CommandParser::GetCommandInfo(const Command cmd, CmdInfo& info)
{
	auto iter = CMD_INFO.find(cmd);
	if (iter != CMD_INFO.end())
	{
		info = (*iter).second;
		return true;
	}
	return false;
}

std::string CommandParser::GetCommandHelp(const Command command)
{
	CmdInfo info;
	GetCommandInfo(command, info);

	std::stringstream s;
	s << CMD_START;
	s << CMD_PREFIX << GetCommandStr(command);

	auto OutputCmdHelp = [&s](const Command c)
	{
		CmdInfo cmdInfo;
		if (GetCommandInfo(c, cmdInfo) && cmdInfo.help.size() > 0)
		{
			s << " ";
			s << cmdInfo.help;
		}
	};

	OutputCmdHelp(command);

	auto related = info.relatedCommands;
	for (auto relatedIter = related.begin(); relatedIter != related.end(); ++relatedIter)
	{
		const Command relatedCmd = (*relatedIter).first;
		const CmdInfo::is_mandatory isMandatory = (*relatedIter).second;
		s << " " << (isMandatory ? "" : OPTIONAL_START) << CMD_PREFIX << GetCommandStr(relatedCmd);
		OutputCmdHelp(relatedCmd);
		s << (isMandatory ? "" : OPTIONAL_END);
	}
	s << CMD_END;
	return s.str();
}

bool CommandParser::IsCommand(std::string& input)
{
	const size_t pos = input.find(CMD_PREFIX);
	if (pos != std::string::npos && input.size() > CMD_PREFIX.size())
	{
		input = input.substr(pos + CMD_PREFIX.size());
		return true;
	}
	return false;
}

bool CommandParser::ReadParameters(const CmdInfo& cmdInfo,
								   std::vector<CommandData::Parameter>& params,
								   const std::vector<std::string>& strParams)
{
	bool ret = true;
	if (params.size() > UINT8_MAX)
	{
		std::cerr << "Invalid amount of parameters" << std::endl;
		return false;
	}
	auto paramsIter = cmdInfo.allowedParams.find((uint8_t)strParams.size());
	if (paramsIter == cmdInfo.allowedParams.end())
	{
		// Correct amount of parameters not found
		std::cerr << "Invalid amount of parameters" << std::endl;
		ret = false;
	}
	else
	{
		const std::vector<ParamType> paramTypes = (*paramsIter).second;
		for (size_t i = 0; i < paramTypes.size(); ++i)
		{
			const ParamType type = paramTypes.at(i);
			const std::string param = strParams.at(i);
			bool isValid = false;
			switch (type)
			{
			case ParamType::STRING:
				if (param.size() > 0)
				{
					// Non-emptry string, assume to be valid
					params.push_back(CommandData::Parameter(param));
					isValid = true;
				}
				break;
			case ParamType::THREAD_COUNT:
			case ParamType::KEYSIZE:
			{
				uint64_t value = 0;
				if (StringToNumber(param, value))
				{
					if (type == ParamType::THREAD_COUNT)
					{
						if (value > 0 && value <= std::thread::hardware_concurrency())
						{
							params.push_back(CommandData::Parameter(value));
							isValid = true;
						}
					}
					else
					{
						Crypto::KeySize keySize;
						if (GetKeySize(value, keySize))
						{
							params.push_back(CommandData::Parameter(keySize));
							isValid = true;
						}
					}
				}
				break;
			}
			case ParamType::INVALID:
				break;
			default:
				break;
			}

			if (!isValid)
			{
				std::cerr << "Invalid parameter: " << param << std::endl;
				ret = false;
			}
		}
	}
	return ret;
}

void CommandParser::ReadParameters(std::vector<std::string>& params, const int index)
{
	for (auto i = index; i < m_argc; ++i)
	{
		std::string param;
		if (!ReadParameter(param, i))
		{
			break;
		}
		params.push_back(param);
	}
}

bool CommandParser::ReadParameter(std::string& param, const int index)
{
	bool ret = false;
	if (index < m_argc)
	{
		std::string tmp(m_argv[index]);
		if (!IsCommand(tmp))
		{
			param = tmp;
			ret = true;
		}
	}
	return ret;
}
