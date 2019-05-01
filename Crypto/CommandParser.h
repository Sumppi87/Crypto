#pragma once
#include "Crypto.h"
#include <map>
#include <vector>
#include <unordered_set>
#include <string>

enum class Command
{
	HELP,
	GENERATE_KEYS,
	LOAD_PRIVATE_KEY,
	LOAD_PUBLIC_KEY,
	ENCRYPT,
	DECRYPT,
	THREAD_COUNT,
};

enum class ParamType
{
	INVALID = -1,
	STRING, // Filepath, commands etc
	THREAD_COUNT,
	KEYSIZE
};

struct CmdInfo
{
	Command command;

	bool isPrimaryCommand;

	typedef uint8_t NumOfParams;
	std::map<NumOfParams, std::vector<ParamType>> allowedParams;

	typedef bool is_mandatory;
	std::map<Command, is_mandatory> relatedCommands;

	std::string help;

	std::string detailedHelp;
};

struct CommandData
{
	struct Parameter
	{
		Parameter()
			: type(ParamType::INVALID)
			, uValue(0)
			, kValue(Crypto::KeySize::KS_64)
		{
		}

		Parameter(uint64_t val)
			: type(ParamType::THREAD_COUNT)
			, uValue(val)
			, kValue(Crypto::KeySize::KS_64)
		{
		}

		Parameter(const Crypto::KeySize keySize)
			: type(ParamType::KEYSIZE)
			, uValue(0)
			, kValue(keySize)
		{
		}

		Parameter(const std::string& s)
			: type(ParamType::STRING)
			, uValue(0)
			, kValue(Crypto::KeySize::KS_64)
			, sValue(s)
		{
		}

		ParamType type;
		struct
		{
			//! \brief Numerical parameter, e.g. thread count
			uint64_t uValue;
			//! \brief Keysize
			Crypto::KeySize kValue;
			//! \brief string-value, e.g. filepath/name
			std::string sValue;
		};
	};

	CmdInfo cmdInfo;
	std::vector<Parameter> cmdParams;
};

struct Commands
{
	CommandData primaryCmd;
	std::map<Command, CommandData> otherCmds;
};

class CommandParser
{
public:
	CommandParser(const int argc, char** argv);
	~CommandParser();

	static void PrintHelp();

	bool ReadCommands(Commands& commands);

	static void PrintDetailedHelp(const std::string& command);

private:
	static bool ValidateCommands(const Commands& commands);

	static std::string GetCommandStr(const Command cmd);

	static bool GetCommandInfo(const Command cmd, CmdInfo& info);

	static std::string GetCommandHelp(const Command command);

	static bool IsCommand(std::string& input);

	bool ReadParameters(const CmdInfo& cmdInfo,
						std::vector<CommandData::Parameter>& params,
						const std::vector<std::string>& strParams);

	void ReadParameters(std::vector<std::string>& params, const int index);
	bool ReadParameter(std::string& param, const int index);

private:
	const int m_argc;
	char** m_argv;

	CommandParser& operator=(const CommandParser&) = delete;
};

