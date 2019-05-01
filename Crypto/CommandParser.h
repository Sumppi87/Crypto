#pragma once
#include "Crypto.h"
#include <map>
#include <list>
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

		Parameter(uint16_t val)
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
			uint16_t uValue;
			Crypto::KeySize kValue;
			std::string sValue;
		};
	};

	CmdInfo cmdInfo;
	std::list<Parameter> cmdParams;
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

private:
	static bool ValidateCommands(const Commands& commands);

	static std::string GetCommandStr(const Command cmd);

	static bool GetCommandInfo(const Command cmd, CmdInfo& info);

	static std::string GetCommandHelp(const Command command);

	static void PrintDetailedHelp(const std::string command);

	static bool IsCommand(std::string& input);

	bool ReadParameters(const CmdInfo& cmdInfo,
						std::list<CommandData::Parameter>& params,
						const std::vector<std::string>& strParams);

	void ReadParameters(std::vector<std::string>& params, const int index);
	bool ReadParameter(std::string& param, const int index);

private:
	const int m_argc;
	char** m_argv;
};

