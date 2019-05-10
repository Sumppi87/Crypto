#pragma once
#include "Crypto.h"
#include <map>
#include <vector>
#include <unordered_set>
#include <string>
#include <any>

enum class Command
{
	HELP,
	GENERATE_KEYS,
	LOAD_PRIVATE_KEY,
	LOAD_PUBLIC_KEY,
	ENCRYPT,
	DECRYPT,
	CREATE_SIGNATURE,
	VALIDATE_SIGNATURE,
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
		{
		}

		Parameter(uint64_t val)
			: type(ParamType::THREAD_COUNT)
			, value(val)
		{
		}

		Parameter(const Crypto::KeySize keySize)
			: type(ParamType::KEYSIZE)
			, value(keySize)
		{
		}

		Parameter(const std::string& s)
			: type(ParamType::STRING)
			, value(s)
		{
		}

		template <typename T>
		inline bool GetValue(T& v) const
		{
			bool ret = false;
			if (value.type() != typeid(T))
				return ret;

			try
			{
				v = std::any_cast<T>(value);
				ret = true;
			}
			catch (const std::bad_any_cast&)
			{
				// Invalid cast
				std::cerr << "std::bad_any_cast while casting std::any to " << typeid(T).name() << std::endl;
			}
			catch (...)
			{
				std::cerr << "Unknown error while casting std::any to " << typeid(T).name() << std::endl;
			}
			return ret;
		}

		template <typename T>
		inline T GetValue() const
		{
			T val;
			if (GetValue(val))
				return val;
			return T();
		}

		ParamType type;
		std::any value;
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

