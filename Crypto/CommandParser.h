#pragma once
#include <map>
#include <list>
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

struct CmdInfo
{
	Command command;
	bool isPrimaryCommand;
	std::unordered_set<uint8_t> allowedParamCount;

	typedef bool is_mandatory;
	std::map<Command, is_mandatory> relatedCommands;

	std::string help;

	std::string detailedHelp;
};

struct CommandData
{
	CmdInfo cmdInfo;
	std::list<std::string> cmdParams;
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

	void ReadParameters(std::list<std::string>& params, const int index);

private:
	const int m_argc;
	char** m_argv;
};

