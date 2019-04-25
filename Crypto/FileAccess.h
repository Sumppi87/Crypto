#pragma once
#include <string>
#include <Windows.h>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <fstream>

int OpenFile(FILE** ppFile,
	const std::string& filename,
	DWORD dwDesiredAccess,
	DWORD dwCreationDisposition,
	const int flags,
	const char* mode)
{
	wchar_t buf[255];
	size_t len = 0;
	mbstowcs_s(&len, buf, 255, filename.c_str(), filename.length());
	std::wstring ws(buf, len);
	FILE* pFile = nullptr;
	HANDLE hFile = CreateFile(ws.c_str(), dwDesiredAccess, 0, NULL, dwCreationDisposition, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "File creation failed\n";
		return -1;
	}

	int file_descriptor = _open_osfhandle((intptr_t)hFile, flags);
	if (file_descriptor != -1)
	{
		pFile = _fdopen(file_descriptor, mode);
		if (pFile == nullptr)
		{
			std::cout << "Opening FD failed\n";
			return -2;
		}
	}
	else
	{
		std::cout << "Opening OSFhandle failed\n";
		return -3;
	}

	(*ppFile) = pFile;
	return 0;
}

bool OpenForRead(const std::string& filename, std::ifstream& stream)
{
	FILE* pFile = nullptr;
	int ret = OpenFile(&pFile, filename, GENERIC_READ, OPEN_EXISTING, _O_RDONLY, "r");
	if (ret != 0)
	{
		return false;
	}

	stream = std::ifstream(pFile);
	if (!stream.is_open())
	{
		std::cout << "Opening the stream failed\n";
		return false;
	}
	return true;
}

bool OpenForWrite(const std::string& filename, std::ofstream& stream)
{
	FILE* pFile = nullptr;
	int ret = OpenFile(&pFile, filename, GENERIC_WRITE, CREATE_ALWAYS, _O_WRONLY, "w");
	if (ret != 0)
	{
		return false;
	}

	stream = std::ofstream(pFile);
	if (!stream.is_open())
	{
		std::cout << "Opening the stream failed\n";
		return false;
	}
	return true;
}
