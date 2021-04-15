#pragma once

#include <afxstr.h>

class PacketDumper
{
private:
	CString		m_path;			// 转储文件默认存储路径

public:
	PacketDumper();
	~PacketDumper();

	void setPath(CString path);
	CString getPath();
	//CString getFileName();

	void dump(CString path);
	void copyFile(CFile* dest, CFile* src);
};


