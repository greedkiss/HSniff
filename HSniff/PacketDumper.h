#pragma once

#include <afxstr.h>

class PacketDumper
{
private:
	CString		m_path;			// ת���ļ�Ĭ�ϴ洢·��

public:
	PacketDumper();
	~PacketDumper();

	void setPath(CString path);
	CString getPath();
	//CString getFileName();

	void dump(CString path);
	void copyFile(CFile* dest, CFile* src);
};


