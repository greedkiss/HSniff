#include "pch.h"
#include "PacketDumper.h"

PacketDumper::PacketDumper()
{
}

PacketDumper::~PacketDumper()
{
}

void PacketDumper::setPath(CString path)
{
	m_path = path;
}

CString PacketDumper::getPath()
{
	return m_path;
}

//����ļ�
void PacketDumper::dump(CString path)
{
	CFile dumpFile(m_path, CFile::modeRead | CFile::shareDenyNone);
	CFile saveAsFile(path, CFile::modeCreate | CFile::modeWrite);

	copyFile(&saveAsFile, &dumpFile);

	saveAsFile.Close();
	dumpFile.Close();
}

//����ת���ļ�
void PacketDumper::copyFile(CFile* dest, CFile* src)
{
	char buf[1024];
	int  byteCount;

	while ((byteCount = src->Read(buf, sizeof(buf))) > 0)
		dest->Write(buf, byteCount);
}