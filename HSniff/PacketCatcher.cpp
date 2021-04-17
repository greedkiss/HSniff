#include "pch.h"
#include "PacketCatcher.h"
#include "Packet.h"
#include "Thread.h"


PacketCatcher::PacketCatcher()
{
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
}

PacketCatcher::PacketCatcher(PacketPool* pool)
{
	m_adhandle = NULL;
	m_pool = pool;
	m_dumper = NULL;
}

PacketCatcher::~PacketCatcher()
{
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
}

bool PacketCatcher::setPool(PacketPool* pool)
{
	if (pool)
	{
		m_pool = pool;
		return true;
	}
	return false;
}

//打开网卡，获得文件描述符
bool PacketCatcher::openAdapter(int devIndex, const CTime& currentTime)
{
	if (devIndex < 0 || m_adhandle) {
		return false;
	}

	int count = 0;
	int selDev = devIndex - 1;
	pcap_if_t* dev, * allDevs;

	if (pcap_findalldevs(&allDevs, NULL) == -1) {
		AfxMessageBox(L"查找网络设备错误", MB_OK);
		return false;
	}

	for (dev = allDevs; count < selDev; dev = dev->next, count++);
	//网卡信息
	m_dev = CString(" ( ") + dev->name + CString(" )");

	// 打开网卡
	if ((m_adhandle = pcap_open_live(dev->name,
		65535,						// 最大捕获长度
		PCAP_OPENFLAG_PROMISCUOUS,	// 设置网卡为混杂模式 
		READ_PACKET_TIMEOUT,		// 读取超时时间
		NULL)) == NULL)
	{
		AfxMessageBox(_T("pcap_open_live错误!"), MB_OK);
		return false;
	}

	/* 打开转储文件 */
	CString file = L"HSniff" + currentTime.Format("%Y%m%d%H%M%S") + L".pcap";
	CString path = L"E:\\project\\HSniff\\HSniff\\tmp" + file;
	
	char* char_path = (LPSTR)(LPCTSTR)path;

	m_dumper = pcap_dump_open(m_adhandle, char_path);

	pcap_freealldevs(allDevs);
	return true;
}

//代开文件获得文件描述符
bool PacketCatcher::openAdapter(CString path)
{
	if (path.IsEmpty())
		return false;
	m_dev = path;

	char* char_path = (LPSTR)(LPCTSTR)path;

	if ((m_adhandle = pcap_open_offline(char_path, NULL)) == NULL)
	{
		AfxMessageBox(_T("pcap_open_offline错误!"), MB_OK);
		return false;
	}
	return true;
}

//关闭网卡
bool PacketCatcher::closeAdapter()
{
	if (m_adhandle)
	{
		pcap_close(m_adhandle);
		m_adhandle = NULL;
		if (m_dumper)
		{
			pcap_dump_close(m_dumper);
			m_dumper = NULL;
		}
		return true;
	}
	return false;
}

//处理函数
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ThreadParam* threadParam = (ThreadParam*)param;

	switch (threadParam->m_mode)
	{
	case MODE_CAPTURE_LIVE:
	{
		threadParam->m_pool->add(header, pkt_data);
		pcap_dump((u_char*)threadParam->m_dumper, header, pkt_data);
		break;
	}
	case MODE_CAPTURE_OFFLINE:
	{
		threadParam->m_pool->add(header, pkt_data);
		break;
	}
	}

	PostMessage(AfxGetMainWnd()->m_hWnd, WM_PKTCATCH, NULL, (LPARAM)(threadParam->m_pool->getLast().num));

	// 若是在线抓包，则让线程睡眠0.1秒，防止界面卡顿
	if (threadParam->m_mode == MODE_CAPTURE_LIVE) {
		Sleep(100);
	}
}

UINT capture_thread(LPVOID pParam)
{
	ThreadParam* p = (ThreadParam*)pParam;

	/* 开始捕获数据包 */
	pcap_loop(p->m_adhandle, -1, packet_handler, (unsigned char*)p);
	PostMessage(AfxGetMainWnd()->m_hWnd, WM_TEXIT, NULL, NULL);
	return 0;
}

//开始抓包
void PacketCatcher::startCapture(int mode)
{
	if (m_adhandle && m_pool)
		AfxBeginThread(capture_thread, new ThreadParam(m_adhandle, m_pool, m_dumper, mode));
}

//停止抓包
void PacketCatcher::stopCapture()
{
	if (m_adhandle)
		pcap_breakloop(m_adhandle);
}

CString PacketCatcher::getDevName()
{
	return m_dev;
}
