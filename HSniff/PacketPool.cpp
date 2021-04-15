#include "pch.h"
#include "PacketPool.h"


PacketPool::PacketPool()
{
}

PacketPool::~PacketPool()
{
}

//添加数据到Pool
void PacketPool::add(const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	if (header && pkt_data)
	{
		int pktNum = 1 + m_pkts.size();
		Packet pkt(header, pkt_data, pktNum);
		m_pkts[pktNum] = pkt;
	}
}

//添加数据包
void PacketPool::add(const Packet& pkt) {
	if (!pkt.isEmpty())
		m_pkts[pkt.num] = pkt;
}

//删除数据包
void PacketPool::remove(int pktNum)
{
	if (pktNum < 1 || pktNum > m_pkts.size())
		return;
	m_pkts.erase(pktNum);
}

//清除所有数据包
void PacketPool::clear()
{
	if (m_pkts.size() > 0)
		m_pkts.clear();
}

//根据数据包编号来获取数据包
Packet& PacketPool::get(int pktNum)
{
	if (m_pkts.count(pktNum) > 0)
		return m_pkts[pktNum];
	return Packet();
}

//获取最后一个数据包
Packet& PacketPool::getLast()
{
	if (m_pkts.count(m_pkts.size()) > 0)
		return m_pkts[m_pkts.size()];
	return Packet();
}

//获取数据包个数
int PacketPool::getSize() const
{
	return m_pkts.size();
}

//判断是否有数据包
bool PacketPool::isEmpty() const
{
	if (m_pkts.size())
		return false;
	return true;
}