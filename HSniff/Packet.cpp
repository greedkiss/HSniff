#include "pch.h"
#include "Packet.h"
#include "pcap.h"

Packet::Packet()
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;

	pkt_data = NULL;
	num = -1;
	header = NULL;
}

Packet::Packet(const Packet& p) {
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;

	if (!p.isEmpty())
	{
		u_int caplen = p.header->caplen;

		pkt_data = (u_char*)malloc(caplen);
		memcpy(pkt_data, p.pkt_data, caplen);

		header = (struct pcap_pkthdr*)malloc(sizeof(*(p.header)));
		memcpy(header, p.header, sizeof(*(p.header)));

		num = p.num;

		decodeEthernet();
	}
	else
	{
		pkt_data = NULL;
		header = NULL;
		num = -1;
	}
}

Packet::Packet(const struct pcap_pkthdr* header, const u_char* pkt_data, const u_short& packetNum)
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;
	num = packetNum;

	if (pkt_data != NULL && header != NULL)
	{
		this->pkt_data = (u_char*)malloc(header->caplen);
		memcpy(this->pkt_data, pkt_data, header->caplen);

		this->header = (struct pcap_pkthdr*)malloc(sizeof(*header));
		memcpy(this->header, header, sizeof(*header));

		decodeEthernet();
	}
	else
	{
		this->pkt_data = NULL;
		this->header = NULL;
	}
}

Packet& Packet::operator=(const Packet& p)
{
	if (this == &p)
	{
		return *this;
	}
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;


	if (!p.isEmpty())
	{
		u_int caplen = p.header->caplen;

		if (pkt_data == NULL)
		{
			pkt_data = (u_char*)malloc(caplen);
		}
		memcpy(pkt_data, p.pkt_data, caplen);

		if (header == NULL)
		{
			header = (struct pcap_pkthdr*)malloc(sizeof(*(p.header)));
		}
		memcpy(header, p.header, sizeof(*(p.header)));

		num = p.num;

		decodeEthernet();
	}
	else
	{
		pkt_data = NULL;
		header = NULL;
		httpmsg = NULL;
		num = -1;
	}
	return *this;
}

Packet::~Packet()
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;
	num = -1;

	free(pkt_data);
	pkt_data = NULL;

	free(header);
	header = NULL;
	protocol.Empty();
}

bool Packet::isEmpty() const
{
	if (pkt_data == NULL || header == NULL)
	{
		return true;
	}
	return false;
}

int Packet::decodeEthernet()
{
	if (isEmpty())
	{
		return -1;
	} 

	protocol = "Ethernet";
	ethh = (Ethernet_Header*)pkt_data;

	switch (ntohs(ethh->eth_type))
	{
	case ETHERNET_TYPE_IP:
		decodeIP(pkt_data + ETHERNET_HEADER_LENGTH);
		break;
	case ETHERNET_TYPE_ARP:
		decodeARP(pkt_data + ETHERNET_HEADER_LENGTH);
		break;
	default:
		break;
	}
	return 0;
}

int Packet::decodeIP(u_char* L2payload)
{
	if (L2payload == NULL)
	{
		return -1;
	}

	protocol = "IPv4";
	iph = (IP_Header*)(L2payload);
	u_short IPHeaderLen = (iph->ver_headerlen & 0x0f) * 4;
	switch (iph->protocol)
	{
	case PROTOCOL_ICMP:
		decodeICMP(L2payload + IPHeaderLen);
		break;

	case PROTOCOL_TCP:
		decodeTCP(L2payload + IPHeaderLen);
		break;

	case PROTOCOL_UDP:
		decodeUDP(L2payload + IPHeaderLen);
		break;

	default:
		break;
	}
	return 0;
}

int Packet::decodeARP(u_char* L2payload)
{
	if (L2payload == NULL)
	{
		return -1;
	}
	protocol = "ARP";
	arph = (ARP_Header*)(L2payload);

	return 0;
}

/**
*	@brief	????ICMP????????????????????icmph????
*	@param	L2payload	????ICMP??????????
*	@return	0 ????????????	-1 ????????????
*/
int Packet::decodeICMP(u_char* L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "ICMP";
	icmph = (ICMP_Header*)(L3payload);
	return 0;
}

/**
*	@brief	????TCP??????????????????????tcph??????????????????????????????????
*	@param	L3payload	????TCP????????????
*	@return	0 ????????????	-1 ????????????
*/
int Packet::decodeTCP(u_char* L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "TCP";
	tcph = (TCP_Header*)(L3payload);

	u_short TCPHeaderLen = (ntohs(tcph->headerlen_rsv_flags) >> 12) * 4;
	if (ntohs(tcph->srcport) == PORT_DNS || ntohs(tcph->dstport) == PORT_DNS)
	{
		decodeDNS(L3payload + TCPHeaderLen);
	}
	else if (ntohs(tcph->srcport) == PORT_HTTP || ntohs(tcph->dstport) == PORT_HTTP)
	{
		int HTTPMsgLen = getL4PayloadLength();
		if (HTTPMsgLen > 0)
		{
			decodeHTTP(L3payload + TCPHeaderLen);
		}
	}
	else if(ntohs(tcph->srcport) == PORT_TLS || ntohs(tcph->dstport) == PORT_TLS){
		int TLSLen = getL4PayloadLength();
		if (TLSLen > 0)
		{
			decodeTLS(L3payload + TCPHeaderLen);
		}
	}
	return 0;
}

int Packet::decodeTLS(u_char* L4payload) {
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "TLS";
	TLS = L4payload;
	return 0;
}

/**
*	@brief	????UDP??????????????????????????udph??????????????????????????????????
*	@param	L2payload	????UDP????????????????
*	@return	0 ????????????	-1 ????????????
*/
int Packet::decodeUDP(u_char* L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "UDP";
	udph = (UDP_Header*)(L3payload);
	if (ntohs(udph->srcport) == PORT_DNS || ntohs(udph->dstport) == PORT_DNS)
	{
		decodeDNS(L3payload + UDP_HEADER_LENGTH);

	}
	else if ((ntohs(udph->srcport) == PORT_DHCP_CLIENT && ntohs(udph->dstport) == PORT_DHCP_SERVER) || (ntohs(udph->srcport) == PORT_DHCP_SERVER && ntohs(udph->dstport) == PORT_DHCP_CLIENT))
	{
		decodeDHCP(L3payload + UDP_HEADER_LENGTH);
	}
	return 0;
}

/**
*	@brief	????DNS????????????????????dnsh????
*	@param	L4payload	????DNS??????????
*	@return	0 ????????????	-1 ????????????
*/
int Packet::decodeDNS(u_char* L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "DNS";
	dnsh = (DNS_Header*)(L4payload);
	return 0;
}

/**
*	@brief	????DHCP????????????????????dhcph????
*	@param	L4payload	????DHCP??????????
*	@return	0 ????????????	-1 ????????????
*/
int Packet::decodeDHCP(u_char* L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "DHCP";
	dhcph = (DHCP_Header*)L4payload;
	return 0;
}

/**
*	@brief	????HTTP????????????????????httpmsg????
*	@param	L4payload	????httpmsg??????????
*	@return	0 ????????????	-1 ????????????
*/
int Packet::decodeHTTP(u_char* L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "HTTP";
	httpmsg = L4payload;
	return 0;
}

/**
*	@brief	????IP????????
*	@param	-
*	@return IP????????
*/
int Packet::getIPHeaderLegnth() const
{
	if (iph == NULL)
		return -1;
	else
		return (iph->ver_headerlen & 0x0F) * 4;
}

/**
*	@brief	????IP??????????????
*	@param	-
*	@return IP??????????????	-1	IP????????
*/
int Packet::getIPHeaderLengthRaw() const
{
	if (iph == NULL)
		return -1;
	else
		return (iph->ver_headerlen & 0x0F);
}

/**
*	@brief	????IP????????
*	@param	-
*	@return IP????????	-1	IP????????
*/
int Packet::getIPFlags() const
{
	if (iph == NULL)
		return -1;
	else
		return ntohs(iph->flags_offset) >> 13;
}

/**
*	@brief	????IP????????DF??
*	@param	-
*	@return IP????????DF??	-1	IP????????
*/
int Packet::getIPFlagDF() const
{
	if (iph == NULL)
		return -1;
	else
		return (ntohs(iph->flags_offset) >> 13) & 0x0001;
}

/**
*	@brief	????IP????????MF??
*	@param	-
*	@return IP????????MF??	-1	IP????????
*/
int Packet::getIPFlagsMF() const
{
	if (iph == NULL)
		return -1;
	else
		return (ntohs(iph->flags_offset) >> 14) & 0x0001;
}

/**
*	@brief	????IP??????????
*	@param	-
*	@return IP??????????	-1	IP????????
*/
int Packet::getIPOffset() const
{
	if (iph == NULL)
		return -1;
	else
		return	ntohs(iph->flags_offset) & 0x1FFF;
}

/**
*	@brief	????ICMP????Other????????Id
*	@param	-
*	@return ICMP????Other????????Id	-1	ICMP????????
*/
u_short Packet::getICMPID() const
{
	if (icmph == NULL)
		return -1;
	else
		return (u_short)(ntohl(icmph->others) >> 16);
}

/**
*	@brief	????ICMP????Other????????Seq
*	@param	-
*	@return ICMP????Other????????Seq	-1	ICMP????????
*/
u_short Packet::getICMPSeq() const
{
	if (icmph == NULL)
		return -1;
	else
		return (u_short)(ntohl(icmph->others) & 0x0000FFFF);
}

/**
*	@brief	????TCP????????
*	@param	-
*	@return TCP????????	-1	TCP????????
*/
int Packet::getTCPHeaderLength() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 12) * 4;
}

/**
*	@brief	????TCP??????????????
*	@param	-
*	@return TCP??????????????	-1	TCP????????
*/
int Packet::getTCPHeaderLengthRaw() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 12);
}

/**
*	@brief	????TCP????????
*	@param	-
*	@return TCP????????	-1	TCP????????
*/
u_short Packet::getTCPFlags() const
{
	if (tcph == NULL)
		return -1;
	else
		return  ntohs(tcph->headerlen_rsv_flags) & 0x0FFF;
}

/**
*	@brief	????TCP????????URG
*	@param	-
*	@return TCP????????URG	-1	TCP????????
*/
int Packet::getTCPFlagsURG() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 5) & 0x0001;
}

/**
*	@brief	????TCP????????ACK
*	@param	-
*	@return TCP????????ACK	-1	TCP????????
*/
int Packet::getTCPFlagsACK() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 4) & 0x0001;
}

/**
*	@brief	????TCP????????PSH
*	@param	-
*	@return TCP????????PSH	-1	TCP????????
*/
int Packet::getTCPFlagsPSH() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 3) & 0x0001;
}

/**
*	@brief	????TCP????????RST
*	@param	-
*	@return TCP????????RST	-1	TCP????????
*/
int Packet::getTCPFlagsRST() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 2) & 0x0001;
}

/**
*	@brief	????TCP????????SYN
*	@param	-
*	@return TCP????????SYN	-1	TCP????????
*/
int Packet::getTCPFlagsSYN() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 1) & 0x0001;
}

/**
*	@brief	????TCP????????FIN
*	@param	-
*	@return TCP????????FIN	-1	TCP????????
*/
int Packet::getTCPFlagsFIN() const
{
	if (tcph == NULL)
		return -1;
	else
		return ntohs(tcph->headerlen_rsv_flags) & 0x0001;
}
/**
*	@brief ??????????????????
*	@param	-
*	@return ??????????????
*/
int Packet::getL4PayloadLength() const
{
	if (iph == NULL || tcph == NULL)
	{
		return 0;
	}
	int IPTotalLen = ntohs(iph->totallen);
	int IPHeaderLen = (iph->ver_headerlen & 0x0F) * 4;
	int TCPHeaderLen = (ntohs(tcph->headerlen_rsv_flags) >> 12) * 4;

	return IPTotalLen - IPHeaderLen - TCPHeaderLen;
}

/**
*	@brief	????DNS????????QR
*	@param	-
*	@return DNS????????QR	-1	DNS????????
*/
int Packet::getDNSFlagsQR() const
{
	if (dnsh == NULL)
		return -1;
	else
		return	dnsh->flags >> 15;
}

/**
*	@brief	????DNS????????OPCODE
*	@param	-
*	@return DNS????????OPCODE	-1	DNS????????
*/
int Packet::getDNSFlagsOPCODE() const
{
	if (dnsh == NULL)
		return -1;
	else
		return	(ntohs(dnsh->flags) >> 11) & 0x000F;
}

/**
*	@brief	????DNS????????AA
*	@param	-
*	@return DNS????????AA	-1	DNS????????
*/
int Packet::getDNSFlagsAA() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 10) & 0x0001;
}

/**
*	@brief	????DNS????????TC
*	@param	-
*	@return DNS????????TC	-1	DNS????????
*/
int Packet::getDNSFlagsTC() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 9) & 0x0001;
}

/**
*	@brief	????DNS????????RD
*	@param	-
*	@return DNS????????RD	-1	DNS????????
*/
int Packet::getDNSFlagsRD() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 8) & 0x0001;
}

/**
*	@brief	????DNS????????RA
*	@param	-
*	@return DNS????????RA	-1	DNS????????
*/
int Packet::getDNSFlagsRA() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 7) & 0x0001;
}

/**
*	@brief	????DNS????????Z
*	@param	-
*	@return DNS????????Z	-1	DNS????????
*/
int Packet::getDNSFlagsZ() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 4) & 0x0007;
}

/**
*	@brief	????DNS????????RCODE
*	@param	-
*	@return DNS????????RCODE	-1	DNS????????
*/
int Packet::getDNSFlagsRCODE() const
{
	if (dnsh == NULL)
		return -1;
	else
		return ntohs(dnsh->flags) & 0x000F;
}
