
// HSniffDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "HSniff.h"
#include "HSniffDlg.h"
#include "afxdialogex.h"
#include <vector>
#include "PacketCatcher.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:

	afx_msg void On32771();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)

	ON_COMMAND(ID_32771, &CAboutDlg::On32771)
END_MESSAGE_MAP()


// CHSniffDlg 对话框



CHSniffDlg::CHSniffDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_HSNIFF_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	catcher.setPool(&pool);

	pktCaptureFlag = false;
	fileOpenFlag = false;
}

void CHSniffDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, combo_dev);
	DDX_Control(pDX, IDC_COMBO2, combox_filter);
	DDX_Control(pDX, IDC_LIST2, listCtrl_packetList);
	DDX_Control(pDX, IDC_BUTTON2, Button_start);
	DDX_Control(pDX, IDC_TREE1, treeCtrl_packet);
	DDX_Control(pDX, IDC_EDIT1, edit_packet);
}

BEGIN_MESSAGE_MAP(CHSniffDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()

	//事件处理
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST2, &CHSniffDlg::OnCustomdrawList1)
	ON_NOTIFY(NM_CLICK, IDC_LIST2, &CHSniffDlg::OnNMClickList2)

	ON_BN_CLICKED(IDC_BUTTON1, &CHSniffDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CHSniffDlg::OnBnClickedButton2)
	//捕获网络包的处理函数
	ON_MESSAGE(WM_PKTCATCH, &CHSniffDlg::OnPktCatchMessage)

	ON_BN_CLICKED(IDC_BUTTON3, &CHSniffDlg::OnBnClickedButton3)
	ON_NOTIFY(NM_RCLICK, IDC_LIST2, &CHSniffDlg::OnNMRClickList2)
	ON_COMMAND(ID_32771, &CHSniffDlg::trackTCP)
	ON_BN_CLICKED(IDC_BUTTON4, &CHSniffDlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// CHSniffDlg 消息处理程序

BOOL CHSniffDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// 初始化代码
	initialComboBoxDevList();
	initialComboBoxFilterList();
	initialListCtrlPacketList();
	createDirectory(L".\\tmp");

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CHSniffDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CHSniffDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CHSniffDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

CString translateNameInDNS(const char* name);
void translateData(const DNS_Header* dnsh, char* data1, char* data2, const int data2_len);
int is0xC0PointerInName(char* name);
CString getNameInDNS(char* name, const DNS_Header* pDNSHeader);
CString get0xC0PointerValue(const DNS_Header* pDNSHeader, const int offset);
int is0xC0PointerInName(char* name);

void CHSniffDlg::initialComboBoxDevList()
{
	combo_dev.AddString(_T("选择网络设备"));
	combo_dev.SetCurSel(0);

	pcap_if_t* dev = NULL;
	pcap_if_t* allDevs = NULL;
	if (pcap_findalldevs(&allDevs, NULL) == -1) {
		AfxMessageBox(_T("获取网卡列表失败"), MB_OK);
		return;
	}
	for (dev = allDevs; dev != NULL; dev = dev->next) {
		if (dev->description != NULL) {
			combo_dev.AddString((CString)dev->description);
		}
	}
}

void CHSniffDlg::initialComboBoxFilterList()
{
	std::vector<CString> filterList;
	filterList.push_back(L"Ethernet");
	filterList.push_back(L"IP");
	filterList.push_back(L"ARP");
	filterList.push_back(L"ICMP");
	filterList.push_back(L"TCP");
	filterList.push_back(L"UDP");
	filterList.push_back(L"DNS");
	filterList.push_back(L"DHCP");
	filterList.push_back(L"HTTP");
	filterList.push_back(L"TLS");

	combox_filter.AddString(_T("选择过滤器（可选）"));
	combox_filter.SetCurSel(0);

	for (int i = 0; i < filterList.size(); ++i)
		combox_filter.AddString(filterList[i]);
}

void CHSniffDlg::initialListCtrlPacketList() {
	CRect rect;
	listCtrl_packetList.GetWindowRect(&rect);
	//左键单选加整行选中
	listCtrl_packetList.ModifyStyle(0, LVS_SINGLESEL);
	listCtrl_packetList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP);

	int index = 0;
	listCtrl_packetList.InsertColumn(index, L"编号", LVCFMT_CENTER, rect.Width() * 0.05);
	listCtrl_packetList.InsertColumn(++index, L"时间", LVCFMT_CENTER, rect.Width() * 0.15);
	listCtrl_packetList.InsertColumn(++index, L"协议", LVCFMT_CENTER, rect.Width() * 0.05);
	listCtrl_packetList.InsertColumn(++index, L"长度", LVCFMT_CENTER, rect.Width() * 0.05);
	listCtrl_packetList.InsertColumn(++index, L"源MAC地址", LVCFMT_CENTER, rect.Width() * 0.175);
	listCtrl_packetList.InsertColumn(++index, L"目的MAC地址", LVCFMT_CENTER, rect.Width() * 0.175);
	listCtrl_packetList.InsertColumn(++index, L"源IP地址", LVCFMT_CENTER, rect.Width() * 0.175);
	listCtrl_packetList.InsertColumn(++index, L"目的IP地址", LVCFMT_CENTER, rect.Width() * 0.175);
}

bool CHSniffDlg::createDirectory(const CString& dirPath)
{
	if (!PathIsDirectory(dirPath.GetString()))  // 是否有重名文件夹
	{
		::CreateDirectory(dirPath.GetString(), 0);
		return true;
	}
	return false;
}

//开始抓包
void CHSniffDlg::OnBnClickedButton2()
{
	// 获取当前时间
	time_t tt = time(NULL);	// 这句返回的只是一个时间戳
	localtime(&tt);
	CTime currentTime(tt);

	int devIndex = combo_dev.GetCurSel();
	if (devIndex < 0) {
		AfxMessageBox(L"请选择网卡", MB_OK);
		return;
	}
	
	//TODO 可以使能开始结束按钮
	if (catcher.openAdapter(devIndex, currentTime))
	{
		CString status = L"正在捕获："+ catcher.getDevName();

		/* 清空控件显示内容 */
		listCtrl_packetList.DeleteAllItems();
		treeCtrl_packet.DeleteAllItems();
		edit_packet.SetWindowText(L"");
		AfxGetMainWnd()->SetWindowText(status);

		pool.clear();

		CString fileName = L"Sniffer" + currentTime.Format(L"%Y%m%d%H%M%S") + L".pcap";
		pktDumper.setPath(L"E:\\project\\HSniff\\HSniff\\tmp\\" + fileName);

		catcher.startCapture(MODE_CAPTURE_LIVE);
		pktCaptureFlag = true;

		openFileName = fileName;
		fileOpenFlag = true;
	}
	else {
		AfxMessageBox(L"打开网卡失败", MB_OK);
		return;
	}
}

//停止抓包
void CHSniffDlg::OnBnClickedButton1()
{
	AfxGetMainWnd()->SetWindowText(pktDumper.getPath());

	catcher.stopCapture();
	pktCaptureFlag = false;
	catcher.closeAdapter();
}

//MAC地址转换成cstring
CString	CHSniffDlg::MACAddr2CString(const MAC_Address& addr)
{
	CString strAddr, strTmp;

	for (int i = 0; i < 6; i++) {
		strTmp.Format(L"%02X", addr.bytes[i]);
		strAddr += strTmp + L"-";
	}
	strAddr.Delete(strAddr.GetLength() - 1, 1);

	return strAddr;
}

//IP地址转换成cstring
CString CHSniffDlg::IPAddr2CString(const IP_Address& addr)
{
	CString strAddr, strTmp;

	for (int i = 0; i < 4; ++i)
	{
		strTmp.Format(L"%d", addr.bytes[i]);
		strAddr += strTmp + L".";
	}
	strAddr.Delete(strAddr.GetLength() - 1, 1);

	return strAddr;
}

//单数据包信息打印
int CHSniffDlg::printListCtrlPacketList(const Packet& pkt)
{
	if (pkt.isEmpty())
		return -1;

	int row = 0;	// 行号
	int col = 0;	// 列号
	/* 打印编号 */
	CString	strNum;
	strNum.Format(L"%d", pkt.num);

	UINT mask = LVIF_PARAM | LVIF_TEXT;

	// protocol字段在OnCustomdrawList1()中使用
	row = listCtrl_packetList.InsertItem(mask, listCtrl_packetList.GetItemCount(), strNum, 0, 0, 0, (LPARAM) & (pkt.protocol));


	/* 打印时间 */
	CTime pktArrivalTime((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format(L"%Y/%m/%d %H:%M:%S");
	listCtrl_packetList.SetItemText(row, ++col, strPktArrivalTime);

	/* 打印协议 */
	if (!pkt.protocol.IsEmpty())
		listCtrl_packetList.SetItemText(row, ++col, pkt.protocol);
	else
		++col;

	/* 打印长度 */
	CString strCaplen;
	strCaplen.Format(L"%d", pkt.header->caplen);
	listCtrl_packetList.SetItemText(row, ++col, strCaplen);

	/* 打印源目MAC地址 */
	if (pkt.ethh != NULL)
	{
		CString strSrcMAC = MACAddr2CString(pkt.ethh->srcaddr);
		CString strDstMAC = MACAddr2CString(pkt.ethh->dstaddr);

		listCtrl_packetList.SetItemText(row, ++col, strSrcMAC);
		listCtrl_packetList.SetItemText(row, ++col, strDstMAC);
	}
	else
	{
		col += 2;
	}

	/* 打印源目IP地址 */
	if (pkt.iph != NULL)
	{
		CString strSrcIP = IPAddr2CString(pkt.iph->srcaddr);
		CString strDstIP = IPAddr2CString(pkt.iph->dstaddr);

		listCtrl_packetList.SetItemText(row, ++col, strSrcIP);
		listCtrl_packetList.SetItemText(row, ++col, strDstIP);
	}
	else
	{
		col += 2;
	}
	return 0;
}

//打印pool的信息
int CHSniffDlg::printListCtrlPacketList(PacketPool& pool)
{
	if (pool.isEmpty())
		return -1;
	int pktNum = pool.getSize();
	for (int i = 1; i <= pktNum; ++i)
		printListCtrlPacketList(pool.get(i));

	return pktNum;
}


//打印数据包信息
int CHSniffDlg::printListCtrlPacketList(PacketPool& pool, const CString& filter)
{
	if (pool.isEmpty() || filter.IsEmpty())
		return -1;

	int pktNum = pool.getSize();
	int filterPktNum = 0;
	for (int i = 0; i < pktNum; ++i)
	{
		const Packet& pkt = pool.get(i);
		if (pkt.protocol == filter)
		{
			printListCtrlPacketList(pkt);
			++filterPktNum;
		}
	}
	return filterPktNum;
}

//如果捕获到数据包，触发该事件
LRESULT CHSniffDlg::OnPktCatchMessage(WPARAM wParam, LPARAM lParam)
{
	int pktNum = lParam;
	if (pktNum > 0)
	{
		Packet& pkt = pool.get(pktNum);
		/* 检查过滤器是否启动，若启动了，则只打印符合过滤器的新捕获数据包 */
		int selFilterIndex = combox_filter.GetCurSel();
		if (selFilterIndex != 10)
		{
			CString strFilter;
			combox_filter.GetLBText(selFilterIndex, strFilter);
			if (strFilter == pkt.protocol)
				printListCtrlPacketList(pkt);
		}
		else {
			printListCtrlPacketList(pkt);
		}
		
	}

	return 0;
}

void CHSniffDlg::OnBnClickedButton3()
{
	CString saveAsFilePath = _T("");
	CString dumpFilePath = pktDumper.getPath();
	CString defaultFileName = pktDumper.getPath();
	CFileDialog	dlgFile(FALSE, L".pcap", defaultFileName, OFN_OVERWRITEPROMPT, _T("pcap文件 (*.pcap)|*.pcap|所有文件 (*.*)|*.*||"), NULL);

	if (dlgFile.DoModal() == IDOK)
	{
		saveAsFilePath = dlgFile.GetPathName();
		pktDumper.dump(saveAsFilePath);
		AfxGetMainWnd()->SetWindowText(dlgFile.GetFileName());		// 修改标题栏

	}
}


int CHSniffDlg::printEditCtrlPacketBytes(const Packet& pkt)
{
	if (pkt.isEmpty())
	{
		return -1;
	}

	CString strPacketBytes, strTmp;
	u_char* pHexPacketBytes = pkt.pkt_data;
	u_char* pASCIIPacketBytes = pkt.pkt_data;
	for (int byteCount = 0, byteCount16 = 0, offset = 0; byteCount < pkt.header->caplen && pHexPacketBytes != NULL; ++byteCount)
	{
		/* 若当前字节是行首，打印行首偏移量 */
		if (byteCount % 16 == 0)
		{
			strTmp.Format(L"%04X:", offset);
			strPacketBytes += strTmp + L" ";
		}

		/* 打印16进制字节 */
		strTmp.Format(L"%02X", *pHexPacketBytes);
		strPacketBytes += strTmp + L" ";
		++pHexPacketBytes;
		++byteCount16;

		switch (byteCount16)
		{
		case 8:
		{
			/* 每读取8个字节打印一个制表符 */
			strPacketBytes += L"\t";
		}
		break;
		case 16:
		{
			/* 每读取16个字节打印对应字节的ASCII字符，只打印字母数字 */
			if (byteCount16 == 16)
			{
				strPacketBytes += L" ";
				for (int charCount = 0; charCount < 16; ++charCount, ++pASCIIPacketBytes)
				{
					strTmp.Format(L"%c", isalnum(*pASCIIPacketBytes) ? *pASCIIPacketBytes : '.');
					strPacketBytes += strTmp;
				}
				strPacketBytes += L"\r\n";
				offset += 16;
				byteCount16 = 0;
			}
		}
		break;
		default:break;
		}
	}
	/* 若数据包总长度不是16字节对齐时，打印最后一行字节对应的ASCII字符 */
	if (pkt.header->caplen % 16 != 0)
	{
		/* 空格填充，保证字节流16字节对齐 */
		for (int spaceCount = 0, byteCount16 = (pkt.header->caplen % 16); spaceCount < 16 - (pkt.header->caplen % 16); ++spaceCount)
		{
			strPacketBytes += L"  ";
			strPacketBytes += L" ";
			++byteCount16;
			if (byteCount16 == 8)
			{
				strPacketBytes += L"\t";
				//strPacketBytes += L"#";
			}
		}
		strPacketBytes += L" ";
		/* 打印最后一行字节对应的ASCII字符 */
		for (int charCount = 0; charCount < (pkt.header->caplen % 16); ++charCount, ++pASCIIPacketBytes)
		{
			strTmp.Format(L"%c", isalnum(*pASCIIPacketBytes) ? *pASCIIPacketBytes : '.');
			strPacketBytes += strTmp;
		}
		strPacketBytes += L"\r\n";
	}

	edit_packet.SetWindowText(strPacketBytes);

	return 0;
}


void CHSniffDlg::OnCustomdrawList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;

	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) // 一个Item(一行)被绘画前
	{
		COLORREF itemColor;
		CString* pStrPktProtocol = (CString*)(pNMCD->nmcd.lItemlParam);	// 在printListCtrlPacketList(pkt)里将数据包的protocol字段传递过来

		///* 若该行被选中，则将其背景颜色调整为 */
		//if (pNMCD->nmcd.uItemState & CDIS_SELECTED)
		//{
		//	pNMCD->clrTextBk = RGB(0, 0, 0);
		//}
		if (!pStrPktProtocol->IsEmpty())
		{
			if (*pStrPktProtocol == L"ARP")
			{
				itemColor = RGB(255, 182, 193);	// 红色
			}
			else if (*pStrPktProtocol == L"ICMP")
			{
				itemColor = RGB(186, 85, 211);	// 紫色
			}
			else if (*pStrPktProtocol == L"TCP")
			{
				itemColor = RGB(144, 238, 144);	// 绿色
			}
			else if (*pStrPktProtocol == L"UDP")
			{
				itemColor = RGB(100, 149, 237);	// 蓝色

			}
			else if (*pStrPktProtocol == L"DNS")
			{
				itemColor = RGB(135, 206, 250);	// 浅蓝色
			}
			else if (*pStrPktProtocol == L"DHCP")
			{
				itemColor = RGB(189, 254, 76);	// 淡黄色
			}
			else if (*pStrPktProtocol == L"HTTP")
			{
				itemColor = RGB(238, 232, 180);	// 黄色
			}
			else
			{
				itemColor = RGB(211, 211, 211);	// 灰色
			}
			pNMCD->clrTextBk = itemColor;
		}
		*pResult = CDRF_DODEFAULT;
	}
}

//判断name中有无指针0xC0,并返回指针在name中的位置
int is0xC0PointerInName(char* name)
{
	if (name == NULL)
	{
		return -2;
	}
	char* p = name;
	int pos = 0;

	while (*p)
	{
		if (*(u_char*)p == 0xC0)
		{
			return pos;
		}
		++p;
		++pos;
	}
	return -1;
}

//获取DNS中的name字段（查询区域，资源记录区域）
CString getNameInDNS(char* name, const DNS_Header* pDNSHeader)
{
	int pointerPos;

	// name中无0xC0指针
	if ((pointerPos = is0xC0PointerInName(name)) == -1)
	{
		return translateNameInDNS(name);
	}
	else
	{
		int valueOffset = *(name + pointerPos + 1);
		CString value = get0xC0PointerValue(pDNSHeader, valueOffset);

		char* pName = (char*)malloc(pointerPos);
		memcpy(pName, name, pointerPos);
		CString strName(pName);
		strName += value;

		free(pName);
		return strName;
	}
}

//获取0xC0指针的值
CString get0xC0PointerValue(const DNS_Header* pDNSHeader, const int offset)
{
	char* pValue = (char*)pDNSHeader + offset;
	CString strValue = getNameInDNS(pValue, pDNSHeader);
	return strValue;
}

CString translateNameInDNS(const char* name)
{
	CString strName(name);
	bool canMove = false;

	if (!isalnum(strName.GetAt(0)) && strName.GetAt(0) != '-')
	{
		canMove = true;
	}
	/* 将计数转换为'.' */
	for (int i = 0; i < strName.GetLength(); ++i)
	{
		if (!isalnum(strName.GetAt(i)) && strName.GetAt(i) != '-')
		{
			strName.SetAt(i, '.');
		}
	}

	/* 将域名整体向前移1位 */
	if (canMove)
	{
		for (int i = 0; i < strName.GetLength(); ++i)
		{
			strName.SetAt(i, strName.GetAt(i + 1));
		}
	}
	return strName;
}
/* DNS资源记录数据部分转换 将带有指针0xc0的data2转换为不带指针的data1 offset为到dns首部的偏移量*/
void translateData(const DNS_Header* dnsh, char* data1, char* data2, const int data2_len)
{
	char* p = data2;
	int count = 0, i = 0;

	/* 遍历data2 */
	while (count < data2_len)
	{
		/* 指针 */
		if (*(u_char*)p == 0xC0)
		{
			++p;

			/* 读取指针所指向的数据 */
			char* data_ptr = (char*)((u_char*)dnsh + *(u_char*)p);

			int pos = is0xC0PointerInName(data_ptr);
			if (pos)
			{
				translateData(dnsh, data1 + i, data_ptr, pos + 2);
			}
			else
			{
				strcpy(data1 + i, data_ptr);
				i += strlen(data_ptr) + 1;
			}
			count += 2;
		}
		else
		{
			data1[i++] = *p;
			++p;
			++count;
		}
	}

}


//将带有字节计数的域名name2转换成域名name1
void translateNameInDNS(char* name1, const char* name2)
{
	strcpy(name1, name2);

	char* p = name1;
	bool canMove = false;

	if (!isalnum(*p) && *p != '-')
	{
		canMove = true;
	}

	/* 将计数转换为'.' */
	while (*p)
	{
		if (!isalnum(*p) && *p != '-')
		{
			*p = '.';
		}
		++p;
	}

	/* 将域名整体向前移1位 */
	if (canMove)
	{
		p = name1;
		while (*p)
		{
			*p = *(p + 1);
			++p;
		}
	}
}

//打印DNS查询部分
int CHSniffDlg::printDNSQuery(char* DNSQuery, const u_short& questions, HTREEITEM& parentNode)
{
	if (DNSQuery == NULL && parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	HTREEITEM DNSQueryNode = treeCtrl_packet.InsertItem(L"查询部分：", parentNode, 0);

	/* 查询部分 */

	char* p = DNSQuery;
	//if (questions < 10)
	//{
	for (int queryNum = 0; queryNum < questions; ++queryNum)
	{
		char* name = (char*)malloc(strlen(p) + 1);
		translateNameInDNS(name, p);

		/* 跳过域名字段 */
		p += strlen(p) + 1;
		strText.Format(L"%s：", name);

		DNS_Query* DNSQuery = (DNS_Query*)p;
		strText += DNSType2CString(DNSQuery->type) + L", ";
		strText += DNSClass2CString(DNSQuery->classes);
		treeCtrl_packet.InsertItem(strText, DNSQueryNode, 0);

		/* 跳过查询类型和查询类字段 */
		p += sizeof(DNS_Query);
		free(name);
	}// for
//}// if
	return p - DNSQuery + 1;
}

//将DNS报文中的class字段转换成CString类字符串
CString CHSniffDlg::DNSClass2CString(const u_short& classes)
{
	CString strClass;
	switch (ntohs(classes))
	{
	case DNS_CLASS_IN:		strClass = L"Class IN";									break;
	case DNS_CLASS_CS:		strClass = L"Class CS";									break;
	case DNS_CLASS_HS:		strClass = L"Class HS";									break;
	default:				strClass.Format(L"Class 未知（%hu）", ntohs(classes));	break;
	}
	return strClass;
}

//将DNS报文中的type字段转换成CString类字符串
CString CHSniffDlg::DNSType2CString(const u_short& type)
{
	CString strType;
	switch (ntohs(type))
	{
	case DNS_TYPE_A:		strType = L"Type A";										break;
	case DNS_TYPE_NS:		strType = L"Type NS";									break;
	case DNS_TYPE_CNAME:	strType = L"Type CNAME";									break;
	case DNS_TYPE_SOA:		strType = L"Type SOA";									break;
	case DNS_TYPE_PTR:		strType = L"Type PTR";									break;
	case DNS_TYPE_MX:		strType = L"Type MX";									break;
	case DNS_TYPE_AAAA:		strType = L"Type AAAA";									break;
	case DNS_TYPE_ANY:		strType = L"Type ANY";									break;
	default:				strType.Format(L" Type 未知（%hu）,", ntohs(type));		break;
	}
	return strType;
}

//打印DNS首部
int CHSniffDlg::printDNSHeader(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.dnsh == NULL || parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	strText.Format(L"标识：0x%04hX (%hu)", ntohs(pkt.dnsh->identifier), ntohs(pkt.dnsh->identifier));
	treeCtrl_packet.InsertItem(strText, parentNode, 0);

	strText.Format(L"标志：0x%04hX", ntohs(pkt.dnsh->flags));
	strText += strTmp;

	HTREEITEM DNSFlagNode = treeCtrl_packet.InsertItem(strText, parentNode, 0);
	/* 标志子字段 */
	switch (pkt.getDNSFlagsQR())
	{
	case DNS_FLAGS_QR_REQUEST:	strText = L"QR：; 查询报文 （0）";	break;
	case DNS_FLAGS_QR_REPLY:	strText = L"QR：; 响应报文 （1）";	break;
	}
	treeCtrl_packet.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsOPCODE())
	{
	case DNS_FLAGS_OPCODE_STANDARD_QUERY:			strText = L"OPCODE：标准查询 （0）";			break;
	case DNS_FLAGS_OPCODE_INVERSE_QUERY:			strText = L"OPCODE：反向查询 （1）";			break;
	case DNS_FLAGS_OPCODE_SERVER_STATUS_REQUEST:	strText = L"OPCODE：服务器状态请求 （2）";	break;
	}
	treeCtrl_packet.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsAA())
	{
	case 0:	strText = L"AA：非授权回答 （0）";	break;
	case 1: strText = L"AA：授权回答 （1）";		break;
	}
	treeCtrl_packet.InsertItem(strText, DNSFlagNode, 0);


	switch (pkt.getDNSFlagsTC())
	{
	case 0: strText = L"TC：报文未截断 （0）";	break;
	case 1: strText = L"TC：报文截断 （1）";		break;
	}
	treeCtrl_packet.InsertItem(strText, DNSFlagNode, 0);


	switch (pkt.getDNSFlagsRD())
	{
	case 0: strText = L"RD：0";						break;
	case 1: strText = L"RD：希望进行递归查询 （1）";	break;
	}
	treeCtrl_packet.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsRA())
	{
	case 0: strText = L"RA：服务器不支持递归查询 （0）"; break;
	case 1: strText = L"RA：服务器支持递归查询 （1）";	break;
	}
	treeCtrl_packet.InsertItem(strText, DNSFlagNode, 0);

	strText.Format(L"Z：保留（%d）", pkt.getDNSFlagsZ());
	treeCtrl_packet.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsRCODE())
	{
	case DNS_FLAGS_RCODE_NO_ERROR:			strText = L"RCODE：无差错 （0）";							 break;
	case DNS_FLAGS_RCODE_FORMAT_ERROR:		strText = L"RCODE：格式差错 （1）";							 break;
	case DNS_FLAGS_RCODE_SERVER_FAILURE:	strText = L"RCODE：DNS服务器问题 （2）";						 break;
	case DNS_FLAGS_RCODE_NAME_ERROR:		strText = L"RCODE：域名不存在或出错 （3）";					 break;
	case DNS_FLAGS_RCODE_NOT_IMPLEMENTED:	strText = L"RCODE：查询类型不支持 （4）";					 break;
	case DNS_FLAGS_RCODE_REFUSED:			strText = L"RCODE：在管理上禁止 （5）";						 break;
	default:								strText.Format(L"RCODE：保留（%d）", pkt.getDNSFlagsRCODE()); break;
	}
	treeCtrl_packet.InsertItem(strText, DNSFlagNode, 0);

	strText.Format(L"查询记录数：%hu", ntohs(pkt.dnsh->questions));
	treeCtrl_packet.InsertItem(strText, parentNode, 0);

	strText.Format(L"回答记录数：%hu", ntohs(pkt.dnsh->answer_RRs));
	treeCtrl_packet.InsertItem(strText, parentNode, 0);

	strText.Format(L"授权回答记录数：%hu", ntohs(pkt.dnsh->authority_RRs));
	treeCtrl_packet.InsertItem(strText, parentNode, 0);

	strText.Format(L"附加信息记录数：%hu", ntohs(pkt.dnsh->additional_RRs));
	treeCtrl_packet.InsertItem(strText, parentNode, 0);

	return 0;
}

//DNS节点消息
HTREEITEM CHSniffDlg::printDNSBanner(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || parentNode == NULL)
	{
		return NULL;
	}
	CString strText;

	switch (pkt.getDNSFlagsQR())
	{
	case DNS_FLAGS_QR_REQUEST:	strText = L"DNS（请求）";		break;
	case DNS_FLAGS_QR_REPLY:	strText = L"DNS（响应）";		break;
	}
	return treeCtrl_packet.InsertItem(strText, parentNode, 0);
}

//打印UDP消息
int CHSniffDlg::printUDP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.udph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM UDPNode;
	CString strText, strTmp;

	strText.Format(L"UDP（%hu -> %hu）", ntohs(pkt.udph->srcport), ntohs(pkt.udph->dstport));
	UDPNode = treeCtrl_packet.InsertItem(strText, parentNode, 0);

	strText.Format(L"源端口：%hu", ntohs(pkt.udph->srcport));
	treeCtrl_packet.InsertItem(strText, UDPNode, 0);

	strText.Format(L"目的端口：%hu", ntohs(pkt.udph->dstport));
	treeCtrl_packet.InsertItem(strText, UDPNode, 0);

	strText.Format(L"长度：%hu", ntohs(pkt.udph->len));
	treeCtrl_packet.InsertItem(strText, UDPNode, 0);

	strText.Format(L"校验和：0x%04hX", ntohs(pkt.udph->checksum));
	treeCtrl_packet.InsertItem(strText, UDPNode, 0);

	if (pkt.dnsh != NULL)
	{
		//printDNS2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.dhcph != NULL)
	{
		printDHCP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}

//打印TCP消息
int CHSniffDlg::printTCP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.tcph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM TCPNode;
	CString strText, strTmp;

	strText.Format(L"TCP（%hu -> %hu）", ntohs(pkt.tcph->srcport), ntohs(pkt.tcph->dstport));
	TCPNode = treeCtrl_packet.InsertItem(strText, parentNode, 0);

	strText.Format(L"源端口：%hu", ntohs(pkt.tcph->srcport));
	treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	strText.Format(L"目的端口：%hu", ntohs(pkt.tcph->dstport));
	treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	strText.Format(L"序列号：0x%0lX", ntohl(pkt.tcph->seq));
	treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	strText.Format(L"确认号：0x%0lX", ntohl(pkt.tcph->ack));
	treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	strText.Format(L"首部长度：%d 字节（%d）", pkt.getTCPHeaderLength(), pkt.getTCPHeaderLengthRaw());
	treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	strText.Format(L"标志：0x%03X", pkt.getTCPFlags());
	HTREEITEM TCPFlagNode = treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	strText.Format(L"URG：%d", pkt.getTCPFlagsURG());
	treeCtrl_packet.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(L"ACK：%d", pkt.getTCPFlagsACK());
	treeCtrl_packet.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(L"PSH：%d", pkt.getTCPFlagsPSH());
	treeCtrl_packet.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(L"RST：%d", pkt.getTCPFlagsRST());
	treeCtrl_packet.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(L"SYN：%d", pkt.getTCPFlagsSYN());
	treeCtrl_packet.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(L"FIN：%d", pkt.getTCPFlagsFIN());
	treeCtrl_packet.InsertItem(strText, TCPFlagNode, 0);

	strText.Format(L"窗口大小：%hu", ntohs(pkt.tcph->win_size));
	treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	strText.Format(L"校验和：0x%04hX", ntohs(pkt.tcph->chksum));
	treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	strText.Format(L"紧急指针：%hu", ntohs(pkt.tcph->urg_ptr));
	treeCtrl_packet.InsertItem(strText, TCPNode, 0);

	if (pkt.dnsh != NULL)
	{
		printDNS2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.dhcph != NULL)
	{
		printDHCP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.httpmsg != NULL)
	{
		printHTTP2TreeCtrl(pkt, parentNode);
	}

	return 0;
}

//打印ICMP消息
int CHSniffDlg::printICMP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.icmph == NULL || parentNode == NULL)
		return -1;

	HTREEITEM ICMPNode;
	CString strText, strTmp;

	strText = L"ICMP";
	switch (pkt.icmph->type)
	{
	case ICMP_TYPE_ECHO_REPLY:					strTmp = L"（回应应答报告）";		break;
	case ICMP_TYPE_DESTINATION_UNREACHABLE:		strTmp = L"（信宿不可达报告）";		break;
	case ICMP_TYPE_SOURCE_QUENCH:				strTmp = L"（源端抑制报告）";		break;
	case ICMP_TYPE_REDIRECT:					strTmp = L"（重定向报告）";			break;
	case ICMP_TYPE_ECHO:						strTmp = L"（回应请求报告）";		break;
	case ICMP_TYPE_ROUTER_ADVERTISEMENT:		strTmp = L"（路由器通告报告）";		break;
	case ICMP_TYPE_ROUTER_SOLICITATION:			strTmp = L"（路由器询问报告）";		break;
	case ICMP_TYPE_TIME_EXCEEDED:				strTmp = L"（超时报告）";			break;
	case ICMP_TYPE_PARAMETER_PROBLEM:			strTmp = L"（数据报参数错误报告）";	break;
	case ICMP_TYPE_TIMESTAMP:					strTmp = L"（时间戳请求报告）";		break;
	case ICMP_TYPE_TIMESTAMP_REPLY:				strTmp = L"（时间戳响应报告）";		break;
	default:									strTmp.Format(L"（未知）");			break;
	}
	strText += strTmp;
	ICMPNode = treeCtrl_packet.InsertItem(strText, parentNode, 0);

	IP_Address addr = *(IP_Address*)&(pkt.icmph->others);
	u_short id = pkt.getICMPID();
	u_short seq = pkt.getICMPSeq();

	strText.Format(L"类型：%u", pkt.icmph->type);
	treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

	switch (pkt.icmph->type)
	{
	case ICMP_TYPE_ECHO_REPLY:
	{
		strText = L"代码：0";
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"校验和:0x%04hX", ntohs(pkt.icmph->chksum));
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"标识：%hu", id);
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"序号：%hu", seq);
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		break;
	}


	case ICMP_TYPE_DESTINATION_UNREACHABLE:
		strText = L"代码：";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_NET_UNREACHABLE:
			strText.Format(L"网络不可达 （%d）", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE:
			strText.Format(L"主机不可达 （%d）", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE:
			strText.Format(L"协议不可达 （%d）", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE:
			strText.Format(L"端口不可达 （%d）", pkt.icmph->code);
			break;

		case 6:
			strTmp = L"信宿网络未知 （6）";
			break;

		case 7:
			strTmp = L"信宿主机未知 （7）";
			break;

		default:
			strText.Format(L"未知 （%d）", pkt.icmph->code); break;
		}
		strText += strTmp;
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"校验和：0x%04hX", ntohs(pkt.icmph->chksum));
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_SOURCE_QUENCH:
		strText.Format(L"代码：%d", ICMP_TYPE_SOURCE_QUENCH_CODE);
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"校验和：0x%04hX", ntohs(pkt.icmph->chksum));
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_REDIRECT:
		strText = L"代码：";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_NETWORK:
			strText.Format(L"对特定网络重定向（%d)", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_HOST:
			strText.Format(L"对特定主机重定向 （%d)", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_NETWORK:
			strText.Format(L"基于指定的服务类型对特定网络重定向 （%d）", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_HOST:
			strText.Format(L"基于指定的服务类型对特定主机重定向 （%d）", pkt.icmph->code);
			break;
		}
		strText += strTmp;
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"校验和：0x%04hx", ntohs(pkt.icmph->chksum));
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText = L"目标路由器的IP地址：" + IPAddr2CString(addr);
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_ECHO:
		strText.Format(L"代码：%d", pkt.icmph->code);
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"校验和：0x%04hX", ntohs(pkt.icmph->chksum));
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"标识：%hu", id);
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"序号：%hu", seq);
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_TIME_EXCEEDED:
		strText = L"代码：";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_TIME_EXCEEDED_CODE_TTL_EXCEEDED_IN_TRANSIT:
			strText.Format(L"TTL超时 （%d）", pkt.icmph->code);
			break;
		case ICMP_TYPE_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDE:
			strText.Format(L"分片重组超时 （%d）", pkt.icmph->code);
			break;
		}
		strText += strTmp;
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		strText.Format(L"校验和：0x%04hx", ntohs(pkt.icmph->chksum));
		treeCtrl_packet.InsertItem(strText, ICMPNode, 0);

		break;

	default:
		strText.Format(L"代码：%d", pkt.icmph->code);
		treeCtrl_packet.InsertItem(strText, 0, 0, ICMPNode, 0);

		strText.Format(L"校验和：0x%04hX", pkt.icmph->chksum);
		treeCtrl_packet.InsertItem(strText, 0, 0, ICMPNode, 0);

		break;
	}
	return 0;
}

//ARP数据信息打印
int CHSniffDlg::printARP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.arph == NULL || parentNode == NULL)
		return -1;

	HTREEITEM ARPNode;
	CString strText, strTmp;

	switch (ntohs(pkt.arph->opcode))
	{
	case ARP_OPCODE_REQUET:	strText.Format(L"ARP（请求)");	break;
	case ARP_OPCODE_REPLY:	strText.Format(L"ARP（响应)");	break;
	default:				strText.Format(L"ARP");			break;
	}
	ARPNode = treeCtrl_packet.InsertItem(strText, 0, 0, parentNode, 0);

	strText.Format(L"硬件类型：%hu", ntohs(pkt.arph->hwtype));
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	strText.Format(L"协议类型：0x%04hx (%hu)", ntohs(pkt.arph->ptype), ntohs(pkt.arph->ptype));
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	strText.Format(L"硬件地址长度：%u", pkt.arph->hwlen);
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	strText.Format(L"协议地址长度：%u", pkt.arph->plen);
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	switch (ntohs(pkt.arph->opcode))
	{
	case ARP_OPCODE_REQUET:	strText.Format(L"OP码：请求（%hu）", ntohs(pkt.arph->opcode));	break;
	case ARP_OPCODE_REPLY:	strText.Format(L"OP码：响应（%hu）", ntohs(pkt.arph->opcode));	break;
	default:				strText.Format(L"OP码：未知（%hu）", ntohs(pkt.arph->opcode));	break;
	}
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	strText = L"源MAC地址：" + MACAddr2CString(pkt.arph->srcmac);
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	strText = L"源IP地址：" + IPAddr2CString(pkt.arph->srcip);
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	strText = L"目的MAC地址：" + MACAddr2CString(pkt.arph->dstmac);
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	strText = L"目的IP地址：" + IPAddr2CString(pkt.arph->dstip);
	treeCtrl_packet.InsertItem(strText, ARPNode, 0);

	return 0;
}

int CHSniffDlg::printIP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.iph == NULL || parentNode == NULL)
		return -1;

	HTREEITEM IPNode = treeCtrl_packet.InsertItem(L"IP（" + IPAddr2CString(pkt.iph->srcaddr) + L" -> " + IPAddr2CString(pkt.iph->dstaddr) + "）", parentNode, 0);
	CString strText;

	strText.Format(L"版本号：%d", pkt.iph->ver_headerlen >> 4);
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText.Format(L"首部长度：%d 字节（%d）", pkt.getIPHeaderLegnth(), pkt.getIPHeaderLengthRaw());
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText.Format(L"服务质量：0x%02X", pkt.iph->tos);
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText.Format(L"总长度：%hu", ntohs(pkt.iph->totallen));
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText.Format(L"标识：0x%04hX（%hu）", ntohs(pkt.iph->identifier), ntohs(pkt.iph->identifier));
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText.Format(L"标志：0x%02X", pkt.getIPFlags());
	HTREEITEM IPFlagNode = treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText = L"RSV：0";
	treeCtrl_packet.InsertItem(strText, IPFlagNode, 0);

	strText.Format(L"DF：%d", pkt.getIPFlagDF());
	treeCtrl_packet.InsertItem(strText, IPFlagNode, 0);

	strText.Format(L"MF：%d", pkt.getIPFlagsMF());
	treeCtrl_packet.InsertItem(strText, IPFlagNode, 0);

	strText.Format(L"片偏移：%d", pkt.getIPOffset());
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText.Format(L"TTL：%u", pkt.iph->ttl);
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	switch (pkt.iph->protocol)
	{
	case PROTOCOL_ICMP:	strText = L"协议：ICMP（1）";	break;
	case PROTOCOL_TCP:	strText = L"协议：TCP（6）";	break;
	case PROTOCOL_UDP:	strText = L"协议：UDP（17）";	break;
	default:			strText.Format(L"协议：未知（%d）", pkt.iph->protocol);	break;
	}
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText.Format(L"校验和：0x%02hX", ntohs(pkt.iph->checksum));
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText = L"源IP地址：" + IPAddr2CString(pkt.iph->srcaddr);
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	strText = L"目的IP地址：" + IPAddr2CString(pkt.iph->dstaddr);
	treeCtrl_packet.InsertItem(strText, IPNode, 0);

	if (pkt.icmph != NULL)
	{
		printICMP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.tcph != NULL)
	{
		printTCP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.udph != NULL)
	{
		printUDP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}

int CHSniffDlg::printEthernet2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.ethh == NULL || parentNode == NULL)
	{
		return -1;
	}
	/* 获取源目MAC地址 */
	CString strSrcMAC = MACAddr2CString(pkt.ethh->srcaddr);
	CString	strDstMAC = MACAddr2CString(pkt.ethh->dstaddr);
	CString strEthType;
	strEthType.Format(L"0x%04X", ntohs(pkt.ethh->eth_type));

	HTREEITEM	EthNode = treeCtrl_packet.InsertItem(L"以太网（" + strSrcMAC + L" -> " + strDstMAC + L"）", parentNode, 0);

	treeCtrl_packet.InsertItem(L"目的MAC地址：" + strDstMAC, EthNode, 0);
	treeCtrl_packet.InsertItem(L"源MAC地址：" + strSrcMAC, EthNode, 0);
	treeCtrl_packet.InsertItem(L"类型：" + strEthType, EthNode, 0);

	if (pkt.iph != NULL)
	{
		printIP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.arph != NULL)
	{
		printARP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}

int CHSniffDlg::printTreeCtrlPacketDetails(const Packet& pkt)
{
	if (pkt.isEmpty())
		return -1;

	treeCtrl_packet.DeleteAllItems();

	/* 建立编号结点 */
	CString strText;

	CTime pktArrivalTime((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format(L"%Y/%m/%d %H:%M:%S");

	strText.Format(L"第%d个数据包（%s, 共 %hu 字节, 捕获 %hu 字节）", pkt.num, strPktArrivalTime, pkt.header->len, pkt.header->caplen);

	HTREEITEM rootNode = treeCtrl_packet.InsertItem(strText, TVI_ROOT);
	if (pkt.ethh != NULL)
	{
		printEthernet2TreeCtrl(pkt, rootNode);
	}

	treeCtrl_packet.Expand(rootNode, TVE_EXPAND);
	return 0;
}


void CHSniffDlg::OnNMClickList2(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	//int selectedItemIndex = listCtrl_packetList.GetSelectionMark();
	int selectedItemIndex = listCtrl_packetList.GetNextItem(-1, LVNI_SELECTED);
	CString strPktNum = listCtrl_packetList.GetItemText(selectedItemIndex, 0);
	int pktNum = _ttoi(strPktNum);
	if (pktNum < 1 || pktNum > pool.getSize())
		return;

	const Packet& pkt = pool.get(pktNum);
	printTreeCtrlPacketDetails(pkt);
	printEditCtrlPacketBytes(pkt);
	*pResult = 0;
}



int CHSniffDlg::printDNSResourceRecord(char* DNSResourceRecord, const u_short& resourceRecordNum, const int& resourceRecordType, const DNS_Header* pDNSHeader, HTREEITEM parentNode)
{
	if (DNSResourceRecord == NULL || resourceRecordNum == 0 || pDNSHeader == NULL || parentNode == NULL)
	{
		return -1;
	}
	char* p = DNSResourceRecord;
	CString strText, strTmp;

	switch (resourceRecordType)
	{
	case DNS_RESOURCE_RECORD_TYPE_ANSWER:		strText = L"回答部分：";		break;
	case DNS_RESOURCE_RECORD_TYPE_AUTHORITY:	strText = L"授权回答部分：";	break;
	case DNS_RESOURCE_RECORD_TYPE_ADDITIONAL:	strText = L"附加信息部分：";	break;
	}
	HTREEITEM DNSResourceRecordNode = treeCtrl_packet.InsertItem(strText, parentNode, 0);

	for (int count = 0; count < 1; ++count) //count < resourceRecordNum; ++count)
	{

		if (*(u_char*)p == 0xC0)
		{
			// name
			strText = getNameInDNS(p, pDNSHeader) + L"：";

			// 指向type，class，ttl
			p += 2;			// 2 = 0xC0 + 偏移量
		}
		else
		{
			char* name = (char*)malloc(strlen(p) + 1);
			translateNameInDNS(name, p);

			CString strText, strTmp;
			strText.Format(L"%s: ", name);

			// 指向type，class，ttl
			p += strlen(name) + 1;
			free(name);
		}

		DNS_ResourceRecord* pRecord = (DNS_ResourceRecord*)p;
		strText += DNSType2CString(pRecord->type) + L", ";
		strText += DNSClass2CString(pRecord->classes) + L", ";
		strTmp.Format(L"TTL %d", ntohl(pRecord->ttl));
		strText += strTmp + L", ";

		// 指向资源数据长度
		p += sizeof(DNS_ResourceRecord);
		u_short dataLength = *(u_short*)p;
		strTmp.Format(L"资源数据长度：%hu 字节", dataLength);
		strText += strTmp + L", ";

		// 指向资源数据
		p += sizeof(u_short);

		switch (ntohs(pRecord->type))
		{
		case DNS_TYPE_A:
			strText += L"IP地址： " + IPAddr2CString(*(IP_Address*)p);
			break;
		case DNS_TYPE_NS:
			strText += L"名字服务器： " + IPAddr2CString(*(IP_Address*)p);
			break;
		case DNS_TYPE_CNAME:
		{
			//char *cname = (char*)malloc(dataLength);
			//translateNameInDNS(cname, p);

			CString strCName = getNameInDNS(p, pDNSHeader);
			strText += L"别名：" + strCName;
			//treeCtrl_packet.InsertItem(strText, parentNode, 0);
			//free(cname);
			break;
		}
		default:
			/*strTmp.Format(L"Type 未知(%hu),", ntohs(pRecord->type));
			strText += strTmp;*/
			break;
		}
		treeCtrl_packet.InsertItem(strText, DNSResourceRecordNode, 0);

	}// for
	return p - DNSResourceRecord + 1;
}

int CHSniffDlg::printDNS2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.dnsh == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM DNSNode = printDNSBanner(pkt, parentNode);

	printDNSHeader(pkt, DNSNode);


	char* DNSQuery = (char*)pkt.dnsh + DNS_HEADER_LENGTH;
	int DNSQueryLen = printDNSQuery(DNSQuery, ntohs(pkt.dnsh->questions), DNSNode);

	char* DNSAnswer = NULL, * DNSAuthority = NULL, * DNSAdditional = NULL;
	int DNSAnswerLen = 0, DNSAuthorityLen = 0;

	if (ntohs(pkt.dnsh->answer_RRs) > 0)
	{
		DNSAnswer = DNSQuery + DNSQueryLen;
		DNSAnswerLen = printDNSResourceRecord(DNSAnswer, ntohs(pkt.dnsh->answer_RRs), DNS_RESOURCE_RECORD_TYPE_ANSWER, pkt.dnsh, DNSNode);
	}

	if (ntohs(pkt.dnsh->authority_RRs) > 0)
	{
		DNSAuthority = DNSAnswer + DNSAnswerLen;
		DNSAuthorityLen = printDNSResourceRecord(DNSAuthority, ntohs(pkt.dnsh->authority_RRs), DNS_RESOURCE_RECORD_TYPE_AUTHORITY, pkt.dnsh, DNSNode);
	}


	if (ntohs(pkt.dnsh->additional_RRs) > 0)
	{
		DNSAdditional = DNSAuthority + DNSAuthorityLen;
		printDNSResourceRecord(DNSAdditional, ntohs(pkt.dnsh->additional_RRs), DNS_RESOURCE_RECORD_TYPE_ADDITIONAL, pkt.dnsh, DNSNode);
	}

	return 0;
}

//打印DHCP消息
int CHSniffDlg::printDHCP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.dhcph == NULL || parentNode == NULL)
	{
		return -1;
	}

	HTREEITEM DHCPNode = treeCtrl_packet.InsertItem(L"DHCP", parentNode, 0);
	CString strText, strTmp;
	/* 解析dhcp首部 */
	strText.Format(L"报文类型：%d", pkt.dhcph->op);
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText.Format(L"硬件类型：%d", pkt.dhcph->htype);
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText.Format(L"硬件地址长度：%d", pkt.dhcph->hlen);
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText.Format(L"跳数：%d", pkt.dhcph->hops);
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText.Format(L"事务ID：0x%08lX", ntohl(pkt.dhcph->xid));
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText.Format(L"客户启动时间：%hu", ntohs(pkt.dhcph->secs));
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText.Format(L"标志：0x%04hX", ntohs(pkt.dhcph->flags));
	switch (ntohs(pkt.dhcph->flags) >> 15)
	{
	case DHCP_FLAGS_BROADCAST: strText += L"（广播）"; break;
	case DHCP_FLAGS_UNICAST: strText += L"（单播）"; break;
	}
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText = L"客户机IP地址：" + IPAddr2CString(pkt.dhcph->ciaddr);
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText = L"你的（客户）IP地址：" + IPAddr2CString(pkt.dhcph->yiaddr);
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText = L"服务器IP地址：" + IPAddr2CString(pkt.dhcph->siaddr);;
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText = L"网关IP地址：" + IPAddr2CString(pkt.dhcph->giaddr);
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	/*  解析dhcp首部剩余部分 */
	CString strChaddr;
	for (int i = 0; i < 6; ++i)
	{
		strTmp.Format(L"%02X", pkt.dhcph->chaddr[i]);
		strChaddr += strTmp + L"-";
	}
	strChaddr.Delete(strChaddr.GetLength() - 1, 1);

	strText = L"客户机MAC地址：" + strChaddr;
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText = L"服务器主机名：";
	strTmp.Format(L"%s", pkt.dhcph->snamer);
	strText += strTmp;
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	strText = L"引导文件名：";
	strTmp.Format(L"%s", pkt.dhcph->file);
	strText += strTmp;
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	// 跳过引导文件名
	u_char* p = (u_char*)pkt.dhcph->file + 128;

	if (ntohl(*(u_long*)p) == 0x63825363)
	{
		strText = L"Magic cookie: DHCP";
		treeCtrl_packet.InsertItem(strText, DHCPNode, 0);
	}

	// 跳过magic cookie
	p += 4;

	while (*p != 0xFF)
	{
		switch (*p)
		{
		case DHCP_OPTIONS_DHCP_MESSAGE_TYPE:
		{
			strText = L"选项：（53）DHCP报文类型";
			switch (*(p + 2))
			{
			case 1: strText += L"（Discover）"; break;
			case 2: strText += L"（Offer）"; break;
			case 3: strText += L"（Request）"; break;
			case 4: strText += L"（Decline）"; break;
			case 5: strText += L"（ACK）"; break;
			case 6: strText += L"（NAK）"; break;
			case 7: strText += L"（Release）"; break;
			case 8: strText += L"（Inform）"; break;
			}
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			strText.Format(L"长度：%d", *(++p));
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			strText.Format(L"DHCP：%d", *(++p));
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			++p;
		}
		break;

		case DHCP_OPTIONS_REQUESTED_IP_ADDRESS:
		{
			strText = L"选项：（50）请求IP地址";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			strText.Format(L"长度：%d", *(++p));
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address* addr = (IP_Address*)(++p);
			strText = L"地址：" + IPAddr2CString(*addr);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			p += 4;
		}
		break;

		case DHCP_OPTIONS_IP_ADDRESS_LEASE_TIME:
		{
			strText = L"选项：（51）IP地址租约时间";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			strText.Format(L"长度：%d", *(++p));
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			u_int time = *(++p);
			strText.Format(L"租约时间：%u", time);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			p += 4;
		}
		break;

		case DHCP_OPTIONS_CLIENT_IDENTIFIER:
		{
			strText = L"选项：（61）客户机标识";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(L"长度：%d", len);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			strText = L"硬件类型：";
			if (*(++p) == 0x01)
			{
				strText += L"以太网（0x01）";
				treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

				MAC_Address* addr = (MAC_Address*)(++p);
				strText = L"客户机标识：" + MACAddr2CString(*addr);
				treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

				p += 6;
			}
			else
			{
				strText.Format(L"%d", *p);
				strText += strTmp;
				treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

				p += len;
			}
		}
		break;

		case DHCP_OPTIONS_VENDOR_CLASS_IDENTIFIER:
		{
			strText = L"选项：（60）供应商类标识";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(L"长度：%d", len);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = L"供应商类标识：";
			for (; count < len; count++)
			{
				strTmp.Format(L"%c", *(++p));
				strText += strTmp;
			}
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			++p;
		}
		break;

		case DHCP_OPTIONS_SERVER_IDENTIFIER:
		{
			strText = L"选项：（54）服务器标识";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(L"长度：%d", len);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address* addr = (IP_Address*)(++p);
			strText = L"服务器标识：" + IPAddr2CString(*addr);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
		break;

		case DHCP_OPTIONS_SUBNET_MASK:
		{

			strText = L"选项：（1）子网掩码";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(L"长度：%d", len);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address* submask = (IP_Address*)(++p);
			strText = L"子网掩码：" + IPAddr2CString(*submask);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
		break;

		case DHCP_OPTIONS_ROUTER_OPTION:
		{

			strText = L"选项：（3）路由器";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(L"长度：%d", len);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			while (count < len)
			{
				IP_Address* addr = (IP_Address*)(++p);
				strText = L"路由器：" + IPAddr2CString(*addr);
				treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
		break;

		case DHCP_OPTIONS_DOMAIN_NAME_SERVER_OPTION:
		{
			strText = L"选项：（6）DNS服务器";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(L"长度：%d", len);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			++p;
			while (count < len)
			{
				IP_Address* addr = (IP_Address*)(p);
				strText = L"DNS服务器：" + IPAddr2CString(*addr);
				treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
		break;


		case DHCP_OPTIONS_HOST_NAME_OPTION:
		{
			strText = L"选项：（12）主机名";
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(L"长度：%d", len);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = L"主机名：";

			for (; count < len; count++)
			{
				strTmp.Format(L"%c", *(++p));
				strText += strTmp;
			}
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			++p;
		}
		break;

		case DHCP_OPTIONS_PAD_OPTION:
			++p;
			break;

		default:
		{
			strText.Format(L"选项：（%d）", *p);
			HTREEITEM DHCPOptionNode = treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format(L"长度：%d", len);
			treeCtrl_packet.InsertItem(strText, DHCPOptionNode, 0);

			// 指向选项内容
			++p;

			// 跳过选项内容
			p += len;
		}
		break;
		}// switch 

	}// while
	strText = L"选项：（255）结束";
	treeCtrl_packet.InsertItem(strText, DHCPNode, 0);

	return 0;
}

//打印HTTP报文到treelist
int CHSniffDlg::printHTTP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode)
{
	if (pkt.isEmpty() || pkt.httpmsg == NULL || parentNode == NULL)
	{
		return -1;
	}

	u_char* p = pkt.httpmsg;
	int HTTPMsgLen = pkt.getL4PayloadLength();

	CString strText;
	if (ntohs(pkt.tcph->dstport) == PORT_HTTP)
	{
		strText = L"HTTP（请求）";
	}
	else if (ntohs(pkt.tcph->srcport) == PORT_HTTP)
	{
		strText = L"HTTP（响应）";
	}
	HTREEITEM HTTPNode = treeCtrl_packet.InsertItem(strText, parentNode, 0);

	for (int count = 0; count < HTTPMsgLen; )
	{
		strText = "";
		while (*p != '\r')
		{
			strText += *p;
			++p;
			++count;
		}
		strText += "\\r\\n";
		treeCtrl_packet.InsertItem(strText, HTTPNode, 0);

		p += 2;
		count += 2;
	}
	return 0;
}

//空处理
void CAboutDlg::On32771()
{

}

//右键CListCtrl
void CHSniffDlg::OnNMRClickList2(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);

	POINT pt;
	GetCursorPos(&pt);
	trackItemIndex = listCtrl_packetList.GetNextItem(-1, LVNI_SELECTED)+1;

	menu.LoadMenu(IDR_MENU1);
	CMenu* pop = menu.GetSubMenu(0);
	pop->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, this);
	pop->Detach();
	menu.DestroyMenu();
	*pResult = 0;
}

//TCP流跟踪
void CHSniffDlg::trackTCP()
{
	if (trackItemIndex < 1 || trackItemIndex > pool.getSize())
		return;

	const Packet& pkt = pool.get(trackItemIndex);

	if (pkt.protocol != L"TCP") {
		AfxMessageBox(L"目前只支持TCP流跟踪", MB_OK);
		return;
	}

	//清空显示框
	listCtrl_packetList.DeleteAllItems();
	treeCtrl_packet.DeleteAllItems();
	edit_packet.SetWindowText(L"");

	CString strSrcIP = IPAddr2CString(pkt.iph->srcaddr);
	CString strDstIP = IPAddr2CString(pkt.iph->dstaddr);
	u_short srcport = pkt.tcph->srcport;
	u_short dstport = pkt.tcph->dstport;

	int pktAllNum = pool.getSize();
	int trackPktNum = 0;
	for (int i = 0; i < pktAllNum; ++i)
	{
		const Packet& pkt = pool.get(i);
		if (pkt.protocol == L"TCP")
		{
			if ((IPAddr2CString(pkt.iph->srcaddr) == strSrcIP && IPAddr2CString(pkt.iph->dstaddr) == strDstIP)|| (IPAddr2CString(pkt.iph->dstaddr) == strSrcIP) || (IPAddr2CString(pkt.iph->srcaddr) == strDstIP)) {
				if ((pkt.tcph->srcport == srcport && pkt.tcph->dstport == dstport) || (pkt.tcph->srcport == dstport && pkt.tcph->dstport == srcport)) {
					printListCtrlPacketList(pkt);
					++trackPktNum;
				}	
			}
		}
	}
}

//打开pcap文件
void CHSniffDlg::OnBnClickedButton4()
{
	CFileDialog	dlgFile(TRUE, L".pcap", NULL, OFN_FILEMUSTEXIST | OFN_HIDEREADONLY, _T("pcap文件 (*.pcap)|*.pcap|所有文件 (*.*)|*.*||"), NULL);
	if (dlgFile.DoModal() == IDOK)
	{
		CString openFilePath = dlgFile.GetPathName();
		CString openFileName = dlgFile.GetFileName();
		if (dlgFile.GetFileExt() != L"pcap")	// 检查文件扩展名
		{
			AfxMessageBox(L"无法打开文件" + openFileName + L"，请检查文件扩展名");
			return;
		}
		if (openFileName == alreadyOpenFileName)	// 检查文件名，避免重复打开
		{
			AfxMessageBox(L"不能重复打开相同文件" + openFileName);
			return;
		}
		if (catcher.openAdapter(openFilePath))
		{
			alreadyOpenFileName = openFileName;					// 保存文件名
			AfxGetMainWnd()->SetWindowText(openFileName);	// 修改标题栏为文件名

			listCtrl_packetList.DeleteAllItems();
			treeCtrl_packet.DeleteAllItems();
			edit_packet.SetWindowText(L"");
			pool.clear();

			pktDumper.setPath(openFilePath);
			catcher.startCapture(MODE_CAPTURE_OFFLINE);
			fileOpenFlag = true;

		}
	}
}
