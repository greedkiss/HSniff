
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
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
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

	ON_NOTIFY(NM_CLICK, IDC_LIST2, &CHSniffDlg::OnClickedList1)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST2, &CHSniffDlg::OnCustomdrawList1)

	ON_BN_CLICKED(IDC_BUTTON1, &CHSniffDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CHSniffDlg::OnBnClickedButton2)
	//捕获网络包的处理函数
	ON_MESSAGE(WM_PKTCATCH, &CHSniffDlg::OnPktCatchMessage)
	ON_BN_CLICKED(IDC_BUTTON3, &CHSniffDlg::OnBnClickedButton3)
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

	combox_filter.AddString(_T("选择过滤器（可选）"));
	combox_filter.SetCurSel(0);

	for (int i = 0; i < filterList.size(); ++i)
		combox_filter.AddString(filterList[i]);
}

void CHSniffDlg::initialListCtrlPacketList() {
	CRect rect;
	listCtrl_packetList.GetWindowRect(&rect);

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

		CString fileName = L"SnifferUI_" + currentTime.Format("%Y%m%d%H%M%S") + L".pcap";
		pktDumper.setPath(L".\\tmp\\" + fileName);

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
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");
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
		if (selFilterIndex != 9)
		{
			CString strFilter;
			combox_filter.GetLBText(selFilterIndex, strFilter);
			if (strFilter == pkt.protocol)
				printListCtrlPacketList(pkt);
		}
		else {
			printListCtrlPacketList(pkt);
		}
			

		//updateStatusBar(CString(""), m_pool.getSize(), m_listCtrlPacketList.GetItemCount());
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
		//m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_GRAYED);	// 禁用菜单项"另存为"
		AfxGetMainWnd()->SetWindowText(dlgFile.GetFileName());		// 修改标题栏
		//m_statusBar.SetPaneText(0, "已保存至：" + saveAsFilePath, true);	// 修改状态栏

	}
}

//点击列表显示详细信息
void CHSniffDlg::OnClickedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	/* 获取选中行的行号 */
	int selectedItemIndex = listCtrl_packetList.GetSelectionMark();
	CString strPktNum = listCtrl_packetList.GetItemText(selectedItemIndex, 0);
	int pktNum = _ttoi(strPktNum);
	if (pktNum < 1 || pktNum > pool.getSize())
		return;

	//POSITION pos = g_packetLinkList.FindIndex(pktNum - 1);
	//Packet &pkt = g_packetLinkList.GetAt(pos);

	const Packet& pkt = pool.get(pktNum);

	//printTreeCtrlPacketDetails(pkt);
	printEditCtrlPacketBytes(pkt);
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
			strPacketBytes += "\t";
			//strPacketBytes += "#";
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
				strPacketBytes += "\r\n";
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
			strPacketBytes += "  ";
			strPacketBytes += " ";
			++byteCount16;
			if (byteCount16 == 8)
			{
				strPacketBytes += "\t";
				//strPacketBytes += "#";
			}
		}
		strPacketBytes += " ";
		/* 打印最后一行字节对应的ASCII字符 */
		for (int charCount = 0; charCount < (pkt.header->caplen % 16); ++charCount, ++pASCIIPacketBytes)
		{
			strTmp.Format(L"%c", isalnum(*pASCIIPacketBytes) ? *pASCIIPacketBytes : '.');
			strPacketBytes += strTmp;
		}
		strPacketBytes += "\r\n";
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
			if (*pStrPktProtocol == "ARP")
			{
				itemColor = RGB(255, 182, 193);	// 红色
			}
			else if (*pStrPktProtocol == "ICMP")
			{
				itemColor = RGB(186, 85, 211);	// 紫色
			}
			else if (*pStrPktProtocol == "TCP")
			{
				itemColor = RGB(144, 238, 144);	// 绿色
			}
			else if (*pStrPktProtocol == "UDP")
			{
				itemColor = RGB(100, 149, 237);	// 蓝色

			}
			else if (*pStrPktProtocol == "DNS")
			{
				itemColor = RGB(135, 206, 250);	// 浅蓝色
			}
			else if (*pStrPktProtocol == "DHCP")
			{
				itemColor = RGB(189, 254, 76);	// 淡黄色
			}
			else if (*pStrPktProtocol == "HTTP")
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