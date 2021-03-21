#include "MessageProc.h"

extern HINSTANCE hAppInstance;
//文件路径缓冲区
extern TCHAR szFileName[256];
//extern TCHAR szShellFileName[256];
extern TCHAR szSrcFileName[256];
//PE信息查看对象
PeView* peView;

// 进程遍历
VOID EnumProcess(HWND hListProcess)
{
    LV_ITEM vitem = { 0 };
    vitem.mask = LVIF_TEXT;

    PROCESSENTRY32 processEntry;
    MODULEENTRY32 moduleEntry;
    processEntry.dwSize = sizeof(processEntry);
    moduleEntry.dwSize = sizeof(moduleEntry);

    //获取所有进程的快照
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) return;

    if (!Process32First(hProcessSnap, &processEntry)) return;

    DWORD index = 0;

    do
    {
        //获取当前进程所有模块的快照
        HANDLE hTmp = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processEntry.th32ProcessID);
        if (hTmp == INVALID_HANDLE_VALUE)
        {
            Process32Next(hProcessSnap, &processEntry);
            continue;
        }
        Module32First(hTmp, &moduleEntry);//第一个模块的基址为进程的基址

        char pid[10];
        char imageAddr[20];
        char imageSize[20];


        vitem.pszText = processEntry.szExeFile;
        vitem.iItem = index;
        vitem.iSubItem = 0;
        ListView_InsertItem(hListProcess, &vitem);

        wsprintf(pid, "%d", processEntry.th32ProcessID);
        vitem.pszText = TEXT(pid);
        vitem.iItem = index;
        vitem.iSubItem = 1;
        ListView_SetItem(hListProcess, &vitem);

        wsprintf(imageAddr, "0x%08x", (DWORD)moduleEntry.modBaseAddr);
        vitem.pszText = TEXT(imageAddr);
        vitem.iItem = index;
        vitem.iSubItem = 2;
        ListView_SetItem(hListProcess, &vitem);


        wsprintf(imageSize, "0x%08x", (DWORD)moduleEntry.modBaseSize);
        vitem.pszText = TEXT(imageSize);
        vitem.iItem = index;
        vitem.iSubItem = 3;
        ListView_SetItem(hListProcess, &vitem);

        index++;

    } while (Process32Next(hProcessSnap, &processEntry));

}

//模块遍历
VOID EnumModules(HWND hListProcess, WPARAM wParam, LPARAM lParam, HWND hListModule)
{
    DWORD dwRowId;
    TCHAR szPid[0x20] = { 0 }; //用于接收pid
    LV_ITEM lv = { 0 };

    //获取选择行
    dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
    if (dwRowId == -1) return;

    //获取PID
    lv.iSubItem = 1;        //要获取的列
    lv.pszText = szPid;     //指定存储查询结果的缓冲区
    lv.cchTextMax = 0x20;   //执行缓冲区大小
    SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);


    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)atoi(szPid));
    if (INVALID_HANDLE_VALUE == hSnapshot) return;

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    Module32First(hSnapshot, &moduleEntry);

    LV_ITEM moduleItem = { 0 };
    DWORD index = 0;

    moduleItem.mask = LVIF_TEXT;

    ListView_DeleteAllItems(hListModule);
    do
    {
        moduleItem.pszText = moduleEntry.szModule;
        moduleItem.iItem = index;
        moduleItem.iSubItem = 0;
        ListView_InsertItem(hListModule, &moduleItem);

        moduleItem.pszText = TEXT(moduleEntry.szExePath);
        moduleItem.iItem = index;
        moduleItem.iSubItem = 1;
        ListView_SetItem(hListModule, &moduleItem);

        index++;

    } while (Module32Next(hSnapshot, &moduleEntry));
    CloseHandle(hSnapshot);

}

//初始化ProcessList
VOID InitProcessListView(HWND hListProcess)
{
    LV_COLUMN lv = { 0 };

    //设置整行选中
    SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("进程");
    lv.cx = 150; //列宽
    lv.iSubItem = 0; //列号
    SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

    //第二列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("PID");
    lv.cx = 100; //列宽
    lv.iSubItem = 1;
    SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

    //第三列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("镜像基址");
    lv.cx = 100;
    lv.iSubItem = 2;
    SendMessage(hListProcess, LVM_INSERTCOLUMN, 2, (DWORD)&lv);

    //第四列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("镜像大小");
    lv.cx = 100;
    lv.iSubItem = 3;
    SendMessage(hListProcess, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

    EnumProcess(hListProcess);
}

//初始化ModuleList
VOID InitModuleListView(HWND hListModule)
{
    LV_COLUMN lv = { 0 };
    
    //设置整行选中
    SendMessage(hListModule, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("模块名称");
    lv.cx = 150; //列宽
    lv.iSubItem = 0; //列号
    SendMessage(hListModule, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

    //第二列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("模块位置");
    lv.cx = 400; //列宽
    lv.iSubItem = 1;
    SendMessage(hListModule, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
}

//初始化PE窗口
BOOL InitPeView(HWND hPeViewDlg)
{
    peView = new PeView(szFileName);
    if (peView->fileBufferSize == 0) return FALSE;

    HWND hEditTemp = NULL;
    TCHAR szUserBuff[0x20] = { 0 };

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_EntryPoint);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->AddressOfEntryPoint);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_ImageBase);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->ImageBase);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_SizeOfImage);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->SizeOfImage);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_BaseOfCode);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->BaseOfCode);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_BaseOfData);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->BaseOfData);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_FAlignment);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->FileAlignment);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_SAlignment);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->SectionAlignment);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_Subsystem);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->Subsystem);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_NumOfSec);
    wsprintf(szUserBuff, "%x", peView->pPEHeader->NumberOfSections);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_TimeStamp);
    wsprintf(szUserBuff, "%x", peView->pPEHeader->TimeDateStamp);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_SizeOfHeader);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->SizeOfHeaders);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_CheckSum);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->CheckSum);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_OptionHead);
    wsprintf(szUserBuff, "%x", peView->pPEHeader->SizeOfOptionalHeader);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_Character);
    wsprintf(szUserBuff, "%x", peView->pPEHeader->Characteristics);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_Magic);
    wsprintf(szUserBuff, "%x", peView->pOptionHeader->Magic);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeViewDlg, IDC_EDIT_Machine);
    wsprintf(szUserBuff, "%x", peView->pPEHeader->Machine);
    SetWindowText(hEditTemp, szUserBuff);

    return TRUE;
}

BOOL ClosePeView()
{
    delete peView;
    return 0;
}

VOID InitPeViewSection(HWND hListSection)
{
    LV_COLUMN lv = { 0 };

    //设置整行选中
    SendMessage(hListSection, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("节名");
    lv.cx = 80; //列宽
    lv.iSubItem = 0; //列号
    SendMessage(hListSection, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

    //第二列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("文件偏移");
    lv.cx = 80; //列宽
    lv.iSubItem = 1;
    SendMessage(hListSection, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

    //第三列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("文件大小");
    lv.cx = 80;
    lv.iSubItem = 2;
    SendMessage(hListSection, LVM_INSERTCOLUMN, 2, (DWORD)&lv);

    //第四列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("内存偏移");
    lv.cx = 80;
    lv.iSubItem = 3;
    SendMessage(hListSection, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

    //第五列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("内存大小");
    lv.cx = 80;
    lv.iSubItem = 4;
    SendMessage(hListSection, LVM_INSERTCOLUMN, 4, (DWORD)&lv);

    //第六列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("属性");
    lv.cx = 100;
    lv.iSubItem = 5;
    SendMessage(hListSection, LVM_INSERTCOLUMN, 5, (DWORD)&lv);

    EnumSection(hListSection);
}

VOID EnumSection(HWND hListSection)
{
    PIMAGE_FILE_HEADER peHeaderTemp = peView->pPEHeader;
    PIMAGE_SECTION_HEADER pSectionHeaderTemp = peView->pSectionHeader;

    LV_ITEM sectionItem = { 0 };
    sectionItem.mask = LVIF_TEXT;
    TCHAR buffer[50];

    for (int index = 0; index < peHeaderTemp->NumberOfSections; index++, pSectionHeaderTemp++)
    {
        wsprintf(buffer, "%s", pSectionHeaderTemp->Name);
        buffer[8] = 0;//若节名占8字节，最后的\0会被挤掉，所以此处补上
        sectionItem.pszText = buffer;
        sectionItem.iItem = index;
        sectionItem.iSubItem = 0;
        ListView_InsertItem(hListSection, &sectionItem);

        wsprintf(buffer, "0x%x", pSectionHeaderTemp->PointerToRawData);
        sectionItem.pszText = buffer;
        sectionItem.iItem = index;
        sectionItem.iSubItem = 1;
        ListView_SetItem(hListSection, &sectionItem);

        wsprintf(buffer, "0x%x", pSectionHeaderTemp->SizeOfRawData);
        sectionItem.pszText = buffer;
        sectionItem.iItem = index;
        sectionItem.iSubItem = 2;
        ListView_SetItem(hListSection, &sectionItem);

        wsprintf(buffer, "0x%x", pSectionHeaderTemp->VirtualAddress);
        sectionItem.pszText = buffer;
        sectionItem.iItem = index;
        sectionItem.iSubItem = 3;
        ListView_SetItem(hListSection, &sectionItem);

        wsprintf(buffer, "0x%x", pSectionHeaderTemp->Misc.VirtualSize);
        sectionItem.pszText = buffer;
        sectionItem.iItem = index;
        sectionItem.iSubItem = 4;
        ListView_SetItem(hListSection, &sectionItem);

        wsprintf(buffer, "0x%08X", pSectionHeaderTemp->Characteristics);
        sectionItem.pszText = buffer;
        sectionItem.iItem = index;
        sectionItem.iSubItem = 5;
        ListView_SetItem(hListSection, &sectionItem);
    }
}

VOID InitPeViewDirectory(HWND hPeDirectoryViewDlg)
{
    PIMAGE_DATA_DIRECTORY pDataDirectoryTemp = (PIMAGE_DATA_DIRECTORY)peView->pOptionHeader->DataDirectory;
    HWND hEditTemp = NULL;
    TCHAR szUserBuff[0x20] = { 0 };

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_EXPORT_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_EXPORT_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);
    //若导出表不存在，则按钮不可点击
    if (!pDataDirectoryTemp->VirtualAddress)
    {
        EnableWindow(GetDlgItem(hPeDirectoryViewDlg, IDC_EXPORT), FALSE);
    }

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_IMPORT_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_IMPORT_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);
    if (!pDataDirectoryTemp->VirtualAddress)
    {
        EnableWindow(GetDlgItem(hPeDirectoryViewDlg, IDC_IMPORT), FALSE);
    }

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_RESOURCE_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_RESOURCE_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);
    if (!pDataDirectoryTemp->VirtualAddress)
    {
        EnableWindow(GetDlgItem(hPeDirectoryViewDlg, IDC_RESOURCE), FALSE);
    }

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_EXCEPTION_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_EXCEPTION_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_SECURITY_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_SECURITY_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_RELOCATION_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_RELOCATION_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);
    if (!pDataDirectoryTemp->VirtualAddress)
    {
        EnableWindow(GetDlgItem(hPeDirectoryViewDlg, IDC_RELOCATION), FALSE);
    }

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_DUBUG_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_DUBUG_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_COPYRIGHT_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_COPYRIGHT_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_GLOBALPTR_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_GLOBALPTR_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_TLS_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_TLS_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_LOADCONFIG_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_LOADCONFIG_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_BOUNDIMPORT_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_BOUNDIMPORT_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);
    if (!pDataDirectoryTemp->VirtualAddress)
    {
        EnableWindow(GetDlgItem(hPeDirectoryViewDlg, IDC_BOUNDIMPORT), FALSE);
    }

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_IAT_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_IAT_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_DELAY_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_DELAY_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_COM_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_COM_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);

    pDataDirectoryTemp++;
    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_RETAIN_RVA);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->VirtualAddress);
    SetWindowText(hEditTemp, szUserBuff);

    hEditTemp = GetDlgItem(hPeDirectoryViewDlg, IDC_EDIT_RETAIN_SIZE);
    wsprintf(szUserBuff, "0x%x", pDataDirectoryTemp->Size);
    SetWindowText(hEditTemp, szUserBuff);
}

VOID InitPeViewImport(HWND hPeDirectoryImportDlg, HWND hListDLLName, HWND hListDLLInfo)
{
    LV_COLUMN lv = { 0 };

    //设置整行选中
    SendMessage(hListDLLName, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
    SendMessage(hListDLLInfo, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

    //初始化DLL名列表
    //第一列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("DLL名称");
    lv.cx = 150; //列宽
    lv.iSubItem = 0; //列号
    SendMessage(hListDLLName, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

    //第二列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("INT文件偏移");
    lv.cx = 100; //列宽
    lv.iSubItem = 1;
    SendMessage(hListDLLName, LVM_INSERTCOLUMN, 1, (DWORD)&lv);

    //第三列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("INT内存偏移");
    lv.cx = 100; //列宽
    lv.iSubItem = 2;
    SendMessage(hListDLLName, LVM_INSERTCOLUMN, 2, (DWORD)&lv);

    //第四列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("IAT文件偏移");
    lv.cx = 100;
    lv.iSubItem = 3;
    SendMessage(hListDLLName, LVM_INSERTCOLUMN, 3, (DWORD)&lv);

    //第五列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("IAT内存偏移");
    lv.cx = 100;
    lv.iSubItem = 4;
    SendMessage(hListDLLName, LVM_INSERTCOLUMN, 4, (DWORD)&lv);

    //第六列
    lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lv.pszText = TEXT("时间戳");
    lv.cx = 100;
    lv.iSubItem = 5;
    SendMessage(hListDLLName, LVM_INSERTCOLUMN, 5, (DWORD)&lv);

    //获取DLL名列表
    char szBuffer[50];
    DWORD index = 0;
    LV_ITEM vitem = { 0 };
    vitem.mask = LVIF_TEXT;

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorTemp = peView->pImportDescriptor;
    //导入表结尾处有sizeof(PIMAGE_IMPORT_DESCRIPTOR)个0，所以取两个地址判断一下是否为0
    while (pImportDescriptorTemp->OriginalFirstThunk && pImportDescriptorTemp->FirstThunk)
    {
        //dll名称
        wsprintf(szBuffer, "%s", (char*)peView->RvaToFoa(pImportDescriptorTemp->Name));
        vitem.pszText = TEXT(szBuffer);
        vitem.iItem = index;
        vitem.iSubItem = 0;
        ListView_InsertItem(hListDLLName, &vitem);

        //INT
        wsprintf(szBuffer, "0x%x", peView->RvaToFoaNoBase(pImportDescriptorTemp->OriginalFirstThunk));
        vitem.pszText = TEXT(szBuffer);
        vitem.iItem = index;
        vitem.iSubItem = 1;
        ListView_SetItem(hListDLLName, &vitem);

        wsprintf(szBuffer, "0x%x", pImportDescriptorTemp->OriginalFirstThunk);
        vitem.pszText = TEXT(szBuffer);
        vitem.iItem = index;
        vitem.iSubItem = 2;
        ListView_SetItem(hListDLLName, &vitem);

        //IAT
        wsprintf(szBuffer, "0x%x", peView->RvaToFoaNoBase(pImportDescriptorTemp->FirstThunk));
        vitem.pszText = TEXT(szBuffer);
        vitem.iItem = index;
        vitem.iSubItem = 3;
        ListView_SetItem(hListDLLName, &vitem);

        wsprintf(szBuffer, "0x%x", pImportDescriptorTemp->FirstThunk);
        vitem.pszText = TEXT(szBuffer);
        vitem.iItem = index;
        vitem.iSubItem = 4;
        ListView_SetItem(hListDLLName, &vitem);

        //时间戳
        wsprintf(szBuffer, "%x", pImportDescriptorTemp->TimeDateStamp);
        vitem.pszText = TEXT(szBuffer);
        vitem.iItem = index;
        vitem.iSubItem = 5;
        ListView_SetItem(hListDLLName, &vitem);

        index++;
        pImportDescriptorTemp++;
    }


    //初始化DLL信息列表
    //第一列
    lv.pszText = TEXT("序号");
    lv.cx = 100;
    lv.iSubItem = 0;
    SendMessage(hListDLLInfo, LVM_INSERTCOLUMN, 0, (DWORD)&lv);

    lv.pszText = TEXT("函数名");
    lv.cx = 300;
    lv.iSubItem = 1;
    SendMessage(hListDLLInfo, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
}

VOID EnumImportFunc(HWND hListDLLName, WPARAM wParam, LPARAM lParam, HWND hListDLLInfo)
{
    DWORD dwRowId;
    TCHAR szINTFoa[0x20] = { 0 }; //用于接收INT表foa
    LV_ITEM lv = { 0 };

    //获取选择行
    dwRowId = SendMessage(hListDLLName, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
    if (dwRowId == -1) return;

    //获取PID
    lv.iSubItem = 1;        //要获取的列
    lv.pszText = szINTFoa;     //指定存储查询结果的缓冲区
    lv.cchTextMax = 0x20;   //执行缓冲区大小
    SendMessage(hListDLLName, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);



    DWORD INTfoa = 0;
    sscanf_s(szINTFoa, "%x", &INTfoa);
    PDWORD pINTfoa = (PDWORD)((DWORD)peView->fileBuffer + (DWORD)INTfoa);


    char buffer[50];
    DWORD index = 0;
    LV_ITEM vitem = { 0 };
    vitem.mask = LVIF_TEXT;

    ListView_DeleteAllItems(hListDLLInfo);

    while (*pINTfoa)
    {
        DWORD data = *pINTfoa & 0x7FFFFFFF;
        //判断最高位，若为1，则后31位为导出序号，若为0，则为函数名地址
        if ((*pINTfoa & 0x80000000) == 0x80000000) //最高位为1，说明是序号
        {
            //序号
            wsprintf(buffer, "%d", data);
            vitem.pszText = TEXT(buffer);
            vitem.iItem = index;
            vitem.iSubItem = 0;
            ListView_InsertItem(hListDLLInfo, &vitem);

            //函数名
            wsprintf(buffer, "%s", "NULL");
            vitem.pszText = TEXT(buffer);
            vitem.iItem = index;
            vitem.iSubItem = 1;
            ListView_SetItem(hListDLLInfo, &vitem);
        }
        else //为函数名地址
        {
            //序号
            wsprintf(buffer, "%s", "NULL");
            vitem.pszText = TEXT(buffer);
            vitem.iItem = index;
            vitem.iSubItem = 0;
            ListView_InsertItem(hListDLLInfo, &vitem);

            //函数名
            data = peView->RvaToFoa(data);
            char* str = (char*)data + 2;//前两个字节没用
            wsprintf(buffer, "%s", str);
            vitem.pszText = TEXT(buffer);
            vitem.iItem = index;
            vitem.iSubItem = 1;
            ListView_SetItem(hListDLLInfo, &vitem);
        }
        pINTfoa++;
    }
}

//加壳
BOOL Shelling(HWND hShellDlg)
{
    BOOL result = TRUE;
    //密码表
    DWORD dict[] = {0x12348412,0x1a851c21,0x45a28cb0,0x34af0210,
                    0x98abcd51,0x102d4f8a,0x301cd120,0xaa1154bf,
                    0xddbb2541,0xd125bfc2,0x1287adcf,0xe12ad512,
                    0x1defa210,0x12d5f1e5,0x2a3d51bc,0xeea84079};
    
    //壳代码
    BYTE shell[] = { 0x55,0x8b,0xec,0x81,0xec,0xe0,0x0,0x0,0x0,0x53,0x56,0x57,0xc6,0x85,0x24,0xff,0xff,0xff,0x0,0xc6,0x85,0x25,0xff,0xff,0xff,0x1,0xc6,0x85,0x26,0xff,0xff,0xff,0x2,0xc6,0x85,0x27,0xff,0xff,0xff,0x3,0xc6,0x85,0x28,0xff,0xff,0xff,0x4,0xc6,0x85,0x29,0xff,0xff,0xff,0x5,0xc6,0x85,0x2a,0xff,0xff,0xff,0x6,0xc6,0x85,0x2b,0xff,0xff,0xff,0x7,0xc6,0x85,0x2c,0xff,0xff,0xff,0x8,0xc6,0x85,0x2d,0xff,0xff,0xff,0x9,0xc6,0x85,0x2e,0xff,0xff,0xff,0xa,0xc6,0x85,0x2f,0xff,0xff,0xff,0xb,0xc6,0x85,0x30,0xff,0xff,0xff,0xc,0xc6,0x85,0x31,0xff,0xff,0xff,0xd,0xc6,0x85,0x32,0xff,0xff,0xff,0xe,0xc6,0x85,0x33,0xff,0xff,0xff,0xf,0xc7,0x85,0x38,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x85,0x34,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x85,0x68,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x45,0xe4,0x0,0x0,0x0,0x0,0xc7,0x85,0x5c,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x85,0x6c,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x45,0x94,0x0,0x0,0x0,0x0,0xc7,0x85,0x20,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x45,0x9c,0x12,0x84,0x34,0x12,0xc7,0x45,0xa0,0x21,0x1c,0x85,0x1a,0xc7,0x45,0xa4,0xb0,0x8c,0xa2,0x45,0xc7,0x45,0xa8,0x10,0x2,0xaf,0x34,0xc7,0x45,0xac,0x51,0xcd,0xab,0x98,0xc7,0x45,0xb0,0x8a,0x4f,0x2d,0x10,0xc7,0x45,0xb4,0x20,0xd1,0x1c,0x30,0xc7,0x45,0xb8,0xbf,0x54,0x11,0xaa,0xc7,0x45,0xbc,0x41,0x25,0xbb,0xdd,0xc7,0x45,0xc0,0xc2,0xbf,0x25,0xd1,0xc7,0x45,0xc4,0xcf,0xad,0x87,0x12,0xc7,0x45,0xc8,0x12,0xd5,0x2a,0xe1,0xc7,0x45,0xcc,0x10,0xa2,0xef,0x1d,0xc7,0x45,0xd0,0xe5,0xf1,0xd5,0x12,0xc7,0x45,0xd4,0xbc,0x51,0x3d,0x2a,0xc7,0x45,0xd8,0x79,0x40,0xa8,0xee,0xc6,0x85,0x70,0xff,0xff,0xff,0x4c,0xc6,0x85,0x71,0xff,0xff,0xff,0x6f,0xc6,0x85,0x72,0xff,0xff,0xff,0x61,0xc6,0x85,0x73,0xff,0xff,0xff,0x64,0xc6,0x85,0x74,0xff,0xff,0xff,0x4c,0xc6,0x85,0x75,0xff,0xff,0xff,0x69,0xc6,0x85,0x76,0xff,0xff,0xff,0x62,0xc6,0x85,0x77,0xff,0xff,0xff,0x72,0xc6,0x85,0x78,0xff,0xff,0xff,0x61,0xc6,0x85,0x79,0xff,0xff,0xff,0x72,0xc6,0x85,0x7a,0xff,0xff,0xff,0x79,0xc6,0x85,0x7b,0xff,0xff,0xff,0x41,0xc6,0x85,0x7c,0xff,0xff,0xff,0x0,0xc6,0x45,0x80,0x56,0xc6,0x45,0x81,0x69,0xc6,0x45,0x82,0x72,0xc6,0x45,0x83,0x74,0xc6,0x45,0x84,0x75,0xc6,0x45,0x85,0x61,0xc6,0x45,0x86,0x6c,0xc6,0x45,0x87,0x50,0xc6,0x45,0x88,0x72,0xc6,0x45,0x89,0x6f,0xc6,0x45,0x8a,0x74,0xc6,0x45,0x8b,0x65,0xc6,0x45,0x8c,0x63,0xc6,0x45,0x8d,0x74,0xc6,0x45,0x8e,0x0,0xc6,0x45,0xe8,0x47,0xc6,0x45,0xe9,0x65,0xc6,0x45,0xea,0x74,0xc6,0x45,0xeb,0x43,0xc6,0x45,0xec,0x6f,0xc6,0x45,0xed,0x6d,0xc6,0x45,0xee,0x6d,0xc6,0x45,0xef,0x61,0xc6,0x45,0xf0,0x6e,0xc6,0x45,0xf1,0x64,0xc6,0x45,0xf2,0x4c,0xc6,0x45,0xf3,0x69,0xc6,0x45,0xf4,0x6e,0xc6,0x45,0xf5,0x65,0xc6,0x45,0xf6,0x41,0xc6,0x45,0xf7,0x0,0xc7,0x85,0x54,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x85,0x3c,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x45,0xe0,0x0,0x0,0x0,0x0,0xc7,0x85,0x40,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x85,0x60,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x45,0xdc,0x0,0x0,0x0,0x0,0xc7,0x45,0xfc,0x0,0x0,0x0,0x0,0xc7,0x45,0x90,0x0,0x0,0x0,0x0,0xc7,0x85,0x44,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0x33,0xc9,0x64,0x8b,0x41,0x30,0x8b,0x40,0xc,0x8b,0x58,0xc,0x8b,0x5b,0x18,0x89,0x9d,0x68,0xff,0xff,0xff,0x8b,0x70,0x1c,0xad,0x96,0xad,0x8b,0x58,0x8,0x8b,0x53,0x3c,0x3,0xd3,0x8b,0x52,0x78,0x3,0xd3,0x8b,0x72,0x20,0x3,0xf3,0x33,0xc9,0x41,0xad,0x3,0xc3,0x81,0x38,0x47,0x65,0x74,0x50,0x75,0xf4,0x81,0x78,0x4,0x72,0x6f,0x63,0x41,0x75,0xeb,0x81,0x78,0x8,0x64,0x64,0x72,0x65,0x75,0xe2,0x8b,0x72,0x24,0x3,0xf3,0x66,0x8b,0xc,0x4e,0x49,0x8b,0x72,0x1c,0x3,0xf3,0x8b,0x14,0x8e,0x3,0xd3,0x89,0x9d,0x54,0xff,0xff,0xff,0x89,0x95,0x3c,0xff,0xff,0xff,0x8d,0x85,0x70,0xff,0xff,0xff,0x50,0xff,0xb5,0x54,0xff,0xff,0xff,0xff,0x95,0x3c,0xff,0xff,0xff,0x89,0x45,0xe0,0x8d,0x85,0x80,0xff,0xff,0xff,0x50,0xff,0xb5,0x54,0xff,0xff,0xff,0xff,0x95,0x3c,0xff,0xff,0xff,0x89,0x85,0x40,0xff,0xff,0xff,0x8d,0x85,0xe8,0xff,0xff,0xff,0x50,0xff,0xb5,0x54,0xff,0xff,0xff,0xff,0x95,0x3c,0xff,0xff,0xff,0x89,0x85,0x60,0xff,0xff,0xff,0x8b,0x9d,0x68,0xff,0xff,0xff,0x8b,0x53,0x3c,0x3,0xd3,0x83,0xc2,0x4,0x89,0x55,0xe4,0x83,0xc2,0x14,0x89,0x95,0x5c,0xff,0xff,0xff,0x8b,0x45,0xe4,0x33,0xc9,0x66,0x8b,0x48,0x10,0x8d,0x4,0xa,0x89,0x45,0x94,0x8b,0x85,0x5c,0xff,0xff,0xff,0x8d,0x50,0x60,0x89,0x95,0x6c,0xff,0xff,0xff,0x8d,0x95,0xdc,0xff,0xff,0xff,0x52,0x6a,0x40,0x8b,0xb5,0x5c,0xff,0xff,0xff,0x8b,0x46,0x38,0x50,0xff,0xb5,0x68,0xff,0xff,0xff,0xff,0x95,0x40,0xff,0xff,0xff,0x89,0x45,0xfc,0x8b,0x85,0x38,0xff,0xff,0xff,0x8d,0x34,0x18,0x8b,0x85,0x6c,0xff,0xff,0xff,0x8b,0xf8,0xb9,0x20,0x0,0x0,0x0,0xf3,0xa5,0x60,0xff,0x95,0x60,0xff,0xff,0xff,0x89,0x85,0x44,0xff,0xff,0xff,0x8b,0x85,0x44,0xff,0xff,0xff,0x89,0x45,0x98,0x8b,0x4d,0x98,0x33,0xd2,0x66,0x8b,0x11,0x85,0xd2,0x74,0x2c,0x8b,0x45,0x98,0x33,0xc9,0x66,0x8b,0x8,0x81,0xf9,0x22,0x20,0x0,0x0,0x74,0xf,0x8b,0x55,0x98,0x33,0xc0,0x66,0x8b,0x2,0x3d,0x20,0x20,0x0,0x0,0x75,0x2,0xeb,0xb,0x8b,0x4d,0x98,0x83,0xc1,0x1,0x89,0x4d,0x98,0xeb,0xc8,0x8b,0x55,0x98,0x83,0xc2,0x2,0x89,0x55,0x98,0xc7,0x85,0x58,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xeb,0xf,0x8b,0x85,0x58,0xff,0xff,0xff,0x83,0xc0,0x1,0x89,0x85,0x58,0xff,0xff,0xff,0x83,0xbd,0x58,0xff,0xff,0xff,0x10,0x7d,0x1a,0x8b,0x4d,0x98,0x3,0x8d,0x58,0xff,0xff,0xff,0x8b,0x95,0x58,0xff,0xff,0xff,0x8a,0x1,0x88,0x84,0x15,0x24,0xff,0xff,0xff,0xeb,0xce,0xc7,0x85,0x4c,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xeb,0xf,0x8b,0x8d,0x4c,0xff,0xff,0xff,0x83,0xc1,0x1,0x89,0x8d,0x4c,0xff,0xff,0xff,0x83,0xbd,0x4c,0xff,0xff,0xff,0x10,0x7d,0xe,0x8b,0x55,0x98,0x3,0x95,0x4c,0xff,0xff,0xff,0xc6,0x2,0x20,0xeb,0xda,0x8b,0x85,0x5c,0xff,0xff,0xff,0x8b,0x8d,0x68,0xff,0xff,0xff,0x3,0x48,0x3c,0x89,0x8d,0x50,0xff,0xff,0xff,0x8b,0x55,0xe4,0x33,0xc0,0x66,0x8b,0x42,0x2,0x6b,0xc0,0x28,0x8b,0x4d,0x94,0x8b,0x95,0x5c,0xff,0xff,0xff,0x8b,0x44,0x1,0xe4,0x2b,0x42,0x3c,0x89,0x45,0xf8,0xc7,0x85,0x48,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xc7,0x85,0x64,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0xeb,0xf,0x8b,0x8d,0x64,0xff,0xff,0xff,0x83,0xc1,0x1,0x89,0x8d,0x64,0xff,0xff,0xff,0x8b,0x55,0xf8,0xc1,0xea,0x2,0x39,0x95,0x64,0xff,0xff,0xff,0x73,0x57,0x8b,0x85,0x48,0xff,0xff,0xff,0x33,0xd2,0xb9,0x10,0x0,0x0,0x0,0xf7,0xf1,0x33,0xc0,0x8a,0x84,0x15,0x24,0xff,0xff,0xff,0x25,0xf,0x0,0x0,0x80,0x79,0x5,0x48,0x83,0xc8,0xf0,0x40,0x8b,0x8d,0x64,0xff,0xff,0xff,0x8b,0x95,0x50,0xff,0xff,0xff,0x8b,0xc,0x8a,0x33,0x4c,0x85,0x9c,0x8b,0x95,0x64,0xff,0xff,0xff,0x8b,0x85,0x50,0xff,0xff,0xff,0x89,0xc,0x90,0x8b,0x8d,0x48,0xff,0xff,0xff,0x83,0xc1,0x1,0x89,0x8d,0x48,0xff,0xff,0xff,0xeb,0x8c,0x61,0x8b,0xb5,0x6c,0xff,0xff,0xff,0x8b,0x76,0x8,0x3,0xf3,0x89,0xb5,0x20,0xff,0xff,0xff,0x8b,0x56,0xc,0x3,0xd3,0x52,0xff,0x55,0xe0,0x89,0x45,0x90,0x8b,0x7e,0x10,0x3,0xfb,0x3e,0xf7,0x7,0x0,0x0,0x0,0x80,0x74,0x16,0x3e,0x81,0x27,0xff,0xff,0xff,0x7f,0xff,0x37,0xff,0x75,0x90,0xff,0x95,0x3c,0xff,0xff,0xff,0x89,0x7,0xeb,0x13,0x1,0x1f,0x8b,0x7,0x83,0xc0,0x2,0x50,0xff,0x75,0x90,0xff,0x95,0x3c,0xff,0xff,0xff,0x89,0x7,0x83,0xc7,0x4,0x8b,0x7,0x85,0xc0,0x75,0xc5,0x83,0xc6,0x14,0x8b,0x46,0x10,0x85,0xc0,0x75,0xaa,0x8b,0x85,0x34,0xff,0xff,0xff,0x3,0xc3,0xff,0xe0,0x33,0xc0,0x5f,0x5e,0x5b,0x8b,0xe5,0x5d,0xc3 };
    DWORD shellSize = sizeof(shell);

    //默认密匙
    char password[17] = { 'p' ,'e' ,'t' ,'o' ,'o' ,'l' ,'s' ,'-','p','a','s','s' ,'w' ,'o' ,'r' ,'d'};
    //BYTE newPasswd[16] = { 0 };
    
    PeEdit *srcFile = new PeEdit(szSrcFileName);
    char* pDirectoryBuffer = NULL;//用于存储原目录表
    pDirectoryBuffer = (char*)malloc(0x80);
    if (pDirectoryBuffer == NULL) {
        return FALSE;
    }
    memcpy(pDirectoryBuffer, srcFile->pOptionHeader->DataDirectory, 0x80);
    //原目录表清空
    memset(srcFile->pOptionHeader->DataDirectory, 0, 0x80);

    GetWindowText(GetDlgItem(hShellDlg, IDC_EDIT_PASSWD), password, 17);

    //按新密匙的顺序取出加密字典，从第一个节开始，依次对数据进行加密
    PDWORD buffer = (PDWORD)((DWORD)srcFile->imageBuffer + srcFile->pOptionHeader->SizeOfHeaders);
    DWORD size = srcFile->pOptionHeader->SizeOfImage - srcFile->pOptionHeader->SizeOfHeaders;
    DWORD index = 0;
    for (int i = 0; i < size / 4; i++)
    {
        buffer[i] ^= dict[password[index % 16] % 16];
        index++;
    }

    //新增节
    DWORD newSectionSize = shellSize + 0x80;
    newSectionSize = srcFile->AddSection(newSectionSize);
    DWORD newSectionAddr = srcFile->pOptionHeader->SizeOfImage - newSectionSize;

    //获取原程序入口点
    DWORD oep = srcFile->pOptionHeader->AddressOfEntryPoint;
    //修改新程序入口点为壳节地址
    srcFile->pOptionHeader->AddressOfEntryPoint = newSectionAddr;

    //修复壳代码中的密匙
    for (int i = 0, num = 18; i < 16; i++, num += 7)
    {
        //shell[num] = newPasswd[i];
    }


    //修复壳代码中的目录表偏移
    DWORD directoryVa = newSectionAddr + shellSize;
    char* p = (char*)&directoryVa;
    for (int i = 0, num = 130; i < 4; i++, num++)
    {
        shell[num] = p[i];
    }

    //修复壳代码中的入口点跳转地址 18
    p = (char*)&oep;
    for (int i = 0, num = 140; i < 4; i++, num++)
    {
        shell[num] = p[i];
    }


    memcpy((char*)srcFile->imageBuffer + newSectionAddr, shell, shellSize);
    memcpy((char*)srcFile->imageBuffer + newSectionAddr + shellSize, pDirectoryBuffer, 0x80);

    
    //导出
    srcFile->CopyImageBufferToFileBuffer();

    
    srcFile->DumpFile("shelled.exe");
    

    return result;
}
