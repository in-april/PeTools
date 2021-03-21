#include "framework.h"
#include "PEToolsWinMain.h"
#include "MessageProc.h"

//全局实例句柄
HINSTANCE hAppInstance;
//文件路径缓冲区
TCHAR szFileName[256] = { 0 };
//TCHAR szShellFileName[256] = { 0 };
TCHAR szSrcFileName[256] = { 0 };

//主消息处理函数
BOOL CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//PE头查看消息处理函数
BOOL CALLBACK PeDlgProc(HWND hPeViewDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//PE头查看之节表消息处理函数
BOOL CALLBACK PeSectionDlgProc(HWND hPeSectionViewDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//PE头查看之目录消息处理函数
BOOL CALLBACK PeDirectoryDlgProc(HWND hPeDirectoryViewDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//PE头查看目录之导入表消息处理函数
BOOL CALLBACK PeDirectoryImportDlgProc(HWND hPeDirectoryImportDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//PE头查看目录之导出表消息处理函数
BOOL CALLBACK PeDirectoryExportDlgProc(HWND hPeDirectoryExportDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//PE头查看目录之绑定导入表消息处理函数
BOOL CALLBACK PeDirectoryBoundDlgProc(HWND hPeDirectoryBoundDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//PE头查看目录之重定位表消息处理函数
BOOL CALLBACK PeDirectoryRelocationDlgProc(HWND hPeDirectoryRelocationDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//PE头查看目录之资源表消息处理函数
BOOL CALLBACK PeDirectoryResourceDlgProc(HWND hPeDirectoryResourceDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//加壳消息处理函数
BOOL CALLBACK ShellDlgProc(HWND hShellDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    hAppInstance = hInstance;

    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDlgProc);
    return 0;
}

//主消息处理函数
BOOL CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;
    //获取IDC_LIST_PROCESS句柄
    HWND hListProcess = GetDlgItem(hDlg, IDC_LIST_PROCESS);
    //获取IDC_LIST_PROCESS句柄
    HWND hListModule = GetDlgItem(hDlg, IDC_LIST_MODULE);

    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    //初始化
    case WM_INITDIALOG:
        InitProcessListView(hListProcess);
        InitModuleListView(hListModule);
        return TRUE;

    case WM_NOTIFY:
    {
        NMHDR* pNMHDR = (NMHDR*)lParam;
        //点击进程列表
        if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK)
        {
            EnumModules(hListProcess, wParam, lParam, hListModule);
        }
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BUTTON_ABOUT:
            return TRUE;

        case IDC_BUTTON_LOGOUT:
            EndDialog(hDlg, 0);
            return TRUE;

        case IDC_BUTTON_PE:
        {
            //TCHAR szPeFileExt[100] = "*.exe;*.dll;*.scr;*.drv;*.sys";
            TCHAR szPeFileExt[100] = TEXT("Executable  Files(*.exe)\0*.exe\0DLL Files(*.dll)\0*.dll\0All Files(*.*)\0*.*\0\0");
            OPENFILENAME ofn = { 0 };
            ofn.lStructSize = sizeof(OPENFILENAME);
            ofn.hwndOwner = hDlg;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            ofn.lpstrFilter = szPeFileExt;
            ofn.lpstrFile = szFileName;
            ofn.nMaxFile = sizeof(szFileName);

            GetOpenFileName(&ofn);
            //打开PE查看Dialog
            DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_PE), hDlg, (DLGPROC)PeDlgProc);
            return TRUE;
        }
        case IDC_BUTTON_Shell:
            DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_Shelling), hDlg, (DLGPROC)ShellDlgProc);
            return TRUE;
        }
    }
    return result;
}

BOOL CALLBACK PeDlgProc(HWND hPeViewDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;
    switch (uMsg)
    {
    case WM_CLOSE:
        ClosePeView();
        EndDialog(hPeViewDlg, 0);
        return TRUE;

    //初始化
    case WM_INITDIALOG:
        if (!InitPeView(hPeViewDlg))
        {
            MessageBox(hPeViewDlg, TEXT("打开文件失败"), NULL, MB_OK);
            EndDialog(hPeViewDlg, 0);
        }
        return TRUE;


    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BUTTON_SECTION:
            DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_SECTION), hPeViewDlg, (DLGPROC)PeSectionDlgProc);
            return TRUE;

        case IDC_BUTTON_DIRECTORY:
            DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_DIRECTORY), hPeViewDlg, (DLGPROC)PeDirectoryDlgProc);
            return TRUE;
        }
    }
    return result;
}

BOOL CALLBACK PeSectionDlgProc(HWND hPeSectionViewDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;
    //获取IDC_LIST_PROCESS句柄
    HWND hListSection = GetDlgItem(hPeSectionViewDlg, IDC_LIST_SECTION);

    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hPeSectionViewDlg, 0);
        return TRUE;

        //初始化
    case WM_INITDIALOG:
        InitPeViewSection(hListSection);
        return TRUE;

    }
    return result;
}

BOOL CALLBACK PeDirectoryDlgProc(HWND hPeDirectoryViewDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;
    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hPeDirectoryViewDlg, 0);
        return TRUE;

        //初始化
    case WM_INITDIALOG:
        InitPeViewDirectory(hPeDirectoryViewDlg);
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_EXPORT:
            
            return TRUE;
        case IDC_IMPORT:
            DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_IMPORT), hPeDirectoryViewDlg, (DLGPROC)PeDirectoryImportDlgProc);
            return TRUE;
        case IDC_RESOURCE:
            return TRUE;
        case IDC_RELOCATION:
            return TRUE;
        case IDC_BOUNDIMPORT:
            return TRUE;
        }
    }
    return result;
}

BOOL CALLBACK PeDirectoryImportDlgProc(HWND hPeDirectoryImportDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;
    HWND hListDLLName = GetDlgItem(hPeDirectoryImportDlg, IDC_LIST_DLLNAME);
    HWND hListDLLInfo = GetDlgItem(hPeDirectoryImportDlg, IDC_LIST_DLLINFO);

    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hPeDirectoryImportDlg, 0);
        return TRUE;

        //初始化
    case WM_INITDIALOG:
        InitPeViewImport(hPeDirectoryImportDlg, hListDLLName, hListDLLInfo);
        return TRUE;

    case WM_NOTIFY:
    {
        NMHDR* pNMHDR = (NMHDR*)lParam;
        //点击进程列表
        if (wParam == IDC_LIST_DLLNAME && pNMHDR->code == NM_CLICK)
        {
            EnumImportFunc(hListDLLName, wParam, lParam, hListDLLInfo);
        }
        return TRUE;
    }
    }

    return result;
}

BOOL CALLBACK PeDirectoryExportDlgProc(HWND hPeDirectoryExportDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;

    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hPeDirectoryExportDlg, 0);
        return TRUE;

        //初始化
    case WM_INITDIALOG:
        return TRUE;

    }
    return result;
}

BOOL CALLBACK PeDirectoryBoundDlgProc(HWND hPeDirectoryBoundDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;

    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hPeDirectoryBoundDlg, 0);
        return TRUE;

        //初始化
    case WM_INITDIALOG:
        return TRUE;

    }
    return result;
}

BOOL CALLBACK PeDirectoryRelocationDlgProc(HWND hPeDirectoryRelocationDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;

    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hPeDirectoryRelocationDlg, 0);
        return TRUE;

        //初始化
    case WM_INITDIALOG:
        return TRUE;

    }
    return result;
}

BOOL CALLBACK PeDirectoryResourceDlgProc(HWND hPeDirectoryResourceDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;

    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hPeDirectoryResourceDlg, 0);
        return TRUE;

        //初始化
    case WM_INITDIALOG:
        return TRUE;

    }
    return result;
}

BOOL CALLBACK ShellDlgProc(HWND hShellDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    BOOL result = FALSE;
    //HWND hShellPath = GetDlgItem(hShellDlg, IDC_EDIT_ShellPath);
    HWND hSrcPath = GetDlgItem(hShellDlg, IDC_EDIT_SRCPath);
    TCHAR szPeFileExt[100] = TEXT("Executable  Files(*.exe)\0*.exe\0DLL Files(*.dll)\0*.dll\0All Files(*.*)\0*.*\0\0");

    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hShellDlg, 0);
        return TRUE;

        //初始化
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BUTTON_OPENSRC:
        {
            //TCHAR szPeFileExt[100] = "*.exe;*.dll;*.scr;*.drv;*.sys";

            OPENFILENAME ofnSrc = { 0 };
            ofnSrc.lStructSize = sizeof(OPENFILENAME);
            ofnSrc.hwndOwner = hShellDlg;
            ofnSrc.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            ofnSrc.lpstrFilter = szPeFileExt;
            ofnSrc.lpstrFile = szSrcFileName;
            ofnSrc.nMaxFile = sizeof(szSrcFileName);
            GetOpenFileName(&ofnSrc);
            SetWindowText(hSrcPath, szSrcFileName);

            return TRUE;
        }
        //case IDC_BUTTON_OPENSHELL:
        //{
        //    OPENFILENAME ofn = { 0 };
        //    ofn.lStructSize = sizeof(OPENFILENAME);
        //    ofn.hwndOwner = hShellDlg;
        //    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        //    ofn.lpstrFilter = szPeFileExt;
        //    ofn.lpstrFile = szShellFileName;
        //    ofn.nMaxFile = sizeof(szShellFileName);
        //    GetOpenFileName(&ofn);
        //    SetWindowText(hShellPath, szShellFileName);
        //    return TRUE;
        //}
        case IDC_BUTTON_Shelling:
        {
            Shelling(hShellDlg);
        }
        }
        return TRUE;
    }
    return result;
}
