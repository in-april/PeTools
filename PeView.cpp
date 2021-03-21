#include "PeView.h"

DWORD PeView::RvaToFoaNoBase(IN DWORD dwRva)
{
	if (dwRva <= pOptionHeader->SizeOfHeaders)
	{
		return dwRva;
	}
	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;
	for (int n = 0; n < pPEHeader->NumberOfSections; n++)
	{
		if (dwRva <= pSectionHeaderTemp->VirtualAddress + pSectionHeaderTemp->SizeOfRawData)
		{
			break;
		}
		pSectionHeaderTemp++;
	}
	DWORD fileOffsetAddress = 0;
	fileOffsetAddress = dwRva - pSectionHeaderTemp->VirtualAddress + pSectionHeaderTemp->PointerToRawData;

	return fileOffsetAddress;
}

//RVA转FOA
DWORD PeView::RvaToFoa(IN DWORD dwRva)
{
	//由于大部分使用时，需要从pFileBuffer中取值，所以此处返回加上pFileBuffer后的地址
	return (DWORD)fileBuffer + RvaToFoaNoBase(dwRva);
}

//对齐计算
DWORD PeView::AlignCalc(IN DWORD data, IN DWORD alignSize)
{
	//已对齐
	if (data % alignSize == 0)
	{
		return data;
	}
	return (data / alignSize + 1) * alignSize;
}


//文件读取
DWORD PeView::ReadPEFile(IN LPSTR lpszFile)
{
	FILE* fp;
	errno_t err = fopen_s(&fp, lpszFile, "rb");
	if (err == 0)
	{
		fseek(fp, 0, SEEK_END);
		long lSize = ftell(fp);
		fileBuffer = malloc(lSize);
		if (fileBuffer != NULL) {
			rewind(fp);
			fread(fileBuffer, 1, lSize, fp);
		}
		fileBufferSize = lSize;
		return lSize;
	}
	return 0;
}

//PE头读取
BOOL PeView::LoadPEHeader(LPVOID fileBuffer)
{
	pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)fileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//判断是否为PE文件
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	//读取导出表
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RvaToFoa(pOptionHeader->DataDirectory[0].VirtualAddress));
	//读取导入表
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFoa(pOptionHeader->DataDirectory[1].VirtualAddress));
	//读取重定位表
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)(RvaToFoa(pOptionHeader->DataDirectory[5].VirtualAddress));
	//读取导入表
	pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(RvaToFoa(pOptionHeader->DataDirectory[11].VirtualAddress));

	return TRUE;
}



PeView::PeView(IN LPSTR lpszFile)
{
	if (ReadPEFile(lpszFile))
		if (!LoadPEHeader(fileBuffer)) //如果加装的不是pe文件则将文件大小置0；
			fileBufferSize = 0;
}

PeView::~PeView()
{
	free(fileBuffer);
}
