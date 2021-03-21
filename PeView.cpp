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

//RVAתFOA
DWORD PeView::RvaToFoa(IN DWORD dwRva)
{
	//���ڴ󲿷�ʹ��ʱ����Ҫ��pFileBuffer��ȡֵ�����Դ˴����ؼ���pFileBuffer��ĵ�ַ
	return (DWORD)fileBuffer + RvaToFoaNoBase(dwRva);
}

//�������
DWORD PeView::AlignCalc(IN DWORD data, IN DWORD alignSize)
{
	//�Ѷ���
	if (data % alignSize == 0)
	{
		return data;
	}
	return (data / alignSize + 1) * alignSize;
}


//�ļ���ȡ
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

//PEͷ��ȡ
BOOL PeView::LoadPEHeader(LPVOID fileBuffer)
{
	pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)fileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//�ж��Ƿ�ΪPE�ļ�
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	//��ȡ������
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RvaToFoa(pOptionHeader->DataDirectory[0].VirtualAddress));
	//��ȡ�����
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFoa(pOptionHeader->DataDirectory[1].VirtualAddress));
	//��ȡ�ض�λ��
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)(RvaToFoa(pOptionHeader->DataDirectory[5].VirtualAddress));
	//��ȡ�����
	pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(RvaToFoa(pOptionHeader->DataDirectory[11].VirtualAddress));

	return TRUE;
}



PeView::PeView(IN LPSTR lpszFile)
{
	if (ReadPEFile(lpszFile))
		if (!LoadPEHeader(fileBuffer)) //�����װ�Ĳ���pe�ļ����ļ���С��0��
			fileBufferSize = 0;
}

PeView::~PeView()
{
	free(fileBuffer);
}
