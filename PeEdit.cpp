#include "PeEdit.h"

PeEdit::PeEdit(IN LPSTR lpszFile):PeView(lpszFile)
{
	//���ڴ�չ��
	CopyFileBufferToImageBuffer();
	//���ڴ��еľ������¼���peͷ
	LoadPEHeader(imageBuffer);
}

PeEdit::~PeEdit()
{
	free(imageBuffer);
}

DWORD PeEdit::CopyFileBufferToImageBuffer()
{
	PVOID pTempBuffer = NULL;

	pTempBuffer = calloc(pOptionHeader->SizeOfImage,sizeof(char));
	if (pTempBuffer)
	{
		memcpy(pTempBuffer, fileBuffer, pOptionHeader->SizeOfHeaders);
	}

	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;
	for (int n = 0; n < pPEHeader->NumberOfSections; n++, pSectionHeaderTemp++)
	{
		memcpy((PVOID)((DWORD)pTempBuffer + pSectionHeaderTemp->VirtualAddress),
			(PVOID)((DWORD)fileBuffer + pSectionHeaderTemp->PointerToRawData),
			pSectionHeaderTemp->SizeOfRawData);
	}
	free(imageBuffer);//�ͷ�ԭ�ڴ澵��
	imageBuffer = pTempBuffer;
	imageBufferSize = pOptionHeader->SizeOfImage;
	return imageBufferSize;
}

DWORD PeEdit::CopyImageBufferToFileBuffer()
{
	LPVOID pTempBuffer = NULL;

	//�����������ļ���С�����һ���ڵ��ļ�ƫ��+���һ���ڵ��ļ������Ĵ�С��
	fileBufferSize = pSectionHeader[pPEHeader->NumberOfSections - 1].PointerToRawData
		+ pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData;

	pTempBuffer = calloc(fileBufferSize, sizeof(char));
	if (pTempBuffer)
	{
		memcpy(pTempBuffer, pDosHeader, pOptionHeader->SizeOfHeaders);
	}

	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD j = 0; j < pPEHeader->NumberOfSections; j++, pTempSectionHeader++)
	{
		memcpy((PDWORD)((DWORD)pTempBuffer + pTempSectionHeader->PointerToRawData),
			(PDWORD)((DWORD)imageBuffer + pTempSectionHeader->VirtualAddress),
			pTempSectionHeader->SizeOfRawData);
	}
	free(fileBuffer); //�ͷ�ԭ�ļ�����
	fileBuffer = pTempBuffer;
	return fileBufferSize; 
}

DWORD PeEdit::AddSection(DWORD size)
{
	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;
	DWORD originalImageSize = pOptionHeader->SizeOfImage;

	//���������ڵ�����
	PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)malloc(IMAGE_SIZEOF_SECTION_HEADER); //�ڱ��СΪ40
	if (!pNewSectionHeader)
	{
		return 0;
	}
	//�ڵ�����
	pNewSectionHeader->Name[0] = '.';
	pNewSectionHeader->Name[1] = 'n';
	pNewSectionHeader->Name[2] = 'e';
	pNewSectionHeader->Name[3] = 'w';
	pNewSectionHeader->Name[4] = '\0';
	//����δ����ʱ����ʵ��С
	pNewSectionHeader->Misc.VirtualSize = size;

	//�����ڴ��е�ƫ�ƣ���һ���ڵ��ڴ�ƫ�� + ��һ���ڵ����ڴ�����Ĵ�С��
	pNewSectionHeader->VirtualAddress = pSectionHeaderTemp[pPEHeader->NumberOfSections - 1].VirtualAddress +
		AlignCalc(pSectionHeaderTemp[pPEHeader->NumberOfSections - 1].Misc.VirtualSize, pOptionHeader->SectionAlignment);

	//�����ļ������Ĵ�С
	pNewSectionHeader->SizeOfRawData = AlignCalc(size, pOptionHeader->FileAlignment);

	//�����ļ��е�ƫ�ƣ���һ���ڵ��ļ�ƫ�� + ��һ���ڵ����ļ������Ĵ�С��
	pNewSectionHeader->PointerToRawData = pSectionHeaderTemp[pPEHeader->NumberOfSections - 1].PointerToRawData +
		AlignCalc(pSectionHeaderTemp[pPEHeader->NumberOfSections - 1].SizeOfRawData, pOptionHeader->FileAlignment);

	//������أ�������д
	pNewSectionHeader->PointerToRelocations = 0;
	pNewSectionHeader->PointerToLinenumbers = 0;
	pNewSectionHeader->NumberOfRelocations = 0;
	pNewSectionHeader->NumberOfLinenumbers = 0;

	//�ڵ�����
	pNewSectionHeader->Characteristics = 0xC0000020; //���а������룬�ɶ���ִ��


	//�жϽڱ�����Ƿ����㹻�ռ����ӽڣ��ڱ�ĩβ80byteΪ0 �� SizeOfHeaders - ͷ����ǰ�Ĵ�С > 80��
	char* pTmp = (char*)(pSectionHeaderTemp + pPEHeader->NumberOfSections);
	char flag = 0;
	int zeroLength = 0;
	for (zeroLength = 0; zeroLength < 80; zeroLength++)
	{
		if (pTmp[zeroLength] != 0)
		{
			flag = 1;
			break;
		}
	}
	if (pOptionHeader->SizeOfHeaders - pDosHeader->e_lfanew - 4 - IMAGE_SIZEOF_FILE_HEADER - pPEHeader->SizeOfOptionalHeader
		- pPEHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER < 80)
	{
		flag = 1;
	}
	if (flag != 0) //�ռ䲻��
	{
		//printf("�ڱ�ĩβ�Ŀռ䲻�㣬���ڳ��԰�PEͷ�ͽڱ�����......\n");
		DWORD moveSize = AlignCalc(80 - zeroLength, 8);//���Ƶķ��ȣ��˴�������룩
		if ((char*)pNTHeader - 64 - moveSize > 0) //�������ƿռ�
		{
			memmove((char*)pNTHeader - moveSize, (char*)pNTHeader,
				4 + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader + pPEHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER);
			//�޸�NTͷλ��
			pDosHeader->e_lfanew -= moveSize;
			//���¼���ͷ�ṹ
			LoadPEHeader(imageBuffer);
			pSectionHeaderTemp = pSectionHeader;
			//��սڱ�ռ�
			memset(pSectionHeaderTemp + pPEHeader->NumberOfSections, 0, moveSize);
			//printf("���Ƴɹ������������ڱ�\n");
		}
		else//�ռ仹�ǲ���
		{
			return 0;
		}

	}
	//�޸ı�׼PEͷ�еĽڵ�������1
	pPEHeader->NumberOfSections++;

	//�޸�SizeOfImage
	pOptionHeader->SizeOfImage += AlignCalc(size, pOptionHeader->SectionAlignment);

	//���½ڱ�����ԭ���񣨴�ʱ�ڵĸ����Ѽ�1����������λ��Ҫ��1��
	memcpy(pSectionHeaderTemp + pPEHeader->NumberOfSections - 1, pNewSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	//��ԭ���񿽱����µ��ڴ���
	PVOID pTempBuffer = NULL;
	pTempBuffer = calloc(pOptionHeader->SizeOfImage, sizeof(char));
	if (pTempBuffer)
	{
		memcpy(pTempBuffer, imageBuffer, originalImageSize);
	}

	free(imageBuffer);
	imageBuffer = pTempBuffer;
	LoadPEHeader(imageBuffer);//���¼���peͷ
	imageBufferSize = pOptionHeader->SizeOfImage;
	return imageBufferSize - originalImageSize;
}

BOOL PeEdit::DumpFile(LPSTR lpszFile)
{
	FILE* fp_out;
	errno_t err = fopen_s(&fp_out, lpszFile, "wb");
	if (err == 0)
	{
		fwrite(fileBuffer, 1, fileBufferSize, fp_out);
		fclose(fp_out);
		return TRUE;
	}
	return 0;
}
