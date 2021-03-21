#include "PeEdit.h"

PeEdit::PeEdit(IN LPSTR lpszFile):PeView(lpszFile)
{
	//按内存展开
	CopyFileBufferToImageBuffer();
	//按内存中的镜像重新加载pe头
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
	free(imageBuffer);//释放原内存镜像
	imageBuffer = pTempBuffer;
	imageBufferSize = pOptionHeader->SizeOfImage;
	return imageBufferSize;
}

DWORD PeEdit::CopyImageBufferToFileBuffer()
{
	LPVOID pTempBuffer = NULL;

	//计算输出后的文件大小（最后一个节的文件偏移+最后一个节的文件对齐后的大小）
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
	free(fileBuffer); //释放原文件镜像
	fileBuffer = pTempBuffer;
	return fileBufferSize; 
}

DWORD PeEdit::AddSection(DWORD size)
{
	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;
	DWORD originalImageSize = pOptionHeader->SizeOfImage;

	//构造新增节的数据
	PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)malloc(IMAGE_SIZEOF_SECTION_HEADER); //节表大小为40
	if (!pNewSectionHeader)
	{
		return 0;
	}
	//节的名字
	pNewSectionHeader->Name[0] = '.';
	pNewSectionHeader->Name[1] = 'n';
	pNewSectionHeader->Name[2] = 'e';
	pNewSectionHeader->Name[3] = 'w';
	pNewSectionHeader->Name[4] = '\0';
	//节在未对齐时的真实大小
	pNewSectionHeader->Misc.VirtualSize = size;

	//节在内存中的偏移（上一个节的内存偏移 + 上一个节的在内存对齐后的大小）
	pNewSectionHeader->VirtualAddress = pSectionHeaderTemp[pPEHeader->NumberOfSections - 1].VirtualAddress +
		AlignCalc(pSectionHeaderTemp[pPEHeader->NumberOfSections - 1].Misc.VirtualSize, pOptionHeader->SectionAlignment);

	//节在文件对齐后的大小
	pNewSectionHeader->SizeOfRawData = AlignCalc(size, pOptionHeader->FileAlignment);

	//节在文件中的偏移（上一个节的文件偏移 + 上一个节的在文件对齐后的大小）
	pNewSectionHeader->PointerToRawData = pSectionHeaderTemp[pPEHeader->NumberOfSections - 1].PointerToRawData +
		AlignCalc(pSectionHeaderTemp[pPEHeader->NumberOfSections - 1].SizeOfRawData, pOptionHeader->FileAlignment);

	//调试相关，随意填写
	pNewSectionHeader->PointerToRelocations = 0;
	pNewSectionHeader->PointerToLinenumbers = 0;
	pNewSectionHeader->NumberOfRelocations = 0;
	pNewSectionHeader->NumberOfLinenumbers = 0;

	//节的属性
	pNewSectionHeader->Characteristics = 0xC0000020; //节中包含代码，可读可执行


	//判断节表后面是否有足够空间增加节（节表末尾80byte为0 且 SizeOfHeaders - 头对齐前的大小 > 80）
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
	if (flag != 0) //空间不足
	{
		//printf("节表末尾的空间不足，正在尝试把PE头和节表上移......\n");
		DWORD moveSize = AlignCalc(80 - zeroLength, 8);//上移的幅度（此处必须对齐）
		if ((char*)pNTHeader - 64 - moveSize > 0) //存在上移空间
		{
			memmove((char*)pNTHeader - moveSize, (char*)pNTHeader,
				4 + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader + pPEHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER);
			//修改NT头位置
			pDosHeader->e_lfanew -= moveSize;
			//重新加载头结构
			LoadPEHeader(imageBuffer);
			pSectionHeaderTemp = pSectionHeader;
			//清空节表空间
			memset(pSectionHeaderTemp + pPEHeader->NumberOfSections, 0, moveSize);
			//printf("上移成功，可以新增节表\n");
		}
		else//空间还是不足
		{
			return 0;
		}

	}
	//修改标准PE头中的节的数量加1
	pPEHeader->NumberOfSections++;

	//修改SizeOfImage
	pOptionHeader->SizeOfImage += AlignCalc(size, pOptionHeader->SectionAlignment);

	//将新节表拷贝到原镜像（此时节的个数已加1，所以所在位置要减1）
	memcpy(pSectionHeaderTemp + pPEHeader->NumberOfSections - 1, pNewSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	//将原镜像拷贝到新的内存中
	PVOID pTempBuffer = NULL;
	pTempBuffer = calloc(pOptionHeader->SizeOfImage, sizeof(char));
	if (pTempBuffer)
	{
		memcpy(pTempBuffer, imageBuffer, originalImageSize);
	}

	free(imageBuffer);
	imageBuffer = pTempBuffer;
	LoadPEHeader(imageBuffer);//重新加载pe头
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
