#include <windows.h>

int main()
{
	BYTE password[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
	DWORD directoryOffsetAddress = 0;//目录表相对于解密代码所在节的地址
	DWORD oep = 0; //原程序入口点

	//当前进程基址
	DWORD imageBase = 0;
	//标准Pe头
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	//可选Pe头
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	//目录表
	PIMAGE_DATA_DIRECTORY pDirectory = NULL;
	//节表
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//导入表
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	//密码表
	DWORD dict[] = { 0x12348412,0x1a851c21,0x45a28cb0,0x34af0210,
					0x98abcd51,0x102d4f8a,0x301cd120,0xaa1154bf,
					0xddbb2541,0xd125bfc2,0x1287adcf,0xe12ad512,
					0x1defa210,0x12d5f1e5,0x2a3d51bc,0xeea84079 };



	//string
	char szLoadLibraryA[] = { 'L','o','a' ,'d' ,'L' ,'i' ,'b' ,'r' ,'a' ,'r' ,'y', 'A' ,'\0' };
	char szVirtualProtect[] = { 'V','i','r' ,'t' ,'u' ,'a' ,'l' ,'P' ,'r' ,'o' ,'t','e','c','t','\0' };
	char szGetCommandLineA[] = { 'G','e','t' ,'C' ,'o' ,'m' ,'m' ,'a' ,'n' ,'d' ,'L','i','n','e', 'A', '\0' };

	//dll
	DWORD hKernel = 0;
	//DWORD hUser32 = 0;

	//func
	DWORD pGetProcAddress = 0;
	DWORD pLoadLibrary = 0;
	DWORD pVirtualProtect = 0;
	DWORD pGetCommandLineA = 0;

	//tmp
	DWORD hOldPageValue = 0;//修改前的页面属性
	DWORD result = 0;
	DWORD hDll = 0;
	DWORD pPassword = 0;


	//获取GetProcAddress和LoadLibrary的地址
	__asm
	{
		xor ecx, ecx
		mov eax, fs: [ecx + 0x30] ; //EAX = PEB
		mov eax, [eax + 0xc]; //ldr

		//获取EXE的基址
		mov ebx, [eax + 0xc]; //按加载顺序
		mov ebx, [ebx + 0x18];
		mov imageBase, ebx; //获取进程基址

		//获取Kernel32.dll的基址
		mov esi, [eax + 0x1c]; //按初始化顺序
		lodsd; //EAX = Second module
		xchg eax, esi; //EAX = ESI, ESI = EAX
		lodsd  //EAX = Third module
		mov ebx, [eax + 0x8]; //获取kernel32基址

		//获取kernel32导出表的位置
		mov edx, [ebx + 0x3c]; //EDX = DOS->e_lfanew
		add edx, ebx; //EDX = PE Header
		mov edx, [edx + 0x78]; //EDX = Offset export table
		add edx, ebx; //EDX = Export table
		mov esi, [edx + 0x20]; //ESI = Offset names table
		add esi, ebx; //ESI = Names table
		xor ecx, ecx; //EXC = 0

		//得到GetProcess的序号
	Get_Function:
		inc ecx; //Increment the ordinal
		lodsd; //Get name offset
		add eax, ebx; //Get function name
		cmp dword ptr[eax], 0x50746547; //GetP
		jnz Get_Function
			cmp dword ptr[eax + 0x4], 0x41636f72; //rocA
		jnz Get_Function
			cmp dword ptr[eax + 0x8], 0x65726464; //ddre
		jnz Get_Function

		//根据序号先查询序号表，再查地址表
		mov esi, [edx + 0x24]; //ESI = Offset ordinals
		add esi, ebx; //ESI = Ordinals table
		mov cx, [esi + ecx * 2]; //CX = Number of function
		dec ecx;
		mov esi, [edx + 0x1c]; //ESI = Offset address table
		add esi, ebx; //ESI = Address table
		mov edx, [esi + ecx * 4]; //EDX = Pointer(offset)
		add edx, ebx; //EDX = GetProcAddress

		mov hKernel, ebx;
		mov pGetProcAddress, edx;

		//获取Loadlibrary的地址
		lea eax, szLoadLibraryA;
		push eax; //"LoadLibrary"
		push hKernel; //Kernel32 base address
		call pGetProcAddress; //GetProcAddress(kernel32, “LoadLibraryA”)
		mov pLoadLibrary, eax;

		//获取szVirtualProtectEx函数地址
		lea eax, szVirtualProtect;
		push eax;
		push hKernel;
		call pGetProcAddress;
		mov pVirtualProtect, eax;

		//获取GetCommandLineA函数地址
		lea eax, szGetCommandLineA;
		push eax;
		push hKernel;
		call pGetProcAddress;
		mov pGetCommandLineA, eax;
	}

	//获取pe头信息
	__asm
	{
		mov ebx, imageBase;
		mov edx, [ebx + 0x3c]; //EDX = DOS->e_lfanew
		add edx, ebx; //EDX = PE Header
		add edx, 4; //标准pe头
		mov pPEHeader, edx;
		add edx, 20;
		mov pOptionHeader, edx; //可选pe头
		mov eax, pPEHeader;
		xor ecx, ecx;
		mov cx, [eax + 0x10];
		lea eax, [edx + ecx];
		mov pSectionHeader, eax; //节表
		mov eax, pOptionHeader;
		lea edx, [eax + 0x60]; //目录表
		mov pDirectory, edx;
	}

	//恢复数据目录表
	__asm
	{
		//设置镜像空间可读可写可执行
		lea edx, hOldPageValue;
		push edx;
		push PAGE_EXECUTE_READWRITE;
		//获取SizeOfImage大小
		mov esi, pOptionHeader;
		mov eax, [esi + 0x38]
			push eax; //设置页面大小

		push imageBase;
		call pVirtualProtect;
		mov result, eax;

		//拷贝
		mov eax, directoryOffsetAddress;
		lea esi, [eax + ebx];
		mov eax, pDirectory;
		mov edi, eax;
		mov ecx, 0x20;
		rep movsd;
		pushad;
	}

	//获取密码
	__asm
	{
		call pGetCommandLineA;
		mov pPassword, eax;
	}
	/*
	pPasswrod 形如：
	00DA4A48  22 45 3A 5C 63 5C 44 65 6D 6F 31 5C 52 65 6C 65  "E:\c\Demo1\Rele
	00DA4A58  61 73 65 5C 63 5F 70 6C 75 73 2E 65 78 65 22 20  ase\c_plus.exe"
	00DA4A68  31 32 33 34 35 36 37 00                          1234567.

	在cmd下为
	005B3098  64 65 6D 6F 33 2E 65 78 65 20 20 61 62 63 64 65  demo3.exe  abcde
	005B30A8  66 30 31 32 33 34 35 36 37 38 39 20 31 32 33 00  f0123456789 123.
	005B30B8  DB E4 3A C8 1F 20                                垆:? .

	用 22 20 或 20 20 去匹配
	*/
	
	//匹配 22 20
	char* tmp = (char*)pPassword;
	while ((*(PWORD)tmp) != 0) //最多比配到出现连续的两个0
	{
		//printf("%x\n", *(PWORD)tmp);
		if ((*(PWORD)tmp) == 0x2022 || (*(PWORD)tmp) == 0x2020)
		{
			break;
		}
		tmp++;
	}
	tmp += 2;
	//将命令行接收的到密码存入到password数组中
	for (int j = 0; j < 16; j++)
	{
		password[j] = tmp[j];
	}

	//清空命令行接收的密码
	for (int k = 0; k < 16; k++)
	{
		tmp[k] = 0x20;
	}



	//解密
	PDWORD buffer = (PDWORD)(imageBase + pOptionHeader->SizeOfHeaders);
	//除壳节以外节的大小 = 壳节的相对虚拟地址 - 头大小
	DWORD size = (pSectionHeader + pPEHeader->NumberOfSections - 1)->VirtualAddress - pOptionHeader->SizeOfHeaders;
	DWORD index = 0;
	for (int i = 0; i < size / 4; i++)
	{
		buffer[i] ^= dict[password[index % 16] % 16];
		index++;
	}

	//恢复IAT表
	__asm
	{
		popad;
		mov esi, pDirectory;
		mov esi, [esi + 0x8];
		add esi, ebx;
		mov pImportDescriptor, esi; //获取导入表地址
	DLL:
		mov edx, [esi + 0xc];//dllname
		add edx, ebx;
		push edx;
		call pLoadLibrary;//加载dll
		mov hDll, eax;
		mov edi, [esi + 0x10];
		add edi, ebx;
	IAT:
		//获取IAT内容
		test dword ptr ds : [edi] , 0x80000000; //最高位为1，则为序号导出
		jz byName;
		//序号导出
		and dword ptr ds : [edi] , 0x7FFFFFFF;
		push[edi];
		push hDll;
		call pGetProcAddress;
		mov[edi], eax;
		jmp _end;
	byName:
		//名字导出
		add[edi], ebx;
		mov eax, [edi];
		add eax, 2; //前两个字节没用
		push eax;
		push hDll;
		call pGetProcAddress;
		mov[edi], eax;
	_end:
		//判断IAT表是否遍历完
		add edi, 4;
		mov eax, [edi];
		test eax, eax;
		jnz IAT;
		//判断DLL是否遍历完
		add esi, 20;
		mov eax, [esi + 16];
		test eax, eax;
		jnz DLL;
	}

	//跳回到原程序入口
	__asm
	{
		mov eax, oep;
		add eax, ebx;
		jmp eax;
	}


	return 0;
}
