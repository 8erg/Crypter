#include <Windows.h>
#include <stdio.h>


unsigned char shellcode[] = "";//You can put your shellcode here

//You can change the key used to encrypt your payload
unsigned char key[] = {
	0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x02,0x01
};

VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) 
{
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j > sKeySize)
		{
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
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
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");
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
	logo();

	printf("[i] shellcode : 0x%p \n", shellcode);
	XorByInputKey(shellcode, sizeof(shellcode), key, sizeof(key));
	PrintHexData("Encrypted_Shellcode", shellcode, sizeof(shellcode));

	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}