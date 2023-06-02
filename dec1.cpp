#include <iostream>

void decrypt(char* data)
{
	size_t len = strlen(data);
	unsigned char shift = 0xff;

	for (size_t i = 0; i < len; i++)
	{
		data[i] ^= shift;
		shift--;	// Note it'll just keep rolling around if len > 256
	}
}

int main()
{
	char success[] = "\xAC\x8B\x9E\x9F\x9E\x89\x8A\xD9\xFD\x00";	// unk_3C500

	char failure[] = "\xA6\x91\x88\xDC\x9F\x93\x9D\x96\xD0\x82\xD5\x91\x9D\x86\x94\x82\xCF\x9A\x85\x89"	//unk_3C50C
					 "\xCB\x89\x86\x9A\x95\x83\x86\x90\xC3\x89\x84\x99\xFF\xE4\xF5\xD6\x54\x2E\x01\x00";

	decrypt(success);
	decrypt(failure);

	puts("Success message:");
	printf("%s\n\n", success);

	puts("Failure message:");
	puts(failure);
}

