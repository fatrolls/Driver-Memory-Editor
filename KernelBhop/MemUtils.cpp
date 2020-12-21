#include "MemUtils.h"

string IntToStr(int n)
{
	ostringstream result;
	result << n;

	return result.str();
}

string IntToHex(int n)
{
	char buf[256];
	sprintf_s(buf, "%02X", n);

	stringstream sstream;
	sstream << std::hex << std::uppercase << buf;
	std::string result = sstream.str();

	return result;
}

unsigned int hextoint(string s)
{
	unsigned int x = strtoul(s.c_str(), NULL, 16);

	return x;
}

unsigned int str2int(char *s)
{
	int base = 10;

	if (s[0] == '0' && s[1] == 'x')
	{
		base = 16;
		s += 2;
	}

	return strtoul(s, NULL, base);
}

void ODS(const char *format, ...)
{
	const int MAX_BUF_SIZE = 4096;
	char buf[MAX_BUF_SIZE], *p = buf;
	va_list args;
	int n;

	va_start(args, format);
	n = _vsnprintf_s(p, MAX_BUF_SIZE, sizeof buf - 3, format, args);
	va_end(args);
	p += (n < 0) ? sizeof buf - 3 : n;
	while (p > buf && isspace(p[-1]))
		*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p = '\0';

	OutputDebugStringA(buf);
}