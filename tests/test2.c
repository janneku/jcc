void printf(char *fmt, ..);

void print(char *s)
{
	char *p = s;
	while (*p) {
		printf("%c", *p);
		p = p + 1;
	}
}

int main() {
	print("Hello, world\n");
}
