void printf(char *fmt, ..);

void rot13(char *s)
{
	char *p = s;
	while (*p) {
		int c = *p;
		if (c >= 'a') {
			if (c <= 'm') {
				c = c + 13;
			}
			else if (c <= 'z') {
				c = c - 13;
			}
		} else if (c >= 'A') {
			if (c <= 'M') {
				c = c + 13;
			}
			else if (c <= 'Z') {
				c = c - 13;
			}
		}
		printf("%c", c);
		p = p + 1;
	}
}

int main(int argc, char **argv) {
	char **args = argv;
	if (argc < 2) {
		printf("Usage: %s [text]\n", *argv);
		return 0;
	}
	rot13(*(args + 8));
	printf("\n");
}
