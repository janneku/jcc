void *malloc(long size);
void printf(char *fmt, ..);

struct entry {
	struct entry *next;
	char *name;
};

struct entry *list;

void add(char *name)
{
	char *n = name;
	struct entry *e = malloc(sizeof struct entry);
	e->name = n;
	e->next = list;
	list = e;
}

int main()
{
	struct entry *e;
	add("Alice");
	add("Bob");

	printf("names:\n");
	for (e = list; e; e = e->next) {
		printf("%s\n", e->name);
	}
}
