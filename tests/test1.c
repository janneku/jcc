void printf(..);

int main() {
	int cols = 8;
	int rows = 20;

	int i = 1;
	while (i < cols) {
		printf("%d\t", i);
		i = i + 1;
	}
	printf("\n");
	i = 1;
	while (i < rows) {
		int j = 1;
		while (j < cols) {
			printf("%d\t", i*j);
			j = j + 1;
		}
		printf("\n");
		i = i + 1;
	}
}
