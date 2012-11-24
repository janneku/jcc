void printf(..);

int main() {
	int cols = 8;
	int rows = 20;
	int i;

	for (i = 0; i < cols; i = i + 1) {
		printf("%d\t", i);
	}
	printf("\n");
	for (i = 0; i < rows; i = i + 1) {
		int j;
		printf("%d\t", i);
		for (j = 0; j < cols; j = j + 1) {
			printf("%d\t", i*j);
		}
		printf("\n");
	}
}
