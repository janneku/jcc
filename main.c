#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#define error(fmt...) \
	do { \
		fprintf(stderr, fmt); \
		abort(); \
	} while(0)

/* Tokens returned by lex() */
enum {
	/* 0..255 are single character tokens */
	TOK_WHILE = 1000,
	TOK_IF,
	TOK_FOR,
	TOK_RETURN,
	TOK_CHAR,
	TOK_INT,
	TOK_SHORT,
	TOK_LONG,
	TOK_STRUCT,
	TOK_TYPEDEF,
	TOK_VOID,
	TOK_IDENTIFIER,
	TOK_NUMBER,
	TOK_STRING,
	TOK_ELLIPSIS,
};

/* Types */
enum {
	TYPE_VOID,
	TYPE_FUNCTION,
	TYPE_POINTER,
	TYPE_INT,
};

/*
 * must match reg_names[]. The first ones are preferred over the latter.
 * Note, these are the same as in x86-64 call convention, but reversed.
 */
enum {
	RAX,
	RBX,
	RCX,
	RDX,
	RSI,
	RDI,
	MAX_REG,
};

const char *reg_names[] = {"%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi"};
const char *reg_dword_names[] = {"%eax", "%ebx", "%ecx", "%edx", "%esi", "%edi"};
const char *reg_word_names[] = {"%ax", "%bx", "%cx", "%dx", "%si", "%di"};
const char *reg_byte_names[] = {"%al", "%bl", "%cl", "%dl", "%sil", "%dil"};

struct value {
	struct value *next;
	char *ident; /* identifier (also global name) */
	int type;
	int constant;
	int size; /* Size of the integer */
	int return_type; /* Return type for functions or pointers */
	unsigned long value; /* constant value */
	size_t stack_pos;
	int varargs; /* Function uses variable arguments */
	struct value *args; /* function != 0 */
};

struct string {
	struct string *next;
	int label;
	char *buf;
};

int next_label = 100; /* Used to allocate labels */
FILE *source;
struct value *symtab = NULL;
struct string *stringtab = NULL;
int token, look;
size_t stack_size;
unsigned long token_value;
char *token_str = NULL;
struct value *registers[MAX_REG] = {};
int reg_locked[MAX_REG] = {};

size_t size_of(const struct value *val)
{
	switch (val->type) {
	case TYPE_VOID:
		error("can not take size of void\n");
		break;
	case TYPE_FUNCTION:
		error("can not take size of a function\n");
		break;
	case TYPE_INT:
		return val->size;
	case TYPE_POINTER:
		return 8;
	default:
		assert(0);
	}
}

/* Search for the register where the value is stored */
int search_reg(const struct value *val)
{
	int i;
	for (i = 0; i < MAX_REG; ++i) {
		if (registers[i] == val)
			return i;
	}
	return -1;
}

/* Called when a value is no longer needed. */
void drop(const struct value *val)
{
	if (val->stack_pos > 0 || val->ident != NULL)
		return;
	int i;
	for (i = 0; i < MAX_REG; ++i) {
		if (registers[i] == val)
			registers[i] = NULL;
	}
}

int copies(const struct value *val)
{
	int count = 0;
	if (val->constant)
		count++;
	if (val->stack_pos > 0)
		count++;
	else if (val->ident != NULL)
		count++;
	int i;
	for (i = 0; i < MAX_REG; ++i) {
		if (registers[i] == val)
			count++;
	}
	return count;
}

/* Parse an alphanumeric string (e.g. identifiers and reserved words) */
char *parse_alnum()
{
	char *buf = NULL;
	size_t len = 0;
	size_t buflen = 8;
	while (isalnum(look) || look == '_') {
		if (buf == NULL || len + 1 >= buflen) {
			buflen *= 2;
			buf = realloc(buf, buflen);
			assert(buf != NULL);
		}
		buf[len++] = look;
		look = fgetc(source);
	}
	buf[len] = 0;
	return buf;
}

/* Parses a string */
char *parse_string()
{
	char *buf = NULL;
	size_t len = 0;
	size_t buflen = 8;
	while (look != '"') {
		if (buf == NULL || len + 1 >= buflen) {
			buflen *= 2;
			buf = realloc(buf, buflen);
			assert(buf != NULL);
		}
		buf[len++] = look;
		look = fgetc(source);
	}
	look = fgetc(source);
	buf[len] = 0;
	return buf;
}

/* Takes next token from the source file */
void lex()
{
	free(token_str);
	token_str = NULL;

	while (isspace(look)) {
		look = fgetc(source);
	}

	if (isalpha(look) || look == '_') {
		char *buf = parse_alnum();
		if (strcmp(buf, "while") == 0)
			token = TOK_WHILE;
		else if (strcmp(buf, "if") == 0)
			token = TOK_IF;
		else if (strcmp(buf, "for") == 0)
			token = TOK_FOR;
		else if (strcmp(buf, "return") == 0)
			token = TOK_RETURN;
		else if (strcmp(buf, "char") == 0)
			token = TOK_CHAR;
		else if (strcmp(buf, "int") == 0)
			token = TOK_INT;
		else if (strcmp(buf, "short") == 0)
			token = TOK_SHORT;
		else if (strcmp(buf, "long") == 0)
			token = TOK_LONG;
		else if (strcmp(buf, "struct") == 0)
			token = TOK_STRUCT;
		else if (strcmp(buf, "typedef") == 0)
			token = TOK_TYPEDEF;
		else if (strcmp(buf, "void") == 0)
			token = TOK_VOID;
		else {
			token_str = buf;
			buf = NULL;
			token = TOK_IDENTIFIER;
		}
		free(buf);

	} else if (isdigit(look)) {
		token_value = 0;
		while (isdigit(look)) {
			token_value *= 10;
			token_value += look - '0';
			look = fgetc(source);
		}
		token = TOK_NUMBER;

	} else if (look == '"') {
		look = fgetc(source);
		token_str = parse_string();
		token = TOK_STRING;

	} else if (look == '.') {
		look = fgetc(source);
		if (look == '.') {
			token = TOK_ELLIPSIS;
			look = fgetc(source);
		} else {
			token = '.';
		}

	} else {
		token = look;
		look = fgetc(source);
	}
}

/* Checks if the current token matches and skips it */
int check(int c)
{
	if (token == c) {
		lex();
		return 1;
	}
	return 0;
}

/* Verifies that the current token matches and skip over it */
void expect(int c)
{
	if (!check(c)) {
		error("expected '%c', got '%c'\n", c, token);
	}
}

/* Looks up a symbol by the identifier. */
struct value *lookup(const char *ident)
{
	struct value *s;
	for (s = symtab; s != NULL; s = s->next) {
		if (strcmp(s->ident, ident) == 0)
			return s;
	}
	return NULL;
}

/* Moves a value from a register to stack. Used to solve register pressue. */
void push(int reg)
{
	struct value *val = registers[reg];
	if (copies(val) == 1) {
		stack_size += 8;
		val->stack_pos = stack_size;
		printf("\tpush %s\n", reg_names[reg]);
	}
	registers[reg] = NULL;
}

/* Allocates an unused register. */
size_t alloc_register()
{
	int i;
	for (i = 0; i < MAX_REG; ++i) {
		if (registers[i] == NULL)
			return i;
	}
	/* Try to spill to stack */
	for (i = MAX_REG - 1; i >= 0; --i) {
		if (!reg_locked[i]) {
			push(i);
			return i;
		}
	}
	error("unable to allocate a register\n");
	return -1;
}

const char *asm_reg(const struct value *val, int reg)
{
	switch (val->type) {
	case TYPE_POINTER:
		return reg_names[reg];
	case TYPE_INT:
		switch (val->size) {
		case 1:
			return reg_byte_names[reg];
		case 2:
			return reg_word_names[reg];
		case 4:
			return reg_dword_names[reg];
		case 8:
			return reg_names[reg];
		default:
			assert(0);
		}
	default:
		error("non-numeric type for expression\n");
	}
	return NULL;
}

/* Returns operand for printing. */
const char *asm_operand(const struct value *val)
{
	static char buf[64];

	if (val->type == TYPE_VOID || val->type == TYPE_FUNCTION)
		error("non-numeric type for expression\n");

	/* First, see if we have it in a register */
	int reg = search_reg(val);
	if (reg >= 0)
		return asm_reg(val, reg);

	/* Second, try use a constant value */
	if (val->constant) {
		sprintf(buf, "$%lu", val->value);
		return buf;
	}

	/* Finally, load from memory */
	if (val->stack_pos > 0) {
		sprintf(buf, "%zu(%%rsp)", stack_size - val->stack_pos);
		return buf;
	}

	/* If it does not have stack position, it's a global */
	assert(val->ident != NULL);
	return val->ident;
}

/* Loads a value into the given register. -1 means any register */
int load(struct value *val, int reg)
{
	if (val->type == TYPE_VOID || val->type == TYPE_FUNCTION)
		error("non-numeric type for expression\n");

	if (reg < 0) {
		reg = search_reg(val);
		if (reg >= 0) {
			reg_locked[reg] = 1;
			return reg;
		}
		reg = alloc_register();
	}
	if (registers[reg] == val) {
		reg_locked[reg] = 1;
		return reg;
	}

	if (registers[reg] != NULL) {
		/* Register is already occupied */
		push(reg);
	}

	printf("\tmov %s, %s\n", asm_operand(val), asm_reg(val, reg));
	registers[reg] = val;
	reg_locked[reg] = 1;
	return reg;
}

/* Parses a C declaration, which are used for variables and types */
struct value *parse_declaration()
{
	struct value *val = calloc(1, sizeof(*val));
	assert(val != NULL);
	val->type = -1;

	/* Read all available specifications that can be in random order */
	int done = 0;
	while (!done) {
		switch (token) {
		case TOK_VOID:
			if (val->type >= 0)
				error("already have a basic type\n");
			val->type = TYPE_VOID;
			break;
		case TOK_CHAR:
			if (val->type >= 0)
				error("already have a basic type\n");
			val->type = TYPE_INT;
			val->size = 1;
			break;
		case TOK_INT:
			if (val->size > 0)
				error("type already has a size\n");
			val->type = TYPE_INT;
			break;
		case TOK_SHORT:
			if (val->size > 0)
				error("type already has a size\n");
			val->size = 2;
			break;
		case TOK_LONG:
			if (val->size > 0)
				error("type already has a size\n");
			val->size = 8;
			break;
		default:
			if (val->type < 0 && val->size == 0) {
				/* Found nothing */
				free(val);
				return NULL;
			}
			done = 1;
			break;
		}
		if (!done)
			lex();
	}
	if (val->type < 0)
		val->type = TYPE_INT;
	if (val->size == 0)
		val->size = 4;

	if (check('*')) {
		/* A pointer */
		val->return_type = val->type;
		val->type = TYPE_POINTER;
	}

	if (token == TOK_IDENTIFIER) {
		val->ident = token_str;
		token_str = NULL;
		lex();
	}

	if (check('(')) {
		/* It's a function. Parse function parameters */
		val->return_type = val->type;
		val->type = TYPE_FUNCTION;

		struct value *last_arg = NULL;
		while (!check(')')) {
			if (token == TOK_ELLIPSIS) {
				lex();
				val->varargs = 1;
				expect(')');
				break;
			}
			struct value *arg = parse_declaration();
			if (last_arg == NULL)
				val->args = arg;
			else
				last_arg->next = arg;
			last_arg = arg;
			if (token != ')') {
				expect(',');
			}
		}
	}
	return val;
}

struct value *expr();

/* Handles a function call inside an expression */
void function_call(struct value *fun)
{
	if (fun->type != TYPE_FUNCTION)
		error("calling a non-function: %s\n", fun->ident);

	struct value *values[MAX_REG] = {};
	struct value *arg = fun->args;
	int i = 0;
	while (!check(')')) {
		struct value *val = expr();
		if (arg == NULL) {
			if (!fun->varargs) {
				error("too many arguments for %s\n",
					fun->ident);
			}
		} else if (val->type != arg->type) {
			error("type mismatch for argument\n");
		}
		values[i++] = val;
		if (token != ')') {
			expect(',');
		}
		if (arg != NULL)
			arg = arg->next;
	}

	/* Then, arrange the values for x86-64 call convention */
	for (i = 0; i < MAX_REG; ++i) {
		if (values[i] != NULL) {
			load(values[i], RDI - i);
		} else if (registers[RDI - i] != NULL) {
			/* Reserve all other registers */
			push(RDI - i);
		}
	}

	/* The stack must be aligned to 16 after call */
	size_t align = (stack_size + 8) % 16;
	if (align > 0) {
		printf("\tsub $%zd, %%rsp\n", 16 - align);
		stack_size += 16 - align;
	}

	printf("\tcall %s\n", fun->ident);
	for (i = 0; i < MAX_REG; ++i) {
		if (values[i] != NULL)
			drop(values[i]);
	}
}

/* Parses a term, which is a part of an expression */
struct value *term()
{
	struct value *result = NULL;
	switch (token) {
	case '(': {
			lex();
			struct value *cast = parse_declaration();
			if (cast != NULL)
				error("TODO: typecasting\n");
			result = expr();
			expect(')');
		}
		break;

	case '-': {
			lex();
			struct value *val = term();
			int reg = load(val, -1);
			printf("\tneg %s\n", asm_reg(val, reg));
			reg_locked[reg] = 0;
			drop(val);

			result = calloc(1, sizeof(*result));
			assert(result != NULL);
			result->type = val->type;
			result->size = val->size;
			registers[reg] = result;
			break;
		}

	case TOK_IDENTIFIER:
		result = lookup(token_str);
		if (result == NULL)
			error("undefined: %s\n", token_str);
		lex();
		if (check('(')) {
			struct value *fun = result;
			function_call(fun);
			result = calloc(1, sizeof(*result));
			assert(result != NULL);
			result->type = fun->return_type;
			if (result->type != TYPE_VOID) {
				registers[RAX] = result;
			}
		}
		break;

	case TOK_NUMBER: {
			result = calloc(1, sizeof(*result));
			assert(result != NULL);
			result->type = TYPE_INT;
			result->size = 4;
			result->value = token_value;
			result->constant = 1;
			lex();
			break;
		}

	case TOK_STRING: {
			/* Insert to string table */
			struct string *s = calloc(1, sizeof(*s));
			assert(s != NULL);
			s->label = next_label++;
			s->buf = token_str;
			token_str = NULL;
			s->next = stringtab;
			stringtab = s;
			lex();

			/* Get address to the string */
			result = calloc(1, sizeof(*result));
			assert(result != NULL);
			result->type = TYPE_POINTER;
			result->return_type = TYPE_INT;
			result->size = 1;
			int reg = alloc_register();
			printf("\tmov $l%d, %s\n", s->label,
				asm_reg(result, reg));
			registers[reg] = result;
			break;
		}

	default:
		error("syntax error in expression, got '%c'\n", token);
	}
	return result;
}

/* Handles arithmetic binary operations */
struct value *binop_expr()
{
	struct value *result = term();
	while (1) {
		int oper;
		if (token == '+' || token == '-' || token == '*') {
			oper = token;
		} else
			break;
		lex();

		struct value *lhs = result;
		struct value *rhs = term();

		int reg = load(lhs, -1);
		switch (oper) {
		case '+':
			printf("\tadd %s, %s\n", asm_operand(rhs),
				asm_reg(lhs, reg));
			break;
		case '-':
			printf("\tsub %s, %s\n", asm_operand(rhs),
				asm_reg(lhs, reg));
			break;
		case '*':
			printf("\timul %s, %s\n", asm_operand(rhs),
				asm_reg(lhs, reg));
			break;
		default:
			assert(0);
		}
		reg_locked[reg] = 0;
		drop(lhs);
		drop(rhs);
		result = calloc(1, sizeof(*result));
		assert(result != NULL);
		result->type = lhs->type;
		result->size = lhs->size;
		registers[reg] = result;
	}
	return result;
}

/* Handles relational binary operations */
struct value *relational_expr()
{
	struct value *result = binop_expr();
	while (1) {
		int oper;
		if (token == '<' || token == '>') {
			oper = token;
		} else
			break;
		lex();

		struct value *lhs = result;
		struct value *rhs = binop_expr();

		int reg = load(lhs, -1);
		printf("\tcmp %s, %s\n", asm_operand(rhs), asm_reg(lhs, reg));

		switch (oper) {
		case '<':
			printf("\tsetl %s\n", reg_byte_names[reg]);
			break;
		case '>':
			printf("\tsetg %s\n", reg_byte_names[reg]);
			break;
		default:
			assert(0);
		}

		reg_locked[reg] = 0;
		drop(lhs);
		drop(rhs);
		result = calloc(1, sizeof(*result));
		assert(result != NULL);
		result->type = TYPE_INT;
		result->size = 4;
		printf("\tmovzx %s, %s\n", reg_byte_names[reg],
			asm_reg(result, reg));
		registers[reg] = result;
	}
	return result;
}

/* Process an expression. Assigment always has the highest precedence. */
struct value *expr()
{
	struct value *result = relational_expr();
	if (token == '=') {
		lex();

		struct value *target = result;

		struct value *val = expr();

		int reg = load(val, -1);
		printf("\tmov %s, %s\n", asm_reg(val, reg),
			asm_operand(target));
		reg_locked[reg] = 0;

		/* The value is passed through */
		result = val;
	}
	return result;
}

void end_block(size_t old_stack)
{
	/* Clean up allocated stack space */
	if (stack_size > old_stack) {
		printf("\tadd $%zu, %%rsp\n", stack_size - old_stack);
		stack_size = old_stack;
	}

	/* remove unreachable stack positions */
	struct value *val = symtab;
	while (val != NULL) {
		if (val->stack_pos > stack_size)
			val->stack_pos = 0;
		val = val->next;
	}

	/* Reset registers */
	memset(registers, 0, sizeof registers);
}

void block();

void if_statement()
{
	expect('(');

	/* The condition block must leave the state exactly the same */
	size_t old_stack = stack_size;
	struct value *condition = expr();
	expect(')');

	int reg = load(condition, -1);
	drop(condition);
	end_block(old_stack);

	/* Compare the condition against zero (still in register) */
	int skip_label = next_label++;
	printf("\tor %s, %s\n", asm_reg(condition, reg),
		asm_reg(condition, reg));
	printf("\tjz l%d\n", skip_label);

	block();

	printf("l%d:\n", skip_label);
}

void while_statement()
{
	expect('(');

	int test_label = next_label++;
	printf("l%d:\n", test_label);

	/* The condition block must leave the state exactly the same */
	size_t old_stack = stack_size;
	struct value *condition = expr();
	expect(')');

	int reg = load(condition, -1);
	drop(condition);
	end_block(old_stack);

	/* Compare the condition against zero */
	int end_label = next_label++;
	printf("\tor %s, %s\n", asm_reg(condition, reg),
		asm_reg(condition, reg));
	printf("\tjz l%d\n", end_label);

	block();

	/* Jump back to test the condition again */
	printf("\tjmp l%d\n", test_label);
	printf("l%d:\n", end_label);
}

void for_statement()
{
	expect('(');

	struct value *initial = expr();
	expect(';');
	drop(initial);

	int test_label = next_label++;
	printf("l%d:\n", test_label);

	/* The condition block must leave the state exactly the same */
	size_t old_stack = stack_size;
	struct value *condition = expr();
	expect(';');

	/* Compare the condition against zero */
	int reg = load(condition, -1);
	drop(condition);
	end_block(old_stack);

	int end_label = next_label++;
	int begin_label = next_label++;
	printf("\tor %s, %s\n", asm_reg(condition, reg),
		asm_reg(condition, reg));
	printf("\tjz l%d\n", end_label);
	printf("\tjmp l%d\n", begin_label);

	int step_label = next_label++;
	printf("l%d:\n", step_label);

	old_stack = stack_size;
	struct value *step = expr();
	expect(')');
	drop(step);
	end_block(old_stack);

	/* Jump back to test the condition */
	printf("\tjmp l%d\n", test_label);

	printf("l%d:\n", begin_label);

	block();

	/* Jump back to step after which test the condition */
	printf("\tjmp l%d\n", step_label);
	printf("l%d:\n", end_label);
}

void return_statement()
{
	struct value *val = expr();
	expect(';');

	load(val, RAX);

	/* Clear up the stack and return to caller */
	if (stack_size > 8)
		printf("\tadd $%zu, %%rsp\n", stack_size - 8);
	printf("\tpop %%rbx\n");
	printf("\tret\n");
	drop(val);
}

void statement()
{
	switch (token) {
	case TOK_IF:
		lex();
		if_statement();
		break;
	case TOK_WHILE:
		lex();
		while_statement();
		break;
	case TOK_FOR:
		lex();
		for_statement();
		break;
	case TOK_RETURN:
		lex();
		return_statement();
		break;
	default: {
			struct value *var = parse_declaration();
			if (var != NULL) {
				/* It's a variable declaration */
				stack_size += size_of(var);
				var->stack_pos = stack_size;
				var->next = symtab;
				symtab = var;
				printf("\tsub $%zu, %%rsp\n", size_of(var));

				if (check('=')) {
					/* Initialization */
					struct value *init = expr();
					int reg = load(init, -1);
					printf("\tmov %s, %zu(%%rsp)\n",
						asm_reg(init, reg),
						stack_size - var->stack_pos);
					drop(init);
				}
			} else {
				/* It's an expression. Throw the result away */
				struct value *result = expr();
				drop(result);
			}
			expect(';');
			break;
		}
	}
}

void close_scope(struct value *position)
{
	while (symtab != position) {
		struct value *val = symtab;
		symtab = val->next;
		free(val->ident);
		free(val);
	}
}

void block()
{
	/* Remember current symbol table so we can revert it */
	struct value *old_sym = symtab;
	size_t old_stack = stack_size;

	if (check('{')) {
		while (!check('}')) {
			statement();
		}
	} else
		statement();

	close_scope(old_sym);
	end_block(old_stack);
}

/* Process a function body */
void function_body(struct value *fun)
{
	if (fun->type != TYPE_FUNCTION)
		error("not a function: %s\n", fun->ident);

	/* Remember current symbol table so we can revert it */
	struct value *old_sym = symtab;

	/* Create values for arguments */
	struct value *values = NULL;
	struct value *arg;
	int reg = RDI;
	for (arg = fun->args; arg != NULL; arg = arg->next) {
		struct value *val = calloc(1, sizeof(*val));
		*val = *arg;
		registers[reg] = val;
		val->next = values;
		values = val;
		val->next = symtab;
		symtab = val;
		reg--;
	}

	printf("\t.global %s\n", fun->ident);
	printf("%s:\n", fun->ident);
	printf("\tpush %%rbx\n");

	stack_size = 8; /* because EBX is stored in stack */
	block();

	/* Clean up arguments */
	while (values != NULL) {
		arg = values;
		values = arg->next;
		drop(arg);
	}

	printf("\tpop %%rbx\n");
	printf("\tret\n");

	close_scope(old_sym);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: %s [SOURCE]\n", argv[0]);
		return 0;
	}
	source = fopen(argv[1], "rb");
	if (source == NULL) {
		error("unable to open %s\n", argv[1]);
	}

	look = fgetc(source);
	lex();

	printf("\t.text\n");
	while (token != EOF) {
		struct value *val = parse_declaration();
		if (val == NULL)
			error("expected a declaration\n");
		if (lookup(val->ident) != NULL)
			error("already defined: %s\n", val->ident);
		val->next = symtab;
		symtab = val;
		if (token == '{') {
			function_body(val);
		} else {
			expect(';');
		}
	}

	/* Write string table */
	printf("\t.data\n");
	while (stringtab != NULL) {
		struct string *s = stringtab;
		stringtab = s->next;
		printf("l%d: .string \"%s\"\n", s->label, s->buf);
		free(s->buf);
		free(s);
	}

	close_scope(NULL);

	fclose(source);
	return 0;
}
