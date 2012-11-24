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
	TYPE_CHAR,
	TYPE_INT,
};

/* Storages */
enum {
	STOR_CONSTANT,
	STOR_REGISTER,
	STOR_GLOBAL,
	STOR_STACK,
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
const char *reg_byte_names[] = {"%al", "%bl", "%cl", "%dl", "%sil", "%dil"};

struct value {
	struct value *next;
	char *ident;
	int type;
	int return_type; /* Return type for functions */
	int storage;
	int locked; /* Is locked to the register? */
	unsigned long value; /* constant value */
	size_t loc; /* register number or stack position */
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
int return_stmt;

/* Returns the register where a value is stored */
const char *reg(const struct value *val)
{
	assert(val->storage == STOR_REGISTER);
	return reg_names[val->loc];
}

const char *bytereg(const struct value *val)
{
	assert(val->storage == STOR_REGISTER);
	return reg_byte_names[val->loc];
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
void push(struct value *val)
{
	if (val->storage == STOR_REGISTER) {
		assert(!val->locked);
		assert(registers[val->loc] == val);
		printf("\tpush %s\n", reg(val));
		registers[val->loc] = NULL;
		stack_size += 8;
		val->loc = stack_size;
		val->storage = STOR_STACK;
	}
}

/* Called when a value is no longer used */
void drop(struct value *val)
{
	if (val->storage == STOR_REGISTER) {
		assert(registers[val->loc] == val);
		registers[val->loc] = NULL;
	}
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
		if (!registers[i]->locked) {
			push(registers[i]);
			return i;
		}
	}
	error("unable to allocate a register\n");
}

/* Loads a value into the given register. -1 means any register */
void load(struct value *val, int loc)
{
	if (val->type == TYPE_VOID || val->type == TYPE_FUNCTION)
		error("non-numeric type for expression\n");

	if (loc < 0) {
		if (val->storage == STOR_REGISTER) {
			val->locked = 1;
			return;
		}
		loc = alloc_register();
	}
	if (val->storage == STOR_REGISTER && val->loc == (size_t) loc) {
		val->locked = 1;
		return;
	}
	if (registers[loc] != NULL) {
		/* Register is already occupied */
		push(registers[loc]);
	}

	switch (val->storage) {
	case STOR_CONSTANT:
		printf("\tmov $%zu, %s\n", val->value, reg_names[loc]);
		break;
	case STOR_REGISTER:
		assert(registers[val->loc] == val);
		registers[val->loc] = NULL;
		printf("\tmov %s, %s\n", reg(val), reg_names[loc]);
		break;
	case STOR_GLOBAL:
		printf("\tmov %s, %s\n", val->ident, reg_names[loc]);
		break;
	case STOR_STACK:
		printf("\tmov %zu(%%rsp), %s\n", stack_size - val->loc,
			reg_names[loc]);
		break;
	default:
		assert(0);
	}
	registers[loc] = val;
	val->storage = STOR_REGISTER;
	val->loc = loc;
	val->locked = 1;
}

/* Parses a C declaration, which are used for variables and types */
struct value *parse_declaration()
{
	int type;
	switch (token) {
	case TOK_VOID:
		type = TYPE_VOID;
		break;
	case TOK_CHAR:
		type = TYPE_CHAR;
		break;
	case TOK_INT:
		type = TYPE_INT;
		break;
	default:
		return NULL;
	}
	lex();
	struct value *val = calloc(1, sizeof(*val));
	assert(val != NULL);
	val->type = type;

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

	struct value *values = NULL;
	struct value *last_val = NULL;
	struct value *arg = fun->args;
	while (!check(')')) {
		if (arg == NULL && !fun->varargs)
			error("too many arguments for %s\n", fun->ident);
		struct value *val = expr();
		if (last_val == NULL)
			values = val;
		else
			last_val->next = val;
		last_val = val;
		if (token != ')') {
			expect(',');
		}
		if (arg != NULL)
			arg = arg->next;
	}

	/* Then, arrange the values for x86-64 call convention */
	int loc = RDI;
	for (arg = values; arg != NULL; arg = arg->next) {
		load(arg, loc);
		loc--;
	}
	/* Reserve all other registers, as callee might modify them */
	while (1) {
		if (registers[loc] != NULL)
			push(registers[loc]);
		if (loc == RAX)
			break;
		loc--;
	}

	/* The stack must be aligned to 16 after call */
	size_t align = (stack_size + 8) % 16;
	if (align > 0) {
		printf("\tsub $%zd, %%rsp\n", 16 - align);
		stack_size += 16 - align;
	}

	printf("\tcall %s\n", fun->ident);
	while (values != NULL) {
		arg = values;
		values = arg->next;
		drop(arg);
		free(arg);
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

	case '-':
		lex();
		result = term();
		load(result, -1);
		printf("\tneg %s\n", reg(result));
		result->locked = 0;
		break;

	case TOK_IDENTIFIER: {
			struct value *val = lookup(token_str);
			if (val == NULL)
				error("undefined: %s\n", token_str);
			lex();
			result = calloc(1, sizeof(*result));
			assert(result != NULL);
			*result = *val;
			result->next = NULL; /* just to be safe.. */
			if (check('(')) {
				function_call(val);
				result->type = val->return_type;
				if (result->type != TYPE_VOID) {
					result->loc = RAX;
					result->storage = STOR_REGISTER;
					registers[RAX] = result;
				}
			}
			break;
		}

	case TOK_NUMBER: {
			result = calloc(1, sizeof(*result));
			assert(result != NULL);
			result->type = TYPE_INT;
			result->value = token_value;
			result->storage = STOR_CONSTANT;
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
			result->loc = alloc_register();
			result->storage = STOR_REGISTER;
			registers[result->loc] = result;
			printf("\tmov $l%d, %s\n", s->label, reg(result));
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
		if (token == '+' || token == '-' || token == '*' ||
		    token == '<' || token == '>') {
			oper = token;
		} else
			break;
		lex();

		struct value *lhs = result;
		struct value *rhs = term();

		load(lhs, -1);
		load(rhs, -1);
		switch (oper) {
		case '+':
			printf("\tadd %s, %s\n", reg(rhs), reg(lhs));
			break;
		case '-':
			printf("\tsub %s, %s\n", reg(rhs), reg(lhs));
			break;
		case '*':
			printf("\timul %s, %s\n", reg(rhs), reg(lhs));
			break;
		case '<':
			printf("\tcmp %s, %s\n", reg(rhs), reg(lhs));
			printf("\tsetl %s\n", bytereg(result));
			printf("\tmovzx %s, %s\n", bytereg(result), reg(result));
			break;
		case '>':
			printf("\tcmp %s, %s\n", reg(rhs), reg(lhs));
			printf("\tsetg %s\n", bytereg(result));
			printf("\tmovzx %s, %s\n", bytereg(result), reg(result));
			break;
		default:
			assert(0);
		}
		result = lhs;
		result->locked = 0;
		drop(rhs);
		free(rhs);
	}
	return result;
}

/* Process an expression. Assigment always has the highest precedence. */
struct value *expr()
{
	struct value *result = binop_expr();
	if (token == '=') {
		lex();

		struct value *target = result;

		if (target->storage == STOR_REGISTER)
			error("invalid assignment target\n");

		struct value *val = expr();

		load(val, -1);
		switch (target->storage) {
		case STOR_GLOBAL:
			printf("\tmov %s, %s\n", reg(val), target->ident);
			break;
		case STOR_STACK:
			printf("\tmov %s, %zu(%%rsp)\n", reg(val),
				stack_size - target->loc);
			break;
		default:
			assert(0);
		}
		/* The value is passed through */
		drop(target);
		free(target);
		result = val;
		result->locked = 0;
	}
	return result;
}

void block();

void if_statement()
{
	expect('(');

	struct value *condition = expr();
	expect(')');

	/* Compare the condition against zero */
	int skip_label = next_label++;
	load(condition, -1);
	printf("\tor %s, %s\n", reg(condition), reg(condition));
	printf("\tjz l%d\n", skip_label);
	drop(condition);
	free(condition);

	block();

	printf("l%d:\n", skip_label);
}

void while_statement()
{
	expect('(');

	int test_label = next_label++;
	printf("l%d:\n", test_label);

	struct value *condition = expr();
	expect(')');

	/* Compare the condition against zero */
	int end_label = next_label++;
	load(condition, -1);
	printf("\tor %s, %s\n", reg(condition), reg(condition));
	printf("\tjz l%d\n", end_label);
	drop(condition);
	free(condition);

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
	free(initial);

	int test_label = next_label++;
	printf("l%d:\n", test_label);

	struct value *condition = expr();
	expect(';');

	/* Compare the condition against zero */
	int end_label = next_label++;
	load(condition, -1);
	printf("\tor %s, %s\n", reg(condition), reg(condition));
	printf("\tjz l%d\n", end_label);
	drop(condition);
	free(condition);

	/* Skip over the step which follows */
	int begin_label = next_label++;
	printf("\tjmp l%d\n", begin_label);

	int step_label = next_label++;
	printf("l%d:\n", step_label);

	struct value *step = expr();
	expect(')');
	drop(step);
	free(step);

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
	free(val);
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
				stack_size += 8;
				var->loc = stack_size;
				var->storage = STOR_STACK;
				var->next = symtab;
				symtab = var;
				printf("\tsub $8, %%rsp\n");

				if (check('=')) {
					/* Initialization */
					struct value *val = expr();
					load(val, -1);
					printf("\tmov %s, %zu(%%rsp)\n",
						reg(val),
						stack_size - var->loc);
					free(val);
					drop(val);
				}
			} else {
				/* It's an expression. Throw the result away */
				struct value *result = expr();
				if (result->type != TYPE_VOID) {
					drop(result);
					free(result);
				}
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

	/* Clean up allocated stack space */
	if (stack_size > old_stack) {
		printf("\tadd $%zu, %%rsp\n", stack_size - old_stack);
		stack_size = old_stack;
	}
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
	int loc = RDI;
	for (arg = fun->args; arg != NULL; arg = arg->next) {
		struct value *val = calloc(1, sizeof(*val));
		*val = *arg;
		val->loc = loc;
		val->storage = STOR_REGISTER;
		registers[loc] = val;
		val->next = values;
		values = val;
		val->next = symtab;
		symtab = val;
		loc--;
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
		free(arg);
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
		val->storage = STOR_GLOBAL;
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
