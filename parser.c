#include "parser.h"
#include "scanner.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

#define IMPLEMENT_VECTOR
#include "vector.h"

int error_occur(const char *fmt, ...)
{
    int written = 0;
    va_list args;
    va_start(args, fmt);
    written = fprintf(stderr, "Error: ");
    written += vfprintf(stderr, fmt, args);
    va_end(args);
    return written;
}

Ast *new_ast(TokenType type, NodeType node_type)
{
    Ast *node = calloc(1, sizeof(*node));
    node->type = type;
    node->node_type = node_type;
    node->children = Vector(Ast *);
    return node;
}

void free_ast(Ast *root)
{
    if (root == NULL)
        return;
    for (int i = 0; i < vector_length(root->children); i++)
    {
        free_ast(root->children[i]);
    }
    free_vector(root->children);
    free(root);
}

Ast *bin_op(TokenType type, Ast *left, Ast *right)
{
    Ast *node = new_ast(type, BINARY_OP);
    vector_append(node->children, left);
    vector_append(node->children, right);
    return node;
}

Ast *unary_op(TokenType type, Ast *ast)
{
    Ast *node = new_ast(type, UNARY_OP);
    vector_append(node->children, ast);
    return node;
}

Ast *num_int(int num)
{
    Ast *node = new_ast(INT_CONSTANT, NUM);
    node->value.int_value = num;
    // printf("num_int %d\n",num);
    return node;
}

Ast *num_float(float num)
{
    Ast *node = new_ast(FLOAT_CONSTANT, NUM);
    node->value.float_value = num;
    return node;
}

char *read_entire_file(const char *path, long *len)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        *len = -1;
        return NULL;
    }
    fseek(f, 0L, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0L, SEEK_SET); // equivallent to rewind(f);

    *len = file_size;

    char *content = calloc(file_size, sizeof(*content));
    fread(content, 1, file_size, f);
    fclose(f);
    return content;
}

Parser *init_parser(const char *file_path)
{
    Parser *parser = calloc(1, sizeof(*parser));
    ScannerState *ss = calloc(1, sizeof(*ss));
    long source_len;
    char *source = read_entire_file(file_path, &source_len);

    ss->source = source;
    ss->source_len = source_len;
    parser->ss = ss;
    parser->current_token = next_token(parser->ss);
    // print_token(parser->current_token);
    return parser;
}

void eat(Parser *parser, TokenType token_type)
{
    Token current_token = parser->current_token;
    free(parser->current_token.lexeme);
    if (current_token.type == token_type)
    {
        parser->current_token = next_token(parser->ss);
        // print_token(parser->current_token);
        return;
    }
    invalid_token("Error: %s", "Invalid syntaxt\n");
    printf("Expected %s got %s\n", token_to_str(token_type),
           token_to_str(current_token.type));
    exit(-1);
}

Ast *value(Parser *parser)
{
    //  value : INT_CONSTANT | HEX_CONSTANT|Octal Constant | LEFT_PARAN expr
    //  RIGHT_PARAN | (PLUS|MINUS)value
    Token token = parser->current_token;
    Ast *node = NULL;
    switch (token.type)
    {
    case INT_CONSTANT:
        node = num_int(strtol(token.lexeme, NULL, 10));
        eat(parser, INT_CONSTANT);
        return node;
    case HEX_CONSTANT:
        node = num_int(strtol(token.lexeme, NULL, 16));
        eat(parser, HEX_CONSTANT);
        return node;
    case OCTAL_CONSTANT:
        eat(parser, OCTAL_CONSTANT);
        return num_int(strtol(token.lexeme, NULL, 8));
    case FLOAT_CONSTANT:
        eat(parser, FLOAT_CONSTANT);
        return num_float(10);
    case PLUS:
        eat(parser, PLUS);
        return unary_op(PLUS, value(parser));
    case MINUS:
        eat(parser, MINUS);
        return unary_op(MINUS, value(parser));
    case LEFT_PARAN:
        eat(parser, LEFT_PARAN);
        Ast *node = expr(parser);
        eat(parser, RIGHT_PARAN);
        return node;
    default:
        print_token(token);
        puts("Unexpected token");
        exit(-1);
    }

    return NULL;
}

static bool is_power_of_2(int n)
{
    if (n < 0)
    {
        return false;
    }

    return true;
}

Ast *power(Parser *parser)
{
    // power = value (POWER power)?
    Ast *node = value(parser);
    Token token = parser->current_token;
    if (parser->current_token.type == POWER)
    {
        eat(parser, POWER);
        Ast *tmp = bin_op(token.type, node, power(parser));
        node = tmp;
    }
    return node;
}

Ast *product(Parser *parser)
{
    // """product: power ((MUL | DIV) power)*"""
    Ast *node = power(parser);
    while (token_is(parser->current_token.type, ASTRIK, SLASH))
    {
        Ast *tmp;
        Token token = parser->current_token;
        if (parser->current_token.type == ASTRIK)
        {
            eat(parser, ASTRIK);
            tmp = bin_op(token.type, node, power(parser));
            node = tmp;
        }
        else if (parser->current_token.type == SLASH)
        {
            eat(parser, SLASH);
            tmp = bin_op(token.type, node, power(parser));
            node = tmp;
        }
    }
    return node;
}

Ast *expr(Parser *parser)
{
    // expr: product ((ADD,MINUS) product )*
    Ast *node = product(parser);
    while (token_is(parser->current_token.type, PLUS, MINUS))
    {
        Token token = parser->current_token;
        Ast *tmp;
        if (parser->current_token.type == PLUS)
        {
            eat(parser, PLUS);
            tmp = bin_op(token.type, node, product(parser));
            node = tmp;
        }
        else
        {
            eat(parser, MINUS);
            tmp = bin_op(token.type, node, product(parser));
            node = tmp;
        }
    }

    return node;
}

int visit(Ast *root);

int visit_bin_op(Ast *node)
{
    int left = visit(node->children[0]);
    int right = visit(node->children[1]);
    TokenType type = node->type;
    switch (type)
    {
    case PLUS:
        printf("+ ");
        return left + right;
    case MINUS:
        printf("- ");
        return left - right;
    case SLASH:
        printf("/ ");
        if (right == 0)
        {
            puts("Division by zero error");
            exit(1);
        }
        return left / right;
    case ASTRIK:
        printf("* ");
        return left * right;
    default:
        return -1;
    }
}

int visit_number(Ast *node)
{
    // printf("visiting number %d\n",node->value.int_value);
    printf("%d ", node->value.int_value);
    return node->value.int_value;
}

int visit_unary(Ast *node)
{
    if (node->type == PLUS)
    {
        return visit(node->children[0]);
    }
    else
    {
        return -visit(node->children[0]);
    }
}

int visit(Ast *root)
{
    switch (root->node_type)
    {
    case UNARY_OP:
        return visit_unary(root);
    case BINARY_OP:
        return visit_bin_op(root);
    case NUM:
        return visit_number(root);
    }

    exit(1);
}

int main(void)
{
    Parser *parser = init_parser("test.lang");
    //     while(parser->current_token.type !=FILE_END){
    //     print_token(parser->current_token);
    //     free(parser->current_token.lexeme);
    //     parser->current_token = next_token(parser->ss);
    // }
    // // memset(parser->ss, 0, sizeof(*parser->ss));
    Ast *e = expr(parser);
    int ans = visit(e);
    printf("\n%d\n", ans);
    free((void *)parser->ss->source);
    free((void *)parser->ss);
    free(parser);
    free_ast(e);
    return 0;
}
