#include "scanner.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define IMPLEMENT_VECTOR
#include "vector.h"

#include "./scanner.c"
#include "parser.h"
#include "uthash.h"
#define RELEASE
#ifndef RELEASE
int debug(const char *fmt, ...)
{
    int written = 0;
    va_list args;
    va_start(args, fmt);

    written = vfprintf(stdout, fmt, args);
    fflush(stdout);
    va_end(args);
    return written;
}

#else
#define debug(fmt,...)
#endif

typedef struct 
{
    char id[MAX_IDENDIFYER_LEN+1];
    float value;
    UT_hash_handle hh;
}Var_items;

Var_items* var_memory = NULL;

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

static void assert_id(const char* id)
{
    int id_len = strlen(id);
    if(id_len>MAX_IDENDIFYER_LEN)
    {
        error_occur("Variable name cannot be greter than %d\n",MAX_IDENDIFYER_LEN);
        error_occur("Current variable name length is %d\n",id_len);
        exit(-1);
    }
}

void free_parser(Parser* p)
{
    free((void *)p->ss->source);
    free((void *)p->ss);
    free(p);
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

int visit_assign_op(Ast* node)
{
    if(node->children[0]->type!=IDENTIFYER)
    {
        error_occur("Cannot assign. Invalid expression.\n");
        exit(-1);
    }

    Var_items* var = NULL;
    const char* var_name = node->children[0]->value.identifer;
    HASH_FIND_STR(var_memory,var_name,var);
    if(!var)
    {
        error_occur("Variable \"%s\" not decalred\n.",var_name);
        exit(-1);
    }

    var->value = visit(node->children[1]); 

    HASH_FIND_STR(var_memory,var_name,var);
    return var->value;
}

int visit_bin_op(Ast* node)
{

    TokenType type = node->type;
    int left = visit(node->children[0]);
    int right = visit(node->children[1]);

    switch (type)
    {
    case PLUS:
        debug("+ ");
        return left + right;
    case MINUS:
        debug("- ");
        return left - right;
    case SLASH:
        debug("/ ");
        if (right == 0)
        {
            puts("Division by zero error");
            exit(1);
        }
        return left / right;
    case ASTRIK:
        debug("* ");
        return left * right;
    case POWER:
            debug("** ");
            {
                int product = 1;
                while(right--){product *= left;}
                return product;
            }
    default:
        return -1;
    }
}

int visit_number(Ast* node)
{
    // printf("visiting number %d\n",node->value.int_value);
    debug("%d ", node->value.int_value);
    return node->value.int_value;
}

int visit_unary(Ast* node)
{
    switch(node->type)
    {
    case PLUS:
    {
        debug("+ ");
        return visit(node->children[0]);
    }
    case MINUS:
    {
        debug("- ");
        return -visit(node->children[0]);
    }
    case K_PRINT:
    {
        int res = visit(node->children[0]);
        return printf("%d\n",res);
    }
    }
    return 0;
}

int visit_declaration(Ast* root)
{
    char* var_name = root->children[0]->value.identifer;
    Var_items* var = NULL; 
    HASH_FIND_STR(var_memory,var_name,var); 
    if(var)
    {
        error_occur("Variable \"%s\" already declared.\n",var_name);
        exit(-1);
    }

    var = malloc(sizeof(*var));
    if(!var) perror("Unalble to allocate memory."); 

    strncpy(var->id,var_name,MAX_IDENDIFYER_LEN);
    HASH_ADD_STR(var_memory,id,var);

    HASH_FIND_STR(var_memory,var_name,var); 
    debug("Variable \"%s\" declration successfull.\n",var_name);
    return 0;
}

Ast* program(Parser* p)
{
    // Program :: Expr | statement 
    Ast* root = new_ast(-1,PROGRAM); 
    while(p->current_token.type != FILE_END)
    {
        switch(p->current_token.type)
        {
            case K_VAR:
            {
                vector_append(root->children,declaration(p));
                break;
            }
            default:
            {
                Ast* expression = expr(p,0);
                eat(p,SEMICOLON);
                vector_append(root->children,expression);
            }
        }
    }
    return root;
}

int visit_program(Ast* root)
{
    size_t len = vector_length(root->children);
    for(int i=0;i<len;i++) visit(root->children[i]);
    return 0;
}

int visit_identifyer(Ast* root)
{
    Var_items* var = NULL;
    HASH_FIND_STR(var_memory,root->value.identifer,var);
    if(!var)
    {
        error_occur("Variable \"%s\" not declared.\n",
                    root->value.identifer);
    }
   return var->value;
}

int visit(Ast *root)
{
    switch (root->node_type)
    {
    case UNARY_OP:
        return visit_unary(root);
    case BINARY_OP:
        return visit_bin_op(root);
    case ASSIGN_OP:
        return visit_assign_op(root);
    case NUM:
        return visit_number(root);
    case VAR_DECL:
        return visit_declaration(root);
    case PROGRAM:
        return visit_program(root);
    case ID:
        return visit_identifyer(root);
    }

    exit(1);
}

int bp(TokenType token_type)
{
    switch (token_type) 
    {
        case ASSIGN:
            return 9;
        case PLUS:
        case MINUS:
            return 10;

        case SLASH:
        case ASTRIK: 
            return 20;
        case PREFIX:
            return 21;
        case POWER:
            return 30;
    }
    return -1;
}

    
Ast* nud(Parser* p)
{
    Token token = p->current_token;
    TokenType type  = token.type;
    switch(p->current_token.type)
    {
        case PLUS:
        case MINUS:
        {
                eat(p,type);
                Ast* tmp = unary_op(type,expr(p,bp(PREFIX)));
                return tmp;
        }
        case INT_CONSTANT:
        case HEX_CONSTANT:
        case FLOAT_CONSTANT:
            return value(p);

        case LEFT_PARAN:
        {
            eat(p,type);
            Ast* tmp = expr(p,0);
            eat(p,RIGHT_PARAN);
            return tmp; 
        }
        case K_PRINT:
        {
                eat(p,type);
                Ast* tmp = unary_op(K_PRINT,expr(p,bp(PREFIX)));
                return tmp;
        }
        case IDENTIFYER:
        {
            Ast* tmp = new_ast(IDENTIFYER, ID);
            assert_id(token.lexeme);
            strncpy(tmp->value.identifer,token.lexeme,MAX_IDENDIFYER_LEN); 
            eat(p,IDENTIFYER);
           return tmp; 
        }
        default:
        {
            error_occur("Unexpected Token %s\n",
                        token_to_str(p->current_token.type));
            exit(-1);
            return NULL;
        }
    }

    return NULL; // unneccesory
}

Ast* led(Parser* p,Ast* left)
{
    TokenType type = p->current_token.type;
    eat(p,type);
    switch(type)
    {
        case POWER:
            return bin_op(type,left, expr(p,bp(type)-1));
        case ASSIGN:
        {
            Ast* temp = bin_op(type,left, expr(p,bp(type)-1));
            temp->node_type = ASSIGN_OP;
            return temp;
        }
    }
    return bin_op(type,left, expr(p,bp(type)+1));

}

Ast* expr(Parser*p, int rbp)
{
    Ast* left = nud(p); // consumes the token
    while(bp(p->current_token.type)>rbp)
    {
        left = led(p,left);
    }
    return left;
}

Ast* declaration(Parser* p)
{
    Token token = p->current_token;

    eat(p,K_VAR);
    Ast* var = new_ast(K_VAR,VAR_DECL);

    token = p->current_token;
    if(token.type != IDENTIFYER)
    {
        error_occur("Idenfifyer expected but got %s\n",
                    token_to_str(token.type));
        exit(-1);
    }
   
    assert_id(token.lexeme);

    Ast* id = new_ast(IDENTIFYER,ID);
    strcpy(id->value.identifer,token.lexeme);
    eat(p,IDENTIFYER);

    token = p->current_token;
    eat(p,COLON);


    token = p->current_token;
    eat(p,K_INT);
    Ast* data_type = new_ast(K_INT, DATA_TYPE);
    eat(p,SEMICOLON);
    vector_append(var->children,id);
    vector_append(var->children,data_type);

    return var;
}

int main(int argc, char** argv)
{
    if(argc==1)
    {
        printf("USES: interpreter <sourcefile>\n");
        return 0;
    }
    argv++; 
    Parser *parser = init_parser(*argv);

    Ast *e = program(parser); 
    visit(e);
    fflush(stdout);
    Var_items *current, *tmp;
    HASH_ITER(hh,var_memory, current, tmp) {
        HASH_DEL(var_memory, current);
        free(current);
    }

    free_parser(parser);
    free_ast(e);
    return 0;
}
