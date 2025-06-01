#ifndef parser_h_INCLUDED
#define parser_h_INCLUDED

#define MAX_IDENDIFYER_LEN 256
typedef enum
{
    UNARY_OP,
    BINARY_OP,
    ASSIGN_OP,
    VAR_DECL,
    DATA_TYPE,
    PROGRAM,
    ID,
    NUM
} NodeType;

typedef struct Ast
{
    TokenType type;
    int line;
    int offset;
    union {
        int int_value;
        float float_value;
        char* string;
        char identifer[MAX_IDENDIFYER_LEN+1];
    } value;
    NodeType node_type;
    struct Ast** children;
} Ast;

typedef struct
{
    Token current_token;
    ScannerState *ss;
} Parser;

Parser* init_parser(const char* file_path);

int visit_identifyer(Ast* root);

int visit(Ast *root);
Ast* declaration(Parser* p);
Ast* expr(Parser*p, int rbp);
Ast* led(Parser* p,Ast* left);
Ast* nud(Parser* p);

#endif // parser_h_INCLUDED
