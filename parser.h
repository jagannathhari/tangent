#ifndef parser_h_INCLUDED
#define parser_h_INCLUDED
#include "scanner.h"

typedef enum
{
    UNARY_OP,
    BINARY_OP,
    NUM
} NodeType;

typedef struct Ast
{
    TokenType type;
    union {
        int int_value;
        float float_value;
        char* string;
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
Ast* expr(Parser* parser);

#endif // parser_h_INCLUDED
