#ifndef scanner_h_INCLUDED
#define scanner_h_INCLUDED
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_LIST                                                             \
    TOKEN(LEFT_PARAN)                                                          \
    TOKEN(RIGHT_PARAN)                                                         \
    TOKEN(LEFT_BRACE)                                                          \
    TOKEN(RIGHT_BRACE)                                                         \
    TOKEN(LEFT_SQR)                                                            \
    TOKEN(RIGHT_SQR)                                                           \
    TOKEN(ASTRIK)                                                              \
    TOKEN(SLASH)                                                               \
    TOKEN(PLUS)                                                                \
    TOKEN(MINUS)                                                               \
    TOKEN(ASSIGN)                                                              \
    TOKEN(LESS_THAN)                                                           \
    TOKEN(GREATER_THAN)                                                        \
    TOKEN(COMMA)                                                               \
    TOKEN(SEMICOLON)                                                           \
    TOKEN(MOD)                                                                 \
    TOKEN(DOT)                                                                 \
    TOKEN(NOT)                                                                 \
    TOKEN(LESS_EQUAL)                                                          \
    TOKEN(POWER)                                                               \
    TOKEN(GREATER_EQUAL)                                                       \
    TOKEN(NOT_EQUAL)                                                           \
    TOKEN(PLUS_EQUAL)                                                          \
    TOKEN(MINS_EQUAL)                                                          \
    TOKEN(ASTRIK_EQUAL)                                                        \
    TOKEN(STRING)                                                              \
    TOKEN(NUMBER)                                                              \
    TOKEN(INT_CONSTANT)                                                        \
    TOKEN(OCTAL_CONSTANT)                                                      \
    TOKEN(HEX_CONSTANT)                                                        \
    TOKEN(FLOAT_CONSTANT)                                                      \
    TOKEN(IDENTIFYER)                                                          \
    TOKEN(AND)                                                                 \
    TOKEN(OR)                                                                  \
    TOKEN(IF)                                                                  \
    TOKEN(ELSE)                                                                \
    TOKEN(TRUE)                                                                \
    TOKEN(FALSE)                                                               \
    TOKEN(FOR)                                                                 \
    TOKEN(WHILE)                                                               \
    TOKEN(RETURN)                                                              \
    TOKEN(FUNCTION)                                                            \
    TOKEN(FILE_END)                                                            \
    TOKEN_EXCLUDE(UNKNOWN = -1)

#define TOKEN_EXCLUDE(name) TOKEN(name)
#define TOKEN(name) name,

typedef enum { TOKEN_LIST } TokenType;

#undef TOKEN_EXCLUDE
#undef TOKEN


typedef struct {
    TokenType type;
    int line;
    char *lexeme;
} Token;

typedef struct {
    const char *source;
    int start;
    int current;
    int line;
    int source_len;

} ScannerState;

#define invalid_token(fmt,...) fprintf(stderr,fmt,__VA_ARGS__)
#define token_is(t,...) _token_is(t,__VA_ARGS__,UNKNOWN)

Token next_token(ScannerState *ss);
bool _token_is(TokenType t, ...);
const char *token_to_str(TokenType type);
void print_token(Token token);


#endif // scanner_h_INCLUDED
