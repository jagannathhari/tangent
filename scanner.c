#include "scanner.h"
#include <ctype.h>

const char *token_to_str(TokenType type)
{

    #define TOKEN(name) #name,
    #define TOKEN_EXCLUDE(name)

    const char *tokens[] = {TOKEN_LIST};
    int total_tokens = sizeof(tokens)/sizeof(tokens[0]);

    #undef TOKEN_EXCLUDE
    #undef TOKEN

    if(type>=total_tokens)
    {
        return NULL; 
    }

    return tokens[type];

}

 // similar to in python (token in (INT,STRING....))
bool _token_is(TokenType token_type, ...)
{
    va_list args;
    va_start(args, token_type);

    TokenType tmp;
    bool result = false;
    while ((tmp = va_arg(args, TokenType)) != UNKNOWN)
    {
        if (tmp == token_type)
        {
            result = true;
            break;            
        }
    }

    va_end(args);
    return result;
}


inline void print_token(Token token)
{
    printf("Token(%s, %d, \"%s\")\n",
            token_to_str(token.type),
            token.line,
            token.lexeme
          );
}

static inline bool is_at_end(ScannerState *ss)
{ 
    return ss->current >= ss->source_len; 
}

static inline char advance(ScannerState *ss)
{ 
    return ss->source[ss->current++];
}

static inline char peek(ScannerState *ss)
{
    return is_at_end(ss) ? '\0' : ss->source[ss->current];
}

static inline bool match(char expected, ScannerState *ss)
{
    if (is_at_end(ss) || ss->source[ss->current] != expected)
        return false;

    ss->current++;
    return true;
}

static char *substr(const char *source, int start, int end)
{
    if (start < 0 || start > end || !source)
    {
        return NULL;
    }

    int substr_size = end - start;
    char *result = calloc(substr_size + 1, 1);

    if (!result)
    {
        return NULL;
    }

    strncpy(result, &source[start], substr_size);
    result[substr_size] = '\0';

    return result;
}


static char peek_next(ScannerState *ss)
{
    if (ss->current + 1 >= ss->source_len)
        return '\0';
    return ss->source[ss->current + 1];
}

static Token string(ScannerState *ss)
{
    while (peek(ss) != '"' && !is_at_end(ss))
    {
        if (peek(ss) == '\n')
            ss->line++;
        advance(ss);
    }
    if (is_at_end(ss))
    {
        invalid_token("Error: %s","Unterminated string.\n");
        exit(-1);
    }
    advance(ss); // consume "

    Token token;
    token.type   = STRING;
    token.line   =  ss->line;
    token.lexeme = substr(ss->source, ss->start + 1, ss->current - 1);

    ss->start    = ss->current;
    return token;
}

static inline bool is_octal_digit(char c)
{
    if(c >= '0' && c <= '7') return true;
    return false;
}

static Token octal_number(ScannerState *ss)
{
    while(is_octal_digit(peek(ss)))
    {
         advance(ss);
    }

    Token token;

    token.type   = OCTAL_CONSTANT;
    token.lexeme = substr(ss->source,ss->start,ss->current);
    token.line   = ss->line;

    ss->start    = ss->current;

    return token;
}

bool is_valid_hex_digit(char c)
{
    if ((c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F'))
    {

        return true;

    }
    return false;
}

static Token hex_number(ScannerState *ss)
{
    while(is_valid_hex_digit(peek(ss)))
    {
        advance(ss);
    }

    char *lexeme = substr(ss->source,ss->start, ss->current); 

     // lexeme only contains only 0x 
    if(strlen(lexeme) == 2)
    {
        exit(-1);
    }

    Token token;
    token.type   = HEX_CONSTANT;
    token.line   = ss->line;
    token.lexeme = lexeme; 

    ss->start    = ss->current;
 
    return token;
}

static Token number_decimal(ScannerState *ss)
{
    bool is_float = false;
    while (isdigit(peek(ss)))
    {
        advance(ss);
    }

    if (peek(ss) == '.' && isdigit(peek_next(ss)))
    {
        is_float = true;
        advance(ss);

        while (isdigit(peek(ss)))
        {
            advance(ss);
        }
    }

    Token token;
    token.type   = is_float ? FLOAT_CONSTANT : INT_CONSTANT;
    token.line   = ss->line;
    token.lexeme = substr(ss->source,ss->start, ss->current);

    ss->start    = ss->current;

    return token;
}

static Token number(char first_digit , ScannerState *ss)
{
    if (first_digit == '0')
    {
        char next = peek(ss);
        if (next == 'X' || next == 'x')
        {
            advance(ss); // consume x or X
            return hex_number(ss);
        }

        return octal_number(ss);
    }

    return number_decimal(ss);
}

static TokenType keyword(const char *identifier)
{
#define STRCMP(str) strcmp(identifier, str) == 0

    if (STRCMP("or"))          return OR;
    else if (STRCMP("for"))    return FOR;
    else if (STRCMP("while"))  return WHILE;
    else if (STRCMP("return")) return RETURN;
    else if (STRCMP("else"))   return ELSE;
    else if (STRCMP("true"))   return TRUE;
    else if (STRCMP("false"))  return FALSE;
    else if (STRCMP("if"))     return IF;
    else if (STRCMP("and"))    return AND;
    else if (STRCMP("fn"))     return FUNCTION;
    else                       return IDENTIFYER;
}

static Token identifier(ScannerState *ss)
{
    while (isalnum(peek(ss)) || peek(ss) == '_')
        advance(ss);

    char *identifier = substr(ss->source, ss->start, ss->current);

    Token token;
    token.type   = keyword(identifier);
    token.line   = ss->line;
    token.lexeme = substr(ss->source, ss->start, ss->current);

    ss->start    = ss->current;

    return token;
} 

static Token build_token(TokenType token_type , ScannerState *ss)
{
    Token token;
    token.type   = token_type;
    token.line   = ss->line;
    token.lexeme =  substr(ss->source, ss->start, ss->current); 

    ss->start    = ss->current;

    return token;
}

Token next_token(ScannerState *ss)
{
    while (!is_at_end(ss))
    {
        char c = advance(ss);
        switch (c)
        {
        case '%':
            return build_token(MOD, ss);
        case '*':
            return build_token(match('*',ss)?POWER:ASTRIK, ss);
        case ';':
            return build_token(SEMICOLON, ss);
        case ',':
            return build_token(COMMA, ss);
        case '+':
            return build_token(match('=', ss) ? PLUS_EQUAL : PLUS, ss);
        case '-':
            return build_token(MINUS, ss);
        case '=':
            return build_token(ASSIGN, ss);
        case '/':
            return build_token(SLASH, ss);
        case '!':
            return build_token(match('=', ss) ? NOT_EQUAL : NOT, ss);
        case '.':
            return build_token(DOT, ss);
        case '(':
            return build_token(LEFT_PARAN, ss);
        case ')':
            return build_token(RIGHT_PARAN, ss);
        case '[':
            return build_token(LEFT_SQR, ss);
        case ']':
            return build_token(RIGHT_SQR, ss);
        case '{':
            return build_token(LEFT_BRACE, ss);
        case '}':
            return build_token(RIGHT_BRACE, ss);
        case '<':
            return build_token(match('=', ss) ? LESS_EQUAL : LESS_THAN, ss);
        case '>':
            return build_token(match('=', ss) ? GREATER_EQUAL : GREATER_THAN,
                               ss);
        case '\n':
            ss->line++;
            ss->start = ss->current;
            break;
        case '"':
            return string(ss);
        case ' ':
        case '\t':
        case '\r':
            ss->start = ss->current;
            break;
        //     // while(!is_at_end(ss) && peek(ss)==' ') advance(ss);
        default:
            if (isdigit(c))                  return number(c,ss);
            else if (isalpha(c) || c == '_') return identifier(ss);
            else
            {
                invalid_token("Error: Unknown character %c\n",c);
                exit(1);
            } 
        }
    }

    Token token;
    token.type   = FILE_END;
    token.line   = ss->line;
    token.lexeme = NULL;

    return token;
}
