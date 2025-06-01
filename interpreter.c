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
    TOKEN(COLON)\
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
    TOKEN(PREFIX)\
    TOKEN(K_AND)                                                                 \
    TOKEN(K_OR)                                                                  \
    TOKEN(K_IF)                                                                  \
    TOKEN(K_ELSE)                                                                \
    TOKEN(K_TRUE)                                                                \
    TOKEN(K_FALSE)                                                               \
    TOKEN(K_FOR)                                                                 \
    TOKEN(K_WHILE)                                                               \
    TOKEN(K_RETURN)                                                              \
    TOKEN(K_FUNCTION)                                                            \
    TOKEN(K_VAR)\
    TOKEN(K_INT)\
    TOKEN(K_PRINT)\
    TOKEN(FILE_END)                                                            \
    TOKEN_EXCLUDE(UNKNOWN = -1)

#define TOKEN_EXCLUDE(name) name
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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define IMPLEMENT_VECTOR
#ifndef VECTOR_H
#define VECTOR_H

// refrence https://bytesbeneath.com/p/dynamic-arrays-in-c

#include <stddef.h>
#include <stdlib.h>

// https://github.com/nothings/stb/blob/master/docs/stb_howto.txt
#ifndef VECAPI
    #ifdef VECTOR_STATIC
        #define VECAPI static
    #else
        #define VECAPI extern
    #endif
#endif

#if defined(VEC_MALLOC) && defined(VEC_FREE) && defined(VEC_REALLOC)
#elif !defined(VEC_MALLOC) && !defined(VEC_FREE) && !defined(VEC_REALLOC)
#else
    #error "You need to define all VEC_MALLOC, VEC_REALLOC, and VEC_FREE or none"
#endif

#ifndef VEC_MALLOC
    #define VEC_MALLOC(size) malloc(size)
    #define VEC_FREE(ptr) free(ptr)
    #define VEC_REALLOC(ptr,new_size) realloc(ptr,new_size)
#endif

typedef struct
{
    size_t capacity;
    size_t element_size;
    size_t length;
    size_t vector__aligment; // I think it will not cause alignment issues for 1, 2, 4, 16, 32 (on 64-bit)
}VectorHeader;

#define VECTOR_CAPACITY                 16
#define Vector(T)                       vector_init(sizeof(T), VECTOR_CAPACITY)
#define vector_header(v)                ((VectorHeader *)(v)-1)
#define vector_length(v)                ((v)?vector_header(v)->length:0)
#define vector_capacity(v)              (vector_header(v)->capacity)
#define vector_pop(v)                   (vector_header(v)->length--,v[vector_length(v)])
#define free_vector(v)                  VEC_FREE((v)?(vector_header(v)):NULL)
#define vector_append(vector, value)    ((vector) = vector_ensure_capacity(vector, 1),  \
                                        (vector)[vector_header(vector)->length] = (value),                 \
                                        &(vector)[vector_header(vector)->length++])                        

VECAPI void *vector_init(const size_t element_size, const size_t capacity);
VECAPI void *vector_ensure_capacity(void *vector, const size_t total_element);

#endif // VECTOR_H

#ifdef IMPLEMENT_VECTOR

VECAPI void *vector_init(size_t element_size, const size_t capacity)
{
    void *ptr = 0;
    VectorHeader *vec_header =
        VEC_MALLOC(sizeof(*vec_header) + capacity * element_size);

    if (vec_header)
    {
        vec_header->capacity = capacity;
        vec_header->element_size = element_size;
        vec_header->length = 0;
        ptr = vec_header + 1;
    }

    return ptr;
}

VECAPI void *vector_ensure_capacity(void *vector, const size_t total_element) 
{
    VectorHeader *vec_header = vector_header(vector);
    const size_t element_size = vec_header->element_size;
    const size_t desired_capacity = vec_header->length + total_element;
    if (vec_header->capacity < desired_capacity) 
    {
        size_t new_capacity = vec_header->capacity * 2;
        while (new_capacity < desired_capacity) new_capacity *= 2;

        const size_t new_size = sizeof(*vec_header) + new_capacity * element_size;
        VectorHeader *temp = VEC_REALLOC(vec_header, new_size);
        if (!temp) 
        {
            // todo
            return NULL;
        }

        vec_header = temp;
        vec_header->capacity = new_capacity;
    }

    vec_header += 1;
    return vec_header;
}

#endif // IMPLEMENT_VECTOR

// #include "scanner.h"
#include <ctype.h>

const char *token_to_str(TokenType type)
{

    #define TOKEN(name) #name,
    #define TOKEN_EXCLUDE(name) "/0"
 
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

static TokenType is_keyword(const char *identifier)
{
#define STRCMP(str) strcmp(identifier, str) == 0

    if (STRCMP("or"))          return K_OR;
    else if (STRCMP("for"))    return K_FOR;
    else if (STRCMP("while"))  return K_WHILE;
    else if (STRCMP("return")) return K_RETURN;
    else if (STRCMP("else"))   return K_ELSE;
    else if (STRCMP("true"))   return K_TRUE;
    else if (STRCMP("false"))  return K_FALSE;
    else if (STRCMP("if"))     return K_IF;
    else if (STRCMP("and"))    return K_AND;
    else if (STRCMP("fn"))     return K_FUNCTION;
    else if (STRCMP("var"))    return K_VAR;
    else if (STRCMP("int"))    return K_INT;
    else if (STRCMP("print"))  return K_PRINT;
    else                       return IDENTIFYER;
}

static Token identifier(ScannerState *ss)
{
    while (isalnum(peek(ss)) || peek(ss) == '_')
        advance(ss);

    char *identifier = substr(ss->source, ss->start, ss->current);

    Token token;
    token.type   = is_keyword(identifier);
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
        case ':':
            return build_token(COLON, ss);
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
/*
Copyright (c) 2003-2025, Troy D. Hanson  https://troydhanson.github.io/uthash/
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef UTHASH_H
#define UTHASH_H

#define UTHASH_VERSION 2.3.0

#include <string.h>   /* memcmp, memset, strlen */
#include <stddef.h>   /* ptrdiff_t */
#include <stdlib.h>   /* exit */

#if defined(HASH_NO_STDINT) && HASH_NO_STDINT
/* The user doesn't have <stdint.h>, and must figure out their own way
   to provide definitions for uint8_t and uint32_t. */
#else
#include <stdint.h>   /* uint8_t, uint32_t */
#endif

/* These macros use decltype or the earlier __typeof GNU extension.
   As decltype is only available in newer compilers (VS2010 or gcc 4.3+
   when compiling c++ source) this code uses whatever method is needed
   or, for VS2008 where neither is available, uses casting workarounds. */
#if !defined(DECLTYPE) && !defined(NO_DECLTYPE)
#if defined(_MSC_VER)   /* MS compiler */
#if _MSC_VER >= 1600 && defined(__cplusplus)  /* VS2010 or newer in C++ mode */
#define DECLTYPE(x) (decltype(x))
#else                   /* VS2008 or older (or VS2010 in C mode) */
#define NO_DECLTYPE
#endif
#elif defined(__MCST__)  /* Elbrus C Compiler */
#define DECLTYPE(x) (__typeof(x))
#elif defined(__BORLANDC__) || defined(__ICCARM__) || defined(__LCC__) || defined(__WATCOMC__)
#define NO_DECLTYPE
#else                   /* GNU, Sun and other compilers */
#define DECLTYPE(x) (__typeof(x))
#endif
#endif

#ifdef NO_DECLTYPE
#define DECLTYPE(x)
#define DECLTYPE_ASSIGN(dst,src)                                                 \
do {                                                                             \
  char **_da_dst = (char**)(&(dst));                                             \
  *_da_dst = (char*)(src);                                                       \
} while (0)
#else
#define DECLTYPE_ASSIGN(dst,src)                                                 \
do {                                                                             \
  (dst) = DECLTYPE(dst)(src);                                                    \
} while (0)
#endif

#ifndef uthash_malloc
#define uthash_malloc(sz) malloc(sz)      /* malloc fcn                      */
#endif
#ifndef uthash_free
#define uthash_free(ptr,sz) free(ptr)     /* free fcn                        */
#endif
#ifndef uthash_bzero
#define uthash_bzero(a,n) memset(a,'\0',n)
#endif
#ifndef uthash_strlen
#define uthash_strlen(s) strlen(s)
#endif

#ifndef HASH_FUNCTION
#define HASH_FUNCTION(keyptr,keylen,hashv) HASH_JEN(keyptr, keylen, hashv)
#endif

#ifndef HASH_KEYCMP
#define HASH_KEYCMP(a,b,n) memcmp(a,b,n)
#endif

#ifndef uthash_noexpand_fyi
#define uthash_noexpand_fyi(tbl)          /* can be defined to log noexpand  */
#endif
#ifndef uthash_expand_fyi
#define uthash_expand_fyi(tbl)            /* can be defined to log expands   */
#endif

#ifndef HASH_NONFATAL_OOM
#define HASH_NONFATAL_OOM 0
#endif

#if HASH_NONFATAL_OOM
/* malloc failures can be recovered from */

#ifndef uthash_nonfatal_oom
#define uthash_nonfatal_oom(obj) do {} while (0)    /* non-fatal OOM error */
#endif

#define HASH_RECORD_OOM(oomed) do { (oomed) = 1; } while (0)
#define IF_HASH_NONFATAL_OOM(x) x

#else
/* malloc failures result in lost memory, hash tables are unusable */

#ifndef uthash_fatal
#define uthash_fatal(msg) exit(-1)        /* fatal OOM error */
#endif

#define HASH_RECORD_OOM(oomed) uthash_fatal("out of memory")
#define IF_HASH_NONFATAL_OOM(x)

#endif

/* initial number of buckets */
#define HASH_INITIAL_NUM_BUCKETS 32U     /* initial number of buckets        */
#define HASH_INITIAL_NUM_BUCKETS_LOG2 5U /* lg2 of initial number of buckets */
#define HASH_BKT_CAPACITY_THRESH 10U     /* expand when bucket count reaches */

/* calculate the element whose hash handle address is hhp */
#define ELMT_FROM_HH(tbl,hhp) ((void*)(((char*)(hhp)) - ((tbl)->hho)))
/* calculate the hash handle from element address elp */
#define HH_FROM_ELMT(tbl,elp) ((UT_hash_handle*)(void*)(((char*)(elp)) + ((tbl)->hho)))

#define HASH_ROLLBACK_BKT(hh, head, itemptrhh)                                   \
do {                                                                             \
  struct UT_hash_handle *_hd_hh_item = (itemptrhh);                              \
  unsigned _hd_bkt;                                                              \
  HASH_TO_BKT(_hd_hh_item->hashv, (head)->hh.tbl->num_buckets, _hd_bkt);         \
  (head)->hh.tbl->buckets[_hd_bkt].count++;                                      \
  _hd_hh_item->hh_next = NULL;                                                   \
  _hd_hh_item->hh_prev = NULL;                                                   \
} while (0)

#define HASH_VALUE(keyptr,keylen,hashv)                                          \
do {                                                                             \
  HASH_FUNCTION(keyptr, keylen, hashv);                                          \
} while (0)

#define HASH_FIND_BYHASHVALUE(hh,head,keyptr,keylen,hashval,out)                 \
do {                                                                             \
  (out) = NULL;                                                                  \
  if (head) {                                                                    \
    unsigned _hf_bkt;                                                            \
    HASH_TO_BKT(hashval, (head)->hh.tbl->num_buckets, _hf_bkt);                  \
    if (HASH_BLOOM_TEST((head)->hh.tbl, hashval)) {                              \
      HASH_FIND_IN_BKT((head)->hh.tbl, hh, (head)->hh.tbl->buckets[ _hf_bkt ], keyptr, keylen, hashval, out); \
    }                                                                            \
  }                                                                              \
} while (0)

#define HASH_FIND(hh,head,keyptr,keylen,out)                                     \
do {                                                                             \
  (out) = NULL;                                                                  \
  if (head) {                                                                    \
    unsigned _hf_hashv;                                                          \
    HASH_VALUE(keyptr, keylen, _hf_hashv);                                       \
    HASH_FIND_BYHASHVALUE(hh, head, keyptr, keylen, _hf_hashv, out);             \
  }                                                                              \
} while (0)

#ifdef HASH_BLOOM
#define HASH_BLOOM_BITLEN (1UL << HASH_BLOOM)
#define HASH_BLOOM_BYTELEN (HASH_BLOOM_BITLEN/8UL) + (((HASH_BLOOM_BITLEN%8UL)!=0UL) ? 1UL : 0UL)
#define HASH_BLOOM_MAKE(tbl,oomed)                                               \
do {                                                                             \
  (tbl)->bloom_nbits = HASH_BLOOM;                                               \
  (tbl)->bloom_bv = (uint8_t*)uthash_malloc(HASH_BLOOM_BYTELEN);                 \
  if (!(tbl)->bloom_bv) {                                                        \
    HASH_RECORD_OOM(oomed);                                                      \
  } else {                                                                       \
    uthash_bzero((tbl)->bloom_bv, HASH_BLOOM_BYTELEN);                           \
    (tbl)->bloom_sig = HASH_BLOOM_SIGNATURE;                                     \
  }                                                                              \
} while (0)

#define HASH_BLOOM_FREE(tbl)                                                     \
do {                                                                             \
  uthash_free((tbl)->bloom_bv, HASH_BLOOM_BYTELEN);                              \
} while (0)

#define HASH_BLOOM_BITSET(bv,idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define HASH_BLOOM_BITTEST(bv,idx) ((bv[(idx)/8U] & (1U << ((idx)%8U))) != 0)

#define HASH_BLOOM_ADD(tbl,hashv)                                                \
  HASH_BLOOM_BITSET((tbl)->bloom_bv, ((hashv) & (uint32_t)((1UL << (tbl)->bloom_nbits) - 1U)))

#define HASH_BLOOM_TEST(tbl,hashv)                                               \
  HASH_BLOOM_BITTEST((tbl)->bloom_bv, ((hashv) & (uint32_t)((1UL << (tbl)->bloom_nbits) - 1U)))

#else
#define HASH_BLOOM_MAKE(tbl,oomed)
#define HASH_BLOOM_FREE(tbl)
#define HASH_BLOOM_ADD(tbl,hashv)
#define HASH_BLOOM_TEST(tbl,hashv) 1
#define HASH_BLOOM_BYTELEN 0U
#endif

#define HASH_MAKE_TABLE(hh,head,oomed)                                           \
do {                                                                             \
  (head)->hh.tbl = (UT_hash_table*)uthash_malloc(sizeof(UT_hash_table));         \
  if (!(head)->hh.tbl) {                                                         \
    HASH_RECORD_OOM(oomed);                                                      \
  } else {                                                                       \
    uthash_bzero((head)->hh.tbl, sizeof(UT_hash_table));                         \
    (head)->hh.tbl->tail = &((head)->hh);                                        \
    (head)->hh.tbl->num_buckets = HASH_INITIAL_NUM_BUCKETS;                      \
    (head)->hh.tbl->log2_num_buckets = HASH_INITIAL_NUM_BUCKETS_LOG2;            \
    (head)->hh.tbl->hho = (char*)(&(head)->hh) - (char*)(head);                  \
    (head)->hh.tbl->buckets = (UT_hash_bucket*)uthash_malloc(                    \
        HASH_INITIAL_NUM_BUCKETS * sizeof(struct UT_hash_bucket));               \
    (head)->hh.tbl->signature = HASH_SIGNATURE;                                  \
    if (!(head)->hh.tbl->buckets) {                                              \
      HASH_RECORD_OOM(oomed);                                                    \
      uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                        \
    } else {                                                                     \
      uthash_bzero((head)->hh.tbl->buckets,                                      \
          HASH_INITIAL_NUM_BUCKETS * sizeof(struct UT_hash_bucket));             \
      HASH_BLOOM_MAKE((head)->hh.tbl, oomed);                                    \
      IF_HASH_NONFATAL_OOM(                                                      \
        if (oomed) {                                                             \
          uthash_free((head)->hh.tbl->buckets,                                   \
              HASH_INITIAL_NUM_BUCKETS*sizeof(struct UT_hash_bucket));           \
          uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                    \
        }                                                                        \
      )                                                                          \
    }                                                                            \
  }                                                                              \
} while (0)

#define HASH_REPLACE_BYHASHVALUE_INORDER(hh,head,fieldname,keylen_in,hashval,add,replaced,cmpfcn) \
do {                                                                             \
  (replaced) = NULL;                                                             \
  HASH_FIND_BYHASHVALUE(hh, head, &((add)->fieldname), keylen_in, hashval, replaced); \
  if (replaced) {                                                                \
    HASH_DELETE(hh, head, replaced);                                             \
  }                                                                              \
  HASH_ADD_KEYPTR_BYHASHVALUE_INORDER(hh, head, &((add)->fieldname), keylen_in, hashval, add, cmpfcn); \
} while (0)

#define HASH_REPLACE_BYHASHVALUE(hh,head,fieldname,keylen_in,hashval,add,replaced) \
do {                                                                             \
  (replaced) = NULL;                                                             \
  HASH_FIND_BYHASHVALUE(hh, head, &((add)->fieldname), keylen_in, hashval, replaced); \
  if (replaced) {                                                                \
    HASH_DELETE(hh, head, replaced);                                             \
  }                                                                              \
  HASH_ADD_KEYPTR_BYHASHVALUE(hh, head, &((add)->fieldname), keylen_in, hashval, add); \
} while (0)

#define HASH_REPLACE(hh,head,fieldname,keylen_in,add,replaced)                   \
do {                                                                             \
  unsigned _hr_hashv;                                                            \
  HASH_VALUE(&((add)->fieldname), keylen_in, _hr_hashv);                         \
  HASH_REPLACE_BYHASHVALUE(hh, head, fieldname, keylen_in, _hr_hashv, add, replaced); \
} while (0)

#define HASH_REPLACE_INORDER(hh,head,fieldname,keylen_in,add,replaced,cmpfcn)    \
do {                                                                             \
  unsigned _hr_hashv;                                                            \
  HASH_VALUE(&((add)->fieldname), keylen_in, _hr_hashv);                         \
  HASH_REPLACE_BYHASHVALUE_INORDER(hh, head, fieldname, keylen_in, _hr_hashv, add, replaced, cmpfcn); \
} while (0)

#define HASH_APPEND_LIST(hh, head, add)                                          \
do {                                                                             \
  (add)->hh.next = NULL;                                                         \
  (add)->hh.prev = ELMT_FROM_HH((head)->hh.tbl, (head)->hh.tbl->tail);           \
  (head)->hh.tbl->tail->next = (add);                                            \
  (head)->hh.tbl->tail = &((add)->hh);                                           \
} while (0)

#define HASH_AKBI_INNER_LOOP(hh,head,add,cmpfcn)                                 \
do {                                                                             \
  do {                                                                           \
    if (cmpfcn(DECLTYPE(head)(_hs_iter), add) > 0) {                             \
      break;                                                                     \
    }                                                                            \
  } while ((_hs_iter = HH_FROM_ELMT((head)->hh.tbl, _hs_iter)->next));           \
} while (0)

#ifdef NO_DECLTYPE
#undef HASH_AKBI_INNER_LOOP
#define HASH_AKBI_INNER_LOOP(hh,head,add,cmpfcn)                                 \
do {                                                                             \
  char *_hs_saved_head = (char*)(head);                                          \
  do {                                                                           \
    DECLTYPE_ASSIGN(head, _hs_iter);                                             \
    if (cmpfcn(head, add) > 0) {                                                 \
      DECLTYPE_ASSIGN(head, _hs_saved_head);                                     \
      break;                                                                     \
    }                                                                            \
    DECLTYPE_ASSIGN(head, _hs_saved_head);                                       \
  } while ((_hs_iter = HH_FROM_ELMT((head)->hh.tbl, _hs_iter)->next));           \
} while (0)
#endif

#if HASH_NONFATAL_OOM

#define HASH_ADD_TO_TABLE(hh,head,keyptr,keylen_in,hashval,add,oomed)            \
do {                                                                             \
  if (!(oomed)) {                                                                \
    unsigned _ha_bkt;                                                            \
    (head)->hh.tbl->num_items++;                                                 \
    HASH_TO_BKT(hashval, (head)->hh.tbl->num_buckets, _ha_bkt);                  \
    HASH_ADD_TO_BKT((head)->hh.tbl->buckets[_ha_bkt], hh, &(add)->hh, oomed);    \
    if (oomed) {                                                                 \
      HASH_ROLLBACK_BKT(hh, head, &(add)->hh);                                   \
      HASH_DELETE_HH(hh, head, &(add)->hh);                                      \
      (add)->hh.tbl = NULL;                                                      \
      uthash_nonfatal_oom(add);                                                  \
    } else {                                                                     \
      HASH_BLOOM_ADD((head)->hh.tbl, hashval);                                   \
      HASH_EMIT_KEY(hh, head, keyptr, keylen_in);                                \
    }                                                                            \
  } else {                                                                       \
    (add)->hh.tbl = NULL;                                                        \
    uthash_nonfatal_oom(add);                                                    \
  }                                                                              \
} while (0)

#else

#define HASH_ADD_TO_TABLE(hh,head,keyptr,keylen_in,hashval,add,oomed)            \
do {                                                                             \
  unsigned _ha_bkt;                                                              \
  (head)->hh.tbl->num_items++;                                                   \
  HASH_TO_BKT(hashval, (head)->hh.tbl->num_buckets, _ha_bkt);                    \
  HASH_ADD_TO_BKT((head)->hh.tbl->buckets[_ha_bkt], hh, &(add)->hh, oomed);      \
  HASH_BLOOM_ADD((head)->hh.tbl, hashval);                                       \
  HASH_EMIT_KEY(hh, head, keyptr, keylen_in);                                    \
} while (0)

#endif


#define HASH_ADD_KEYPTR_BYHASHVALUE_INORDER(hh,head,keyptr,keylen_in,hashval,add,cmpfcn) \
do {                                                                             \
  IF_HASH_NONFATAL_OOM( int _ha_oomed = 0; )                                     \
  (add)->hh.hashv = (hashval);                                                   \
  (add)->hh.key = (char*) (keyptr);                                              \
  (add)->hh.keylen = (unsigned) (keylen_in);                                     \
  if (!(head)) {                                                                 \
    (add)->hh.next = NULL;                                                       \
    (add)->hh.prev = NULL;                                                       \
    HASH_MAKE_TABLE(hh, add, _ha_oomed);                                         \
    IF_HASH_NONFATAL_OOM( if (!_ha_oomed) { )                                    \
      (head) = (add);                                                            \
    IF_HASH_NONFATAL_OOM( } )                                                    \
  } else {                                                                       \
    void *_hs_iter = (head);                                                     \
    (add)->hh.tbl = (head)->hh.tbl;                                              \
    HASH_AKBI_INNER_LOOP(hh, head, add, cmpfcn);                                 \
    if (_hs_iter) {                                                              \
      (add)->hh.next = _hs_iter;                                                 \
      if (((add)->hh.prev = HH_FROM_ELMT((head)->hh.tbl, _hs_iter)->prev)) {     \
        HH_FROM_ELMT((head)->hh.tbl, (add)->hh.prev)->next = (add);              \
      } else {                                                                   \
        (head) = (add);                                                          \
      }                                                                          \
      HH_FROM_ELMT((head)->hh.tbl, _hs_iter)->prev = (add);                      \
    } else {                                                                     \
      HASH_APPEND_LIST(hh, head, add);                                           \
    }                                                                            \
  }                                                                              \
  HASH_ADD_TO_TABLE(hh, head, keyptr, keylen_in, hashval, add, _ha_oomed);       \
  HASH_FSCK(hh, head, "HASH_ADD_KEYPTR_BYHASHVALUE_INORDER");                    \
} while (0)

#define HASH_ADD_KEYPTR_INORDER(hh,head,keyptr,keylen_in,add,cmpfcn)             \
do {                                                                             \
  unsigned _hs_hashv;                                                            \
  HASH_VALUE(keyptr, keylen_in, _hs_hashv);                                      \
  HASH_ADD_KEYPTR_BYHASHVALUE_INORDER(hh, head, keyptr, keylen_in, _hs_hashv, add, cmpfcn); \
} while (0)

#define HASH_ADD_BYHASHVALUE_INORDER(hh,head,fieldname,keylen_in,hashval,add,cmpfcn) \
  HASH_ADD_KEYPTR_BYHASHVALUE_INORDER(hh, head, &((add)->fieldname), keylen_in, hashval, add, cmpfcn)

#define HASH_ADD_INORDER(hh,head,fieldname,keylen_in,add,cmpfcn)                 \
  HASH_ADD_KEYPTR_INORDER(hh, head, &((add)->fieldname), keylen_in, add, cmpfcn)

#define HASH_ADD_KEYPTR_BYHASHVALUE(hh,head,keyptr,keylen_in,hashval,add)        \
do {                                                                             \
  IF_HASH_NONFATAL_OOM( int _ha_oomed = 0; )                                     \
  (add)->hh.hashv = (hashval);                                                   \
  (add)->hh.key = (const void*) (keyptr);                                        \
  (add)->hh.keylen = (unsigned) (keylen_in);                                     \
  if (!(head)) {                                                                 \
    (add)->hh.next = NULL;                                                       \
    (add)->hh.prev = NULL;                                                       \
    HASH_MAKE_TABLE(hh, add, _ha_oomed);                                         \
    IF_HASH_NONFATAL_OOM( if (!_ha_oomed) { )                                    \
      (head) = (add);                                                            \
    IF_HASH_NONFATAL_OOM( } )                                                    \
  } else {                                                                       \
    (add)->hh.tbl = (head)->hh.tbl;                                              \
    HASH_APPEND_LIST(hh, head, add);                                             \
  }                                                                              \
  HASH_ADD_TO_TABLE(hh, head, keyptr, keylen_in, hashval, add, _ha_oomed);       \
  HASH_FSCK(hh, head, "HASH_ADD_KEYPTR_BYHASHVALUE");                            \
} while (0)

#define HASH_ADD_KEYPTR(hh,head,keyptr,keylen_in,add)                            \
do {                                                                             \
  unsigned _ha_hashv;                                                            \
  HASH_VALUE(keyptr, keylen_in, _ha_hashv);                                      \
  HASH_ADD_KEYPTR_BYHASHVALUE(hh, head, keyptr, keylen_in, _ha_hashv, add);      \
} while (0)

#define HASH_ADD_BYHASHVALUE(hh,head,fieldname,keylen_in,hashval,add)            \
  HASH_ADD_KEYPTR_BYHASHVALUE(hh, head, &((add)->fieldname), keylen_in, hashval, add)

#define HASH_ADD(hh,head,fieldname,keylen_in,add)                                \
  HASH_ADD_KEYPTR(hh, head, &((add)->fieldname), keylen_in, add)

#define HASH_TO_BKT(hashv,num_bkts,bkt)                                          \
do {                                                                             \
  bkt = ((hashv) & ((num_bkts) - 1U));                                           \
} while (0)

/* delete "delptr" from the hash table.
 * "the usual" patch-up process for the app-order doubly-linked-list.
 * The use of _hd_hh_del below deserves special explanation.
 * These used to be expressed using (delptr) but that led to a bug
 * if someone used the same symbol for the head and deletee, like
 *  HASH_DELETE(hh,users,users);
 * We want that to work, but by changing the head (users) below
 * we were forfeiting our ability to further refer to the deletee (users)
 * in the patch-up process. Solution: use scratch space to
 * copy the deletee pointer, then the latter references are via that
 * scratch pointer rather than through the repointed (users) symbol.
 */
#define HASH_DELETE(hh,head,delptr)                                              \
    HASH_DELETE_HH(hh, head, &(delptr)->hh)

#define HASH_DELETE_HH(hh,head,delptrhh)                                         \
do {                                                                             \
  const struct UT_hash_handle *_hd_hh_del = (delptrhh);                          \
  if ((_hd_hh_del->prev == NULL) && (_hd_hh_del->next == NULL)) {                \
    HASH_BLOOM_FREE((head)->hh.tbl);                                             \
    uthash_free((head)->hh.tbl->buckets,                                         \
                (head)->hh.tbl->num_buckets * sizeof(struct UT_hash_bucket));    \
    uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                          \
    (head) = NULL;                                                               \
  } else {                                                                       \
    unsigned _hd_bkt;                                                            \
    if (_hd_hh_del == (head)->hh.tbl->tail) {                                    \
      (head)->hh.tbl->tail = HH_FROM_ELMT((head)->hh.tbl, _hd_hh_del->prev);     \
    }                                                                            \
    if (_hd_hh_del->prev != NULL) {                                              \
      HH_FROM_ELMT((head)->hh.tbl, _hd_hh_del->prev)->next = _hd_hh_del->next;   \
    } else {                                                                     \
      DECLTYPE_ASSIGN(head, _hd_hh_del->next);                                   \
    }                                                                            \
    if (_hd_hh_del->next != NULL) {                                              \
      HH_FROM_ELMT((head)->hh.tbl, _hd_hh_del->next)->prev = _hd_hh_del->prev;   \
    }                                                                            \
    HASH_TO_BKT(_hd_hh_del->hashv, (head)->hh.tbl->num_buckets, _hd_bkt);        \
    HASH_DEL_IN_BKT((head)->hh.tbl->buckets[_hd_bkt], _hd_hh_del);               \
    (head)->hh.tbl->num_items--;                                                 \
  }                                                                              \
  HASH_FSCK(hh, head, "HASH_DELETE_HH");                                         \
} while (0)

/* convenience forms of HASH_FIND/HASH_ADD/HASH_DEL */
#define HASH_FIND_STR(head,findstr,out)                                          \
do {                                                                             \
    unsigned _uthash_hfstr_keylen = (unsigned)uthash_strlen(findstr);            \
    HASH_FIND(hh, head, findstr, _uthash_hfstr_keylen, out);                     \
} while (0)
#define HASH_ADD_STR(head,strfield,add)                                          \
do {                                                                             \
    unsigned _uthash_hastr_keylen = (unsigned)uthash_strlen((add)->strfield);    \
    HASH_ADD(hh, head, strfield[0], _uthash_hastr_keylen, add);                  \
} while (0)
#define HASH_REPLACE_STR(head,strfield,add,replaced)                             \
do {                                                                             \
    unsigned _uthash_hrstr_keylen = (unsigned)uthash_strlen((add)->strfield);    \
    HASH_REPLACE(hh, head, strfield[0], _uthash_hrstr_keylen, add, replaced);    \
} while (0)
#define HASH_FIND_INT(head,findint,out)                                          \
    HASH_FIND(hh,head,findint,sizeof(int),out)
#define HASH_ADD_INT(head,intfield,add)                                          \
    HASH_ADD(hh,head,intfield,sizeof(int),add)
#define HASH_REPLACE_INT(head,intfield,add,replaced)                             \
    HASH_REPLACE(hh,head,intfield,sizeof(int),add,replaced)
#define HASH_FIND_PTR(head,findptr,out)                                          \
    HASH_FIND(hh,head,findptr,sizeof(void *),out)
#define HASH_ADD_PTR(head,ptrfield,add)                                          \
    HASH_ADD(hh,head,ptrfield,sizeof(void *),add)
#define HASH_REPLACE_PTR(head,ptrfield,add,replaced)                             \
    HASH_REPLACE(hh,head,ptrfield,sizeof(void *),add,replaced)
#define HASH_DEL(head,delptr)                                                    \
    HASH_DELETE(hh,head,delptr)

/* HASH_FSCK checks hash integrity on every add/delete when HASH_DEBUG is defined.
 * This is for uthash developer only; it compiles away if HASH_DEBUG isn't defined.
 */
#ifdef HASH_DEBUG
#include <stdio.h>   /* fprintf, stderr */
#define HASH_OOPS(...) do { fprintf(stderr, __VA_ARGS__); exit(-1); } while (0)
#define HASH_FSCK(hh,head,where)                                                 \
do {                                                                             \
  struct UT_hash_handle *_thh;                                                   \
  if (head) {                                                                    \
    unsigned _bkt_i;                                                             \
    unsigned _count = 0;                                                         \
    char *_prev;                                                                 \
    for (_bkt_i = 0; _bkt_i < (head)->hh.tbl->num_buckets; ++_bkt_i) {           \
      unsigned _bkt_count = 0;                                                   \
      _thh = (head)->hh.tbl->buckets[_bkt_i].hh_head;                            \
      _prev = NULL;                                                              \
      while (_thh) {                                                             \
        if (_prev != (char*)(_thh->hh_prev)) {                                   \
          HASH_OOPS("%s: invalid hh_prev %p, actual %p\n",                       \
              (where), (void*)_thh->hh_prev, (void*)_prev);                      \
        }                                                                        \
        _bkt_count++;                                                            \
        _prev = (char*)(_thh);                                                   \
        _thh = _thh->hh_next;                                                    \
      }                                                                          \
      _count += _bkt_count;                                                      \
      if ((head)->hh.tbl->buckets[_bkt_i].count !=  _bkt_count) {                \
        HASH_OOPS("%s: invalid bucket count %u, actual %u\n",                    \
            (where), (head)->hh.tbl->buckets[_bkt_i].count, _bkt_count);         \
      }                                                                          \
    }                                                                            \
    if (_count != (head)->hh.tbl->num_items) {                                   \
      HASH_OOPS("%s: invalid hh item count %u, actual %u\n",                     \
          (where), (head)->hh.tbl->num_items, _count);                           \
    }                                                                            \
    _count = 0;                                                                  \
    _prev = NULL;                                                                \
    _thh =  &(head)->hh;                                                         \
    while (_thh) {                                                               \
      _count++;                                                                  \
      if (_prev != (char*)_thh->prev) {                                          \
        HASH_OOPS("%s: invalid prev %p, actual %p\n",                            \
            (where), (void*)_thh->prev, (void*)_prev);                           \
      }                                                                          \
      _prev = (char*)ELMT_FROM_HH((head)->hh.tbl, _thh);                         \
      _thh = (_thh->next ? HH_FROM_ELMT((head)->hh.tbl, _thh->next) : NULL);     \
    }                                                                            \
    if (_count != (head)->hh.tbl->num_items) {                                   \
      HASH_OOPS("%s: invalid app item count %u, actual %u\n",                    \
          (where), (head)->hh.tbl->num_items, _count);                           \
    }                                                                            \
  }                                                                              \
} while (0)
#else
#define HASH_FSCK(hh,head,where)
#endif

/* When compiled with -DHASH_EMIT_KEYS, length-prefixed keys are emitted to
 * the descriptor to which this macro is defined for tuning the hash function.
 * The app can #include <unistd.h> to get the prototype for write(2). */
#ifdef HASH_EMIT_KEYS
#define HASH_EMIT_KEY(hh,head,keyptr,fieldlen)                                   \
do {                                                                             \
  unsigned _klen = fieldlen;                                                     \
  write(HASH_EMIT_KEYS, &_klen, sizeof(_klen));                                  \
  write(HASH_EMIT_KEYS, keyptr, (unsigned long)fieldlen);                        \
} while (0)
#else
#define HASH_EMIT_KEY(hh,head,keyptr,fieldlen)
#endif

/* The Bernstein hash function, used in Perl prior to v5.6. Note (x<<5+x)=x*33. */
#define HASH_BER(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _hb_keylen = (unsigned)keylen;                                        \
  const unsigned char *_hb_key = (const unsigned char*)(key);                    \
  (hashv) = 0;                                                                   \
  while (_hb_keylen-- != 0U) {                                                   \
    (hashv) = (((hashv) << 5) + (hashv)) + *_hb_key++;                           \
  }                                                                              \
} while (0)


/* SAX/FNV/OAT/JEN hash functions are macro variants of those listed at
 * http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx
 * (archive link: https://archive.is/Ivcan )
 */
#define HASH_SAX(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _sx_i;                                                                \
  const unsigned char *_hs_key = (const unsigned char*)(key);                    \
  hashv = 0;                                                                     \
  for (_sx_i=0; _sx_i < keylen; _sx_i++) {                                       \
    hashv ^= (hashv << 5) + (hashv >> 2) + _hs_key[_sx_i];                       \
  }                                                                              \
} while (0)
/* FNV-1a variation */
#define HASH_FNV(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _fn_i;                                                                \
  const unsigned char *_hf_key = (const unsigned char*)(key);                    \
  (hashv) = 2166136261U;                                                         \
  for (_fn_i=0; _fn_i < keylen; _fn_i++) {                                       \
    hashv = hashv ^ _hf_key[_fn_i];                                              \
    hashv = hashv * 16777619U;                                                   \
  }                                                                              \
} while (0)

#define HASH_OAT(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _ho_i;                                                                \
  const unsigned char *_ho_key=(const unsigned char*)(key);                      \
  hashv = 0;                                                                     \
  for(_ho_i=0; _ho_i < keylen; _ho_i++) {                                        \
      hashv += _ho_key[_ho_i];                                                   \
      hashv += (hashv << 10);                                                    \
      hashv ^= (hashv >> 6);                                                     \
  }                                                                              \
  hashv += (hashv << 3);                                                         \
  hashv ^= (hashv >> 11);                                                        \
  hashv += (hashv << 15);                                                        \
} while (0)

#define HASH_JEN_MIX(a,b,c)                                                      \
do {                                                                             \
  a -= b; a -= c; a ^= ( c >> 13 );                                              \
  b -= c; b -= a; b ^= ( a << 8 );                                               \
  c -= a; c -= b; c ^= ( b >> 13 );                                              \
  a -= b; a -= c; a ^= ( c >> 12 );                                              \
  b -= c; b -= a; b ^= ( a << 16 );                                              \
  c -= a; c -= b; c ^= ( b >> 5 );                                               \
  a -= b; a -= c; a ^= ( c >> 3 );                                               \
  b -= c; b -= a; b ^= ( a << 10 );                                              \
  c -= a; c -= b; c ^= ( b >> 15 );                                              \
} while (0)

#define HASH_JEN(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned _hj_i,_hj_j,_hj_k;                                                    \
  unsigned const char *_hj_key=(unsigned const char*)(key);                      \
  hashv = 0xfeedbeefu;                                                           \
  _hj_i = _hj_j = 0x9e3779b9u;                                                   \
  _hj_k = (unsigned)(keylen);                                                    \
  while (_hj_k >= 12U) {                                                         \
    _hj_i +=    (_hj_key[0] + ( (unsigned)_hj_key[1] << 8 )                      \
        + ( (unsigned)_hj_key[2] << 16 )                                         \
        + ( (unsigned)_hj_key[3] << 24 ) );                                      \
    _hj_j +=    (_hj_key[4] + ( (unsigned)_hj_key[5] << 8 )                      \
        + ( (unsigned)_hj_key[6] << 16 )                                         \
        + ( (unsigned)_hj_key[7] << 24 ) );                                      \
    hashv += (_hj_key[8] + ( (unsigned)_hj_key[9] << 8 )                         \
        + ( (unsigned)_hj_key[10] << 16 )                                        \
        + ( (unsigned)_hj_key[11] << 24 ) );                                     \
                                                                                 \
     HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                          \
                                                                                 \
     _hj_key += 12;                                                              \
     _hj_k -= 12U;                                                               \
  }                                                                              \
  hashv += (unsigned)(keylen);                                                   \
  switch ( _hj_k ) {                                                             \
    case 11: hashv += ( (unsigned)_hj_key[10] << 24 ); /* FALLTHROUGH */         \
    case 10: hashv += ( (unsigned)_hj_key[9] << 16 );  /* FALLTHROUGH */         \
    case 9:  hashv += ( (unsigned)_hj_key[8] << 8 );   /* FALLTHROUGH */         \
    case 8:  _hj_j += ( (unsigned)_hj_key[7] << 24 );  /* FALLTHROUGH */         \
    case 7:  _hj_j += ( (unsigned)_hj_key[6] << 16 );  /* FALLTHROUGH */         \
    case 6:  _hj_j += ( (unsigned)_hj_key[5] << 8 );   /* FALLTHROUGH */         \
    case 5:  _hj_j += _hj_key[4];                      /* FALLTHROUGH */         \
    case 4:  _hj_i += ( (unsigned)_hj_key[3] << 24 );  /* FALLTHROUGH */         \
    case 3:  _hj_i += ( (unsigned)_hj_key[2] << 16 );  /* FALLTHROUGH */         \
    case 2:  _hj_i += ( (unsigned)_hj_key[1] << 8 );   /* FALLTHROUGH */         \
    case 1:  _hj_i += _hj_key[0];                      /* FALLTHROUGH */         \
    default: ;                                                                   \
  }                                                                              \
  HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                             \
} while (0)

/* The Paul Hsieh hash function */
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__)             \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)             \
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif
#define HASH_SFH(key,keylen,hashv)                                               \
do {                                                                             \
  unsigned const char *_sfh_key=(unsigned const char*)(key);                     \
  uint32_t _sfh_tmp, _sfh_len = (uint32_t)keylen;                                \
                                                                                 \
  unsigned _sfh_rem = _sfh_len & 3U;                                             \
  _sfh_len >>= 2;                                                                \
  hashv = 0xcafebabeu;                                                           \
                                                                                 \
  /* Main loop */                                                                \
  for (;_sfh_len > 0U; _sfh_len--) {                                             \
    hashv    += get16bits (_sfh_key);                                            \
    _sfh_tmp  = ((uint32_t)(get16bits (_sfh_key+2)) << 11) ^ hashv;              \
    hashv     = (hashv << 16) ^ _sfh_tmp;                                        \
    _sfh_key += 2U*sizeof (uint16_t);                                            \
    hashv    += hashv >> 11;                                                     \
  }                                                                              \
                                                                                 \
  /* Handle end cases */                                                         \
  switch (_sfh_rem) {                                                            \
    case 3: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 16;                                                \
            hashv ^= (uint32_t)(_sfh_key[sizeof (uint16_t)]) << 18;              \
            hashv += hashv >> 11;                                                \
            break;                                                               \
    case 2: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 11;                                                \
            hashv += hashv >> 17;                                                \
            break;                                                               \
    case 1: hashv += *_sfh_key;                                                  \
            hashv ^= hashv << 10;                                                \
            hashv += hashv >> 1;                                                 \
            break;                                                               \
    default: ;                                                                   \
  }                                                                              \
                                                                                 \
  /* Force "avalanching" of final 127 bits */                                    \
  hashv ^= hashv << 3;                                                           \
  hashv += hashv >> 5;                                                           \
  hashv ^= hashv << 4;                                                           \
  hashv += hashv >> 17;                                                          \
  hashv ^= hashv << 25;                                                          \
  hashv += hashv >> 6;                                                           \
} while (0)

/* iterate over items in a known bucket to find desired item */
#define HASH_FIND_IN_BKT(tbl,hh,head,keyptr,keylen_in,hashval,out)               \
do {                                                                             \
  if ((head).hh_head != NULL) {                                                  \
    DECLTYPE_ASSIGN(out, ELMT_FROM_HH(tbl, (head).hh_head));                     \
  } else {                                                                       \
    (out) = NULL;                                                                \
  }                                                                              \
  while ((out) != NULL) {                                                        \
    if ((out)->hh.hashv == (hashval) && (out)->hh.keylen == (keylen_in)) {       \
      if (HASH_KEYCMP((out)->hh.key, keyptr, keylen_in) == 0) {                  \
        break;                                                                   \
      }                                                                          \
    }                                                                            \
    if ((out)->hh.hh_next != NULL) {                                             \
      DECLTYPE_ASSIGN(out, ELMT_FROM_HH(tbl, (out)->hh.hh_next));                \
    } else {                                                                     \
      (out) = NULL;                                                              \
    }                                                                            \
  }                                                                              \
} while (0)

/* add an item to a bucket  */
#define HASH_ADD_TO_BKT(head,hh,addhh,oomed)                                     \
do {                                                                             \
  UT_hash_bucket *_ha_head = &(head);                                            \
  _ha_head->count++;                                                             \
  (addhh)->hh_next = _ha_head->hh_head;                                          \
  (addhh)->hh_prev = NULL;                                                       \
  if (_ha_head->hh_head != NULL) {                                               \
    _ha_head->hh_head->hh_prev = (addhh);                                        \
  }                                                                              \
  _ha_head->hh_head = (addhh);                                                   \
  if ((_ha_head->count >= ((_ha_head->expand_mult + 1U) * HASH_BKT_CAPACITY_THRESH)) \
      && !(addhh)->tbl->noexpand) {                                              \
    HASH_EXPAND_BUCKETS(addhh,(addhh)->tbl, oomed);                              \
    IF_HASH_NONFATAL_OOM(                                                        \
      if (oomed) {                                                               \
        HASH_DEL_IN_BKT(head,addhh);                                             \
      }                                                                          \
    )                                                                            \
  }                                                                              \
} while (0)

/* remove an item from a given bucket */
#define HASH_DEL_IN_BKT(head,delhh)                                              \
do {                                                                             \
  UT_hash_bucket *_hd_head = &(head);                                            \
  _hd_head->count--;                                                             \
  if (_hd_head->hh_head == (delhh)) {                                            \
    _hd_head->hh_head = (delhh)->hh_next;                                        \
  }                                                                              \
  if ((delhh)->hh_prev) {                                                        \
    (delhh)->hh_prev->hh_next = (delhh)->hh_next;                                \
  }                                                                              \
  if ((delhh)->hh_next) {                                                        \
    (delhh)->hh_next->hh_prev = (delhh)->hh_prev;                                \
  }                                                                              \
} while (0)

/* Bucket expansion has the effect of doubling the number of buckets
 * and redistributing the items into the new buckets. Ideally the
 * items will distribute more or less evenly into the new buckets
 * (the extent to which this is true is a measure of the quality of
 * the hash function as it applies to the key domain).
 *
 * With the items distributed into more buckets, the chain length
 * (item count) in each bucket is reduced. Thus by expanding buckets
 * the hash keeps a bound on the chain length. This bounded chain
 * length is the essence of how a hash provides constant time lookup.
 *
 * The calculation of tbl->ideal_chain_maxlen below deserves some
 * explanation. First, keep in mind that we're calculating the ideal
 * maximum chain length based on the *new* (doubled) bucket count.
 * In fractions this is just n/b (n=number of items,b=new num buckets).
 * Since the ideal chain length is an integer, we want to calculate
 * ceil(n/b). We don't depend on floating point arithmetic in this
 * hash, so to calculate ceil(n/b) with integers we could write
 *
 *      ceil(n/b) = (n/b) + ((n%b)?1:0)
 *
 * and in fact a previous version of this hash did just that.
 * But now we have improved things a bit by recognizing that b is
 * always a power of two. We keep its base 2 log handy (call it lb),
 * so now we can write this with a bit shift and logical AND:
 *
 *      ceil(n/b) = (n>>lb) + ( (n & (b-1)) ? 1:0)
 *
 */
#define HASH_EXPAND_BUCKETS(hh,tbl,oomed)                                        \
do {                                                                             \
  unsigned _he_bkt;                                                              \
  unsigned _he_bkt_i;                                                            \
  struct UT_hash_handle *_he_thh, *_he_hh_nxt;                                   \
  UT_hash_bucket *_he_new_buckets, *_he_newbkt;                                  \
  _he_new_buckets = (UT_hash_bucket*)uthash_malloc(                              \
           sizeof(struct UT_hash_bucket) * (tbl)->num_buckets * 2U);             \
  if (!_he_new_buckets) {                                                        \
    HASH_RECORD_OOM(oomed);                                                      \
  } else {                                                                       \
    uthash_bzero(_he_new_buckets,                                                \
        sizeof(struct UT_hash_bucket) * (tbl)->num_buckets * 2U);                \
    (tbl)->ideal_chain_maxlen =                                                  \
       ((tbl)->num_items >> ((tbl)->log2_num_buckets+1U)) +                      \
       ((((tbl)->num_items & (((tbl)->num_buckets*2U)-1U)) != 0U) ? 1U : 0U);    \
    (tbl)->nonideal_items = 0;                                                   \
    for (_he_bkt_i = 0; _he_bkt_i < (tbl)->num_buckets; _he_bkt_i++) {           \
      _he_thh = (tbl)->buckets[ _he_bkt_i ].hh_head;                             \
      while (_he_thh != NULL) {                                                  \
        _he_hh_nxt = _he_thh->hh_next;                                           \
        HASH_TO_BKT(_he_thh->hashv, (tbl)->num_buckets * 2U, _he_bkt);           \
        _he_newbkt = &(_he_new_buckets[_he_bkt]);                                \
        if (++(_he_newbkt->count) > (tbl)->ideal_chain_maxlen) {                 \
          (tbl)->nonideal_items++;                                               \
          if (_he_newbkt->count > _he_newbkt->expand_mult * (tbl)->ideal_chain_maxlen) { \
            _he_newbkt->expand_mult++;                                           \
          }                                                                      \
        }                                                                        \
        _he_thh->hh_prev = NULL;                                                 \
        _he_thh->hh_next = _he_newbkt->hh_head;                                  \
        if (_he_newbkt->hh_head != NULL) {                                       \
          _he_newbkt->hh_head->hh_prev = _he_thh;                                \
        }                                                                        \
        _he_newbkt->hh_head = _he_thh;                                           \
        _he_thh = _he_hh_nxt;                                                    \
      }                                                                          \
    }                                                                            \
    uthash_free((tbl)->buckets, (tbl)->num_buckets * sizeof(struct UT_hash_bucket)); \
    (tbl)->num_buckets *= 2U;                                                    \
    (tbl)->log2_num_buckets++;                                                   \
    (tbl)->buckets = _he_new_buckets;                                            \
    (tbl)->ineff_expands = ((tbl)->nonideal_items > ((tbl)->num_items >> 1)) ?   \
        ((tbl)->ineff_expands+1U) : 0U;                                          \
    if ((tbl)->ineff_expands > 1U) {                                             \
      (tbl)->noexpand = 1;                                                       \
      uthash_noexpand_fyi(tbl);                                                  \
    }                                                                            \
    uthash_expand_fyi(tbl);                                                      \
  }                                                                              \
} while (0)


/* This is an adaptation of Simon Tatham's O(n log(n)) mergesort */
/* Note that HASH_SORT assumes the hash handle name to be hh.
 * HASH_SRT was added to allow the hash handle name to be passed in. */
#define HASH_SORT(head,cmpfcn) HASH_SRT(hh,head,cmpfcn)
#define HASH_SRT(hh,head,cmpfcn)                                                 \
do {                                                                             \
  unsigned _hs_i;                                                                \
  unsigned _hs_looping,_hs_nmerges,_hs_insize,_hs_psize,_hs_qsize;               \
  struct UT_hash_handle *_hs_p, *_hs_q, *_hs_e, *_hs_list, *_hs_tail;            \
  if (head != NULL) {                                                            \
    _hs_insize = 1;                                                              \
    _hs_looping = 1;                                                             \
    _hs_list = &((head)->hh);                                                    \
    while (_hs_looping != 0U) {                                                  \
      _hs_p = _hs_list;                                                          \
      _hs_list = NULL;                                                           \
      _hs_tail = NULL;                                                           \
      _hs_nmerges = 0;                                                           \
      while (_hs_p != NULL) {                                                    \
        _hs_nmerges++;                                                           \
        _hs_q = _hs_p;                                                           \
        _hs_psize = 0;                                                           \
        for (_hs_i = 0; _hs_i < _hs_insize; ++_hs_i) {                           \
          _hs_psize++;                                                           \
          _hs_q = ((_hs_q->next != NULL) ?                                       \
            HH_FROM_ELMT((head)->hh.tbl, _hs_q->next) : NULL);                   \
          if (_hs_q == NULL) {                                                   \
            break;                                                               \
          }                                                                      \
        }                                                                        \
        _hs_qsize = _hs_insize;                                                  \
        while ((_hs_psize != 0U) || ((_hs_qsize != 0U) && (_hs_q != NULL))) {    \
          if (_hs_psize == 0U) {                                                 \
            _hs_e = _hs_q;                                                       \
            _hs_q = ((_hs_q->next != NULL) ?                                     \
              HH_FROM_ELMT((head)->hh.tbl, _hs_q->next) : NULL);                 \
            _hs_qsize--;                                                         \
          } else if ((_hs_qsize == 0U) || (_hs_q == NULL)) {                     \
            _hs_e = _hs_p;                                                       \
            if (_hs_p != NULL) {                                                 \
              _hs_p = ((_hs_p->next != NULL) ?                                   \
                HH_FROM_ELMT((head)->hh.tbl, _hs_p->next) : NULL);               \
            }                                                                    \
            _hs_psize--;                                                         \
          } else if ((cmpfcn(                                                    \
                DECLTYPE(head)(ELMT_FROM_HH((head)->hh.tbl, _hs_p)),             \
                DECLTYPE(head)(ELMT_FROM_HH((head)->hh.tbl, _hs_q))              \
                )) <= 0) {                                                       \
            _hs_e = _hs_p;                                                       \
            if (_hs_p != NULL) {                                                 \
              _hs_p = ((_hs_p->next != NULL) ?                                   \
                HH_FROM_ELMT((head)->hh.tbl, _hs_p->next) : NULL);               \
            }                                                                    \
            _hs_psize--;                                                         \
          } else {                                                               \
            _hs_e = _hs_q;                                                       \
            _hs_q = ((_hs_q->next != NULL) ?                                     \
              HH_FROM_ELMT((head)->hh.tbl, _hs_q->next) : NULL);                 \
            _hs_qsize--;                                                         \
          }                                                                      \
          if ( _hs_tail != NULL ) {                                              \
            _hs_tail->next = ((_hs_e != NULL) ?                                  \
              ELMT_FROM_HH((head)->hh.tbl, _hs_e) : NULL);                       \
          } else {                                                               \
            _hs_list = _hs_e;                                                    \
          }                                                                      \
          if (_hs_e != NULL) {                                                   \
            _hs_e->prev = ((_hs_tail != NULL) ?                                  \
              ELMT_FROM_HH((head)->hh.tbl, _hs_tail) : NULL);                    \
          }                                                                      \
          _hs_tail = _hs_e;                                                      \
        }                                                                        \
        _hs_p = _hs_q;                                                           \
      }                                                                          \
      if (_hs_tail != NULL) {                                                    \
        _hs_tail->next = NULL;                                                   \
      }                                                                          \
      if (_hs_nmerges <= 1U) {                                                   \
        _hs_looping = 0;                                                         \
        (head)->hh.tbl->tail = _hs_tail;                                         \
        DECLTYPE_ASSIGN(head, ELMT_FROM_HH((head)->hh.tbl, _hs_list));           \
      }                                                                          \
      _hs_insize *= 2U;                                                          \
    }                                                                            \
    HASH_FSCK(hh, head, "HASH_SRT");                                             \
  }                                                                              \
} while (0)

/* This function selects items from one hash into another hash.
 * The end result is that the selected items have dual presence
 * in both hashes. There is no copy of the items made; rather
 * they are added into the new hash through a secondary hash
 * hash handle that must be present in the structure. */
#define HASH_SELECT(hh_dst, dst, hh_src, src, cond)                              \
do {                                                                             \
  unsigned _src_bkt, _dst_bkt;                                                   \
  void *_last_elt = NULL, *_elt;                                                 \
  UT_hash_handle *_src_hh, *_dst_hh, *_last_elt_hh=NULL;                         \
  ptrdiff_t _dst_hho = ((char*)(&(dst)->hh_dst) - (char*)(dst));                 \
  if ((src) != NULL) {                                                           \
    for (_src_bkt=0; _src_bkt < (src)->hh_src.tbl->num_buckets; _src_bkt++) {    \
      for (_src_hh = (src)->hh_src.tbl->buckets[_src_bkt].hh_head;               \
        _src_hh != NULL;                                                         \
        _src_hh = _src_hh->hh_next) {                                            \
        _elt = ELMT_FROM_HH((src)->hh_src.tbl, _src_hh);                         \
        if (cond(_elt)) {                                                        \
          IF_HASH_NONFATAL_OOM( int _hs_oomed = 0; )                             \
          _dst_hh = (UT_hash_handle*)(void*)(((char*)_elt) + _dst_hho);          \
          _dst_hh->key = _src_hh->key;                                           \
          _dst_hh->keylen = _src_hh->keylen;                                     \
          _dst_hh->hashv = _src_hh->hashv;                                       \
          _dst_hh->prev = _last_elt;                                             \
          _dst_hh->next = NULL;                                                  \
          if (_last_elt_hh != NULL) {                                            \
            _last_elt_hh->next = _elt;                                           \
          }                                                                      \
          if ((dst) == NULL) {                                                   \
            DECLTYPE_ASSIGN(dst, _elt);                                          \
            HASH_MAKE_TABLE(hh_dst, dst, _hs_oomed);                             \
            IF_HASH_NONFATAL_OOM(                                                \
              if (_hs_oomed) {                                                   \
                uthash_nonfatal_oom(_elt);                                       \
                (dst) = NULL;                                                    \
                continue;                                                        \
              }                                                                  \
            )                                                                    \
          } else {                                                               \
            _dst_hh->tbl = (dst)->hh_dst.tbl;                                    \
          }                                                                      \
          HASH_TO_BKT(_dst_hh->hashv, _dst_hh->tbl->num_buckets, _dst_bkt);      \
          HASH_ADD_TO_BKT(_dst_hh->tbl->buckets[_dst_bkt], hh_dst, _dst_hh, _hs_oomed); \
          (dst)->hh_dst.tbl->num_items++;                                        \
          IF_HASH_NONFATAL_OOM(                                                  \
            if (_hs_oomed) {                                                     \
              HASH_ROLLBACK_BKT(hh_dst, dst, _dst_hh);                           \
              HASH_DELETE_HH(hh_dst, dst, _dst_hh);                              \
              _dst_hh->tbl = NULL;                                               \
              uthash_nonfatal_oom(_elt);                                         \
              continue;                                                          \
            }                                                                    \
          )                                                                      \
          HASH_BLOOM_ADD(_dst_hh->tbl, _dst_hh->hashv);                          \
          _last_elt = _elt;                                                      \
          _last_elt_hh = _dst_hh;                                                \
        }                                                                        \
      }                                                                          \
    }                                                                            \
  }                                                                              \
  HASH_FSCK(hh_dst, dst, "HASH_SELECT");                                         \
} while (0)

#define HASH_CLEAR(hh,head)                                                      \
do {                                                                             \
  if ((head) != NULL) {                                                          \
    HASH_BLOOM_FREE((head)->hh.tbl);                                             \
    uthash_free((head)->hh.tbl->buckets,                                         \
                (head)->hh.tbl->num_buckets*sizeof(struct UT_hash_bucket));      \
    uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                          \
    (head) = NULL;                                                               \
  }                                                                              \
} while (0)

#define HASH_OVERHEAD(hh,head)                                                   \
 (((head) != NULL) ? (                                                           \
 (size_t)(((head)->hh.tbl->num_items   * sizeof(UT_hash_handle))   +             \
          ((head)->hh.tbl->num_buckets * sizeof(UT_hash_bucket))   +             \
           sizeof(UT_hash_table)                                   +             \
           (HASH_BLOOM_BYTELEN))) : 0U)

#ifdef NO_DECLTYPE
#define HASH_ITER(hh,head,el,tmp)                                                \
for(((el)=(head)), ((*(char**)(&(tmp)))=(char*)((head!=NULL)?(head)->hh.next:NULL)); \
  (el) != NULL; ((el)=(tmp)), ((*(char**)(&(tmp)))=(char*)((tmp!=NULL)?(tmp)->hh.next:NULL)))
#else
#define HASH_ITER(hh,head,el,tmp)                                                \
for(((el)=(head)), ((tmp)=DECLTYPE(el)((head!=NULL)?(head)->hh.next:NULL));      \
  (el) != NULL; ((el)=(tmp)), ((tmp)=DECLTYPE(el)((tmp!=NULL)?(tmp)->hh.next:NULL)))
#endif

/* obtain a count of items in the hash */
#define HASH_COUNT(head) HASH_CNT(hh,head)
#define HASH_CNT(hh,head) ((head != NULL)?((head)->hh.tbl->num_items):0U)

typedef struct UT_hash_bucket {
   struct UT_hash_handle *hh_head;
   unsigned count;

   /* expand_mult is normally set to 0. In this situation, the max chain length
    * threshold is enforced at its default value, HASH_BKT_CAPACITY_THRESH. (If
    * the bucket's chain exceeds this length, bucket expansion is triggered).
    * However, setting expand_mult to a non-zero value delays bucket expansion
    * (that would be triggered by additions to this particular bucket)
    * until its chain length reaches a *multiple* of HASH_BKT_CAPACITY_THRESH.
    * (The multiplier is simply expand_mult+1). The whole idea of this
    * multiplier is to reduce bucket expansions, since they are expensive, in
    * situations where we know that a particular bucket tends to be overused.
    * It is better to let its chain length grow to a longer yet-still-bounded
    * value, than to do an O(n) bucket expansion too often.
    */
   unsigned expand_mult;

} UT_hash_bucket;

/* random signature used only to find hash tables in external analysis */
#define HASH_SIGNATURE 0xa0111fe1u
#define HASH_BLOOM_SIGNATURE 0xb12220f2u

typedef struct UT_hash_table {
   UT_hash_bucket *buckets;
   unsigned num_buckets, log2_num_buckets;
   unsigned num_items;
   struct UT_hash_handle *tail; /* tail hh in app order, for fast append    */
   ptrdiff_t hho; /* hash handle offset (byte pos of hash handle in element */

   /* in an ideal situation (all buckets used equally), no bucket would have
    * more than ceil(#items/#buckets) items. that's the ideal chain length. */
   unsigned ideal_chain_maxlen;

   /* nonideal_items is the number of items in the hash whose chain position
    * exceeds the ideal chain maxlen. these items pay the penalty for an uneven
    * hash distribution; reaching them in a chain traversal takes >ideal steps */
   unsigned nonideal_items;

   /* ineffective expands occur when a bucket doubling was performed, but
    * afterward, more than half the items in the hash had nonideal chain
    * positions. If this happens on two consecutive expansions we inhibit any
    * further expansion, as it's not helping; this happens when the hash
    * function isn't a good fit for the key domain. When expansion is inhibited
    * the hash will still work, albeit no longer in constant time. */
   unsigned ineff_expands, noexpand;

   uint32_t signature; /* used only to find hash tables in external analysis */
#ifdef HASH_BLOOM
   uint32_t bloom_sig; /* used only to test bloom exists in external analysis */
   uint8_t *bloom_bv;
   uint8_t bloom_nbits;
#endif

} UT_hash_table;

typedef struct UT_hash_handle {
   struct UT_hash_table *tbl;
   void *prev;                       /* prev element in app order      */
   void *next;                       /* next element in app order      */
   struct UT_hash_handle *hh_prev;   /* previous hh in bucket order    */
   struct UT_hash_handle *hh_next;   /* next hh in bucket order        */
   const void *key;                  /* ptr to enclosing struct's key  */
   unsigned keylen;                  /* enclosing struct's key len     */
   unsigned hashv;                   /* result of hash-fcn(key)        */
} UT_hash_handle;

#endif /* UTHASH_H */
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
