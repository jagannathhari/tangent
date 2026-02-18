import os
import sys

from enum import Enum

class TokenType(Enum):
    # paranthesis
    LPARN = "("
    RPARN = ")"

    LSQR_BRC= "["
    RSQR_BRC= "]"

    BLOCK_OPEN = "{"
    BLOCK_CLOSE= "}"

    # arithmatic
    PLUS = "+"
    PLUS_PLUS = "++"
    PLUS_EQUAL = "+="

    MINUS = "-"
    MINUS_MINUS= "--"
    MINUS_EQUAL = "-="

    STAR = "*"
    STAR_STAR= "**"
    STAR_EQUAL = "*="
    
    DIVIDE = "/"
    DIVIDE_DIVIDE= "//"
    DIVIDE_EQUAL = "/="
    
    GREATER = ">"
    GREATER_EQUAL = ">="

    LESS = "<"
    LESS_EQUAL = "<="

    LEFT_SHIFT = "<<"
    RIGHT_SHIFT = ">>"

    EQUAL = "="
    COLON_EQUAL = ":="
    EQUAL_EQUAL = "=="
    NOT_EQUAL = "!="
    AND_EQUAL = "&="
    PIPE_EQUAL = "|="


    NOT = "!"
    POUND = "#"
    MOD = "%"
    CARET = "^"
    PIPE = "|"
    COMMA = ","
    DOT = "."
    DOT_DOT = ".."
    SEMICOLON = ";"
    COLON = ":"
    COLON_COLON = "::"
    AND = "&"
    AND_AND = "&&"

    TILDA = "~"
    QUOTE = '"'
    SINGLE_QUOTE = "'"
    QUESTION = "?"

    #keyword
    I8  ="int8"
    I16 ="int16" 
    I32 ="int32"
    I64 ="int64"

    U8  ="uint8"
    U16 ="uint16" 
    U32 ="uint32"
    U64 ="uint64"
    STR = "str"
    FLOAT = "Float"
    DOUBLE = "Double"

    INT_LITERAL = "integer_constant"
    OCT_LITERAL = "oct_constant"
    HEX_LITERAL = "hex_constant"
    BIN_LITERAL = "bin_constant"
    FLOAT_LITERAL = "float_constant"
    STRING = "String"
    BOOL = "bool"
    FORMATED_STRING = "Formated_string"
    PREFIX = "prefix"

    TRUE = "true"
    FALSE = "false"
    FOR = "for"
    ID = "id"
    EOF = "EOF"

class Token:
    def __init__(self,token_type):
        self.type = token_type 
        self.line = 1
        self.lexeme = "" 
        self.start_pos = 0
        self.line_start = 0

    def __str__(self):
        return f"Token({self.type.name},'{self.lexeme}')"


class Lexer:
    def __init__(self,src):
        self.pos = 0
        self.curr = 0
        self.len = 0
        self.src = src
        self.line = 1
        self.line_start = 0
        self.init_lexer()

    def init_lexer(self):
        if not os.path.isfile(self.src):
            print("Error: File",repr(self.src),"not found.")
            sys.exit(0) 

        with open(self.src,"r") as f:
            self.content = f.read().rstrip()
        self.len = len(self.content)

    def get_state(self):
        return self.pos,self.curr,self.len,self.line,self.line_start

    def set_state(self,state):
        self.pos,self.curr,self.len,self.line,self.line_start = state

    def is_at_end(self):
        return self.len == self.pos

    def match(self,expected):
        if self.is_at_end() or self.content[self.pos] != expected:
            return False
        return True

    def advance(self):
        if self.pos < self.len:
            c = self.content[self.pos]
            self.pos += 1
            return c

    def peek(self):
        if self.is_at_end():
            return ""
        return self.content[self.pos]

    def identifier(self):

        while self.peek().isalnum() or self.peek() == '_':
           self.advance() 
        t = self.build_token(TokenType.ID)

        ids = {"i8":TokenType.I8,
               "i16":TokenType.I16,
               "i32":TokenType.I32,
               "i64":TokenType.I64,
               "U8":TokenType.U8,
               "U16":TokenType.U16,
               "u32":TokenType.U32,
               "u64":TokenType.U64,
               "float":TokenType.FLOAT,
               "double":TokenType.DOUBLE,
               "str":TokenType.STR,
               "bool":TokenType.BOOL,
               "true":TokenType.TRUE,
               "false":TokenType.FALSE,
               "for":TokenType.FOR
               }
        if t.lexeme in ids:
            t.type = ids[t.lexeme]
        return t



    def string(self,close='"'):
        start = self.pos
        while self.peek()!=close and not self.is_at_end():
            c = self.peek()
            match c:
                case '\\':
                    self.advance()
            self.advance()
        self.advance() # consume close
        t = Token(TokenType.STRING if close == '"' else TokenType.FORMATED_STRING)
        t.lexeme = self.content[start:self.pos-1]
        t.line = self.line
        t.line_start = self.line_start
        t.start_pos = self.curr
        self.curr = self.pos
        return t



    def real(self):
        is_float = False
        while not self.is_at_end() and self.peek().isdigit():
            self.advance()
            if self.peek() == '.':
                if is_float:
                    return self.build_token(TokenType.FLOAT_LITERAL)
                is_float = True
                self.advance()
        if is_float:
            return self.build_token(TokenType.FLOAT_LITERAL)
        return self.build_token(TokenType.INT_LITERAL)

    def number(self,first_char):
        base = 0
        allowed = ""
        number_type = TokenType.INT_LITERAL
        if first_char == '0':
            c = self.peek()
            match c:
                case 'x'|'X':
                    base = 16
                    allowed = "0123456789abcdefABCDEF"
                    number_type = TokenType.HEX_LITERAL
                case 'o' | 'O':
                    allowed = "01234567"
                    base = 8
                    number_type = TokenType.OCT_LITERAL
                case 'b': 
                    allowed = "01"
                    base = 2
                    number_type = TokenType.BIN_LITERAL

            number = '0'
            if base != 0:
                number += c
                self.advance()

            while not self.is_at_end() and self.peek() in allowed:
                self.advance()
            return self.build_token(number_type)
        else:
            return self.real()

    def build_token(self,token_type):
        t = Token(token_type)
        t.line = self.line
        t.line_start = self.line_start;
        t.lexeme = self.content[self.curr:self.pos]
        t.start_pos = self.curr
        self.curr = self.pos
        return t

    def next_token(self):
        while self.pos < self.len:
            c = self.advance()
            match c:
                case '!':
                    if self.match('='):
                        self.advance()
                        return self.build_token(TokenType.NOT_EQUAL)
                    else:
                        return self.build_token(TokenType.NOT)
                case '*':
                    # if self.match('*'):
                    #     self.advance()
                    #     return self.build_token(TokenType.STAR_STAR)
                    if self.match('='):
                        self.advance()
                        return self.build_token(TokenType.STAR_EQUAL)
                    else:
                        return self.build_token(TokenType.STAR)
                case '+':
                    if self.match('+'):
                        self.advance()
                        return self.build_token(TokenType.PLUS_PLUS)
                    elif self.match('='):
                        self.advance()
                        return self.build_token(TokenType.PLUS_EQUAL)
                    else:
                        return self.build_token(TokenType.PLUS)
                case '-':
                    if self.match('-'):
                        self.advance()
                        return self.build_token(TokenType.MINUS_MINUS)
                    elif self.match('='):
                        self.advance()
                        return self.build_token(TokenType.MINUS_EQUAL)
                    else:
                        return self.build_token(TokenType.MINUS)
                case '/':
                    if self.match('/'):
                        self.advance()
                        return self.build_token(TokenType.DIVIDE_DIVIDE)
                    elif self.match('='):
                        self.advance()
                        return self.build_token(TokenType.DIVIDE_EQUAL)
                    else:
                        return self.build_token(TokenType.DIVIDE)
                case '=':
                    if self.match('='):
                        self.advance()
                        return self.build_token(TokenType.EQUAL_EQUAL)
                    else:
                        return self.build_token(TokenType.EQUAL)
                case '>':
                    if self.match('='):
                        self.advance()
                        return self.build_token(TokenType.GREATER_EQUAL)
                    elif self.match(">"):
                        self.advance()
                        return self.build_token(TokenType.RIGHT_SHIFT)
                    else:
                        return self.build_token(TokenType.GREATER)
                case '<':
                    if self.match('='):
                        self.advance()
                        return self.build_token(TokenType.LESS_EQUAL)
                    elif self.match("<"):
                        self.advance()
                        return self.build_token(TokenType.LEFT_SHIFT)
                    else:
                        return self.build_token(TokenType.LESS)
                case '(':
                    return self.build_token(TokenType.LPARN)
                case ')':
                    return self.build_token(TokenType.RPARN)
                case '{':
                    return self.build_token(TokenType.BLOCK_OPEN)
                case '}':
                    return self.build_token(TokenType.BLOCK_CLOSE)
                case '[':
                    return self.build_token(TokenType.LSQR_BRC)
                case ']':
                    return self.build_token(TokenType.RSQR_BRC)
                case ',':
                    return self.build_token(TokenType.COMMA)
                case '.':
                    if(self.match('.')):
                        self.advance()
                        return self.build_token(TokenType.DOT_DOT)
                    return self.build_token(TokenType.DOT)
                case ':':
                    if(self.match(':')):
                        self.advance()
                        return self.build_token(TokenType.COLON_COLON)
                    elif(self.match('=')):
                        self.advance()
                        return self.build_token(TokenType.COLON_EQUAL)
                    return self.build_token(TokenType.COLON)
                case '&':
                    if(self.match("&")):
                        return self.build_token(TokenType.AND_AND)
                    return self.build_token(TokenType.AND)
                case '|':
                    if(self.match("=")):
                        self.advance()
                        return self.build_token(TokenType.AND_AND)
                    return self.build_token(TokenType.PIPE)
                case '^':
                    return self.build_token(TokenType.CARET)
                case '%':
                    return self.build_token(TokenType.MOD)
                case '~':
                    return self.build_token(TokenType.TILDA)
                case '?':
                    return self.build_token(TokenType.QUESTION)
                case '#':
                    return self.build_token(TokenType.POUND)
                case ';':
                    return self.build_token(TokenType.SEMICOLON)
                case '"':
                    return self.string()
                case '`':
                    return self.string('`') 
                case "'":
                    return self.build_token(TokenType.SINGLE_QUOTE)
                case " "|"\t":
                    self.curr = self.pos
                case "\n":
                    self.line += 1
                    self.line_start = self.pos
                    self.curr = self.pos
                case _:
                    if c.isalpha():
                        return self.identifier()
                    elif c.isdigit():
                        return self.number(c)
        return self.build_token(TokenType.EOF) 
