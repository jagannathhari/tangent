import os
import sys

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict

from lexer import Lexer
from lexer import TokenType
from ir import*
symbol_table = {}

import hashlib

A = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"


def mangle(sig):
    h = hashlib.blake2b(sig.encode(), digest_size=16).hexdigest()
    print(h)


def enclose(s, char='"'):
    return f"{char}{s}{char}"


dtype_map = {
    "i8": "int8_t",
    "i16": "int16_t",
    "i32": "int32_t",
    "i64": "int64_t",
    "u8": "uint8_t",
    "u16": "uint16_t",
    "u32": "uint32_t",
    "u64": "uint64_t",
    "str": "char*",
    "int": "int",
    "float": "float",
}

fmt_map = {
    "i8": {
        "printf": {"d": "PRId8", "x": "PRIx8"},
        "scanf": {"d": "SCNd8", "x": "SCNx8"},
    },
    "i16": {
        "printf": {"d": "PRId16", "x": "PRIx16"},
        "scanf": {"d": "SCNd16", "x": "SCNx16"},
    },
    "i32": {
        "printf": {"d": "PRId32", "x": "PRIx32"},
        "scanf": {"d": "SCNd32", "x": "SCNx32"},
    },
    "i64": {
        "printf": {"d": "PRId64", "x": "PRIx64"},
        "scanf": {"d": "SCNd64", "x": "SCNx64"},
    },
    "u8": {
        "printf": {"d": "PRIu8", "x": "PRIx8"},
        "scanf": {"d": "SCNu8", "x": "SCNx8"},
    },
    "u16": {
        "printf": {"d": "PRIu16", "x": "PRIx16"},
        "scanf": {"d": "SCNu16", "x": "SCNx16"},
    },
    "u32": {
        "printf": {"d": "PRIu32", "x": "PRIx32"},
        "scanf": {"d": "SCNu32", "x": "SCNx32"},
    },
    "u64": {
        "printf": {"d": "PRIu64", "x": "PRIx64"},
        "scanf": {"d": "SCNu64", "x": "SCNx64"},
    },
    "float": {
        "printf": {"d": enclose("f"), "x": enclose("f")},
        "scanf": {"d": enclose("f"), "x": enclose("f")},
    },
    "int": {
        "printf": {"d": enclose("d"), "x": enclose("x")},
        "scanf": {"d": enclose("d"), "x": enclose("x")},
    },
}


class NodeType(Enum):
    UNARY_OP = "Unary_op"
    BIN_OP = "Binary_op"
    ASSIGN_OP = "Assign_op"
    COMPUND_ASSIGN = "compund assign"
    VAR_DECL = "Var_decl"
    VAR_DECL_SPEC = "Var_decl_SPEC"
    VAR_DECL_WITH_INIT = "Var_decl_with_init"
    FN_CALL = "function_call"
    STATEMENT = "statement"
    BLOCK_STATEMENT = "block_statement"
    RETURN_STATEMENT = "return_statement"
    PROGRAM = "Program"
    ID = "id"
    ID_LIST = "Id_list"
    RETURN_LIST = "Return_list"
    FUNCTION = "Function"
    EXPR = "Expr"
    EMPTY_EXR = "emptry_expr"
    EXPR_LIST = "Expr_list"
    POINTER = "pointer"
    NUM_INT = "num_int"
    NUM_HEX = "num_hex"
    NUM_OCT = "num_oct"
    NUM_BIN = "num_bin"
    NUM_FLOAT = "num_float"
    TRUE = "true"
    FALSE = "false"
    STRING = "string"
    CONST = "constant"
    STRUCT = "struct"
    ENUM = "Enum"
    LOOP = "Loop" 
    INFINITE_LOOP= "Infinite_loop" 
    IF = "if"
    BREAK = "break"
    CONTINUE = "continue"


class Ast:
    def __init__(self, node_type, token=None):
        self.type = node_type
        self.token = token
        self.childrens = []

    def __str__(self):
        return f"{self.token}"

    def add(self, *nodes):
        for i in nodes:
            self.childrens.append(i)


class SymbolKind(Enum):
    VAR = "variable"
    FUNC = "function"
    IFUNC = "inbuild Function"
    PARAM = "parameter"
    CONST = "constant"
    TYPE = "data type"
    STRUCT = "struct"
    ENUM = "enum"


class Dtype(Enum):
    INT_8 = "int_8"
    INT_16 = "int_16"
    INT_32 = "int_32"
    INT_64 = "int_64"

    UINT_8 = "uint_8"
    UINT_16 = "uint_16"
    UINT_32 = "uint_32"
    UINT_64 = "uint_64"
    STR = "str"


class ScopeType(Enum):
    GLOBAL = "global"
    FUNC = "function"
    BLOCK = "block"
    STRUCT = "struct"
    UNION = "union"
    LOOP = "loop"


@dataclass(slots=True)
class Symbol:
    dtype: str = ""
    kind: Optional[SymbolKind] = (
        None  # Variable, function, parameter, constant, struct, etc.
    )
    scope_level: int = 0  # Depth in the scope stack
    is_mutable: bool = True  # True if variable can be reassigned
    # value: Any = None                       # For constants or initial values
    # parameters: List[Symbol] = field(default_factory=list)  # Function parameters
    # return_type: Optional[Dtype] = None  # Function return type
    # fields: Dict[str, Symbol] = field(default_factory=dict) # Struct/union fields
    # is_captured: bool = False              # For closures


@dataclass(slots=True)
class Scope:
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    kind: Optional[ScopeType] = None
    parent: Optional["Scope"] = None
    is_mutable: bool = True


class Parse:
    def __init__(self, src):
        self.lexer = Lexer(src)
        self.prev_token = None
        self.current_token = self.lexer.next_token()

    def eat(self, token_type):
        if self.current_token.type == token_type:
            self.prev_token = self.current_token
            self.current_token = self.lexer.next_token()
            return True
        return False

    def draw_pointer(self, token):
        print(
            f'File: "{self.lexer.src}", line {token.line}:{token.start_pos-token.line_start+1}'
        )
        new_line_pos = token.line_start
        for i in range(token.line_start, self.lexer.len):
            if self.lexer.content[i] == "\n":
                break
            new_line_pos += 1
        print(self.lexer.content[token.line_start : new_line_pos])
        x = ""
        for i in range(token.line_start, token.start_pos + len(token.lexeme)):
            x += " "
        print(x + "^")

    def peek(self, k=1):
        curr_state = self.lexer.get_state()
        t = None
        for i in range(k):
            t = self.lexer.next_token()
        self.lexer.set_state(curr_state)
        return t

    def peek_list(self, k=1):
        curr_state = self.lexer.get_state()
        t = []
        for i in range(k):
            t.append(self.lexer.next_token())
        self.lexer.set_state(curr_state)
        return t

    def bp(self, token_type):
        match token_type:
            case TokenType.PIPE_PIPE:
                return 17
            case TokenType.PIPE:
                return 18
            case TokenType.CARET:
                return 19
            case TokenType.PLUS | TokenType.MINUS:
                return 20
            case TokenType.DIVIDE | TokenType.STAR:
                return 30
            case TokenType.PREFIX:
                return 40
            case TokenType.STAR_STAR:
                return 50
        return -1

    def nud(self):

        t = self.current_token

        match self.current_token.type:

            case TokenType.MINUS | TokenType.PLUS:
                self.eat(self.current_token.type)
                unary_op = Ast(NodeType.UNARY_OP, t)
                unary_op.add(self.expr(self.bp(TokenType.PREFIX)))
                return unary_op

            case TokenType.INT_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_INT, t)

            case TokenType.HEX_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_HEX, t)

            case TokenType.OCT_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_OCT, t)

            case TokenType.BIN_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_BIN, t)
            case TokenType.FLOAT_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_FLOAT, t)
            case TokenType.LPARN:
                self.eat(self.current_token.type)
                node = self.expr(0)
                if not self.eat(TokenType.RPARN):
                    print(f'File: "{self.lexer.src}", line {self.current_token.line}')
                    end_pos = self.current_token.start_pos + len(
                        self.current_token.lexeme
                    )
                    l = end_pos - self.current_token.line_start - 1
                    print(self.lexer.content[self.current_token.line_start : end_pos])
                    print(" " * l, "^")
                    print(f"\tExpected: ), but got {self.current_token.type.value}.")

                return node
            case TokenType.ID:
                self.eat(self.current_token.type)
                if self.current_token.type == TokenType.LPARN:
                    self.eat(self.current_token.type)
                    node = Ast(NodeType.FN_CALL, t)
                    node.add(self.expr_list())
                    self.eat(TokenType.RPARN)
                    return node
                return Ast(NodeType.ID, t)
            case TokenType.STRING:
                self.eat(self.current_token.type)
                return Ast(NodeType.STRING, t)
            case TokenType.STAR:
                self.eat(self.current_token.type)
                n = Ast(NodeType.UNARY_OP, t)
                n.add(self.expr(self.bp(TokenType.PREFIX)))
                return n

    def led(self, left):
        token_type = self.current_token.type
        t = self.current_token
        self.eat(token_type)
        match token_type:
            case TokenType.STAR_STAR:
                node = Ast(NodeType.BIN_OP, t)
                node.add(left, self.expr(self.bp(token_type) - 1))
                return node

        node = Ast(NodeType.BIN_OP, t)
        node.add(left, self.expr(self.bp(token_type) + 1))

        return node

    def expr(self, rbp=0):
        left = self.nud()  # consumes the token
        if not left:
            return Ast(NodeType.EMPTY_EXR, self.current_token)
        while self.bp(self.current_token.type) > rbp:
            left = self.led(left)
        return left

    def return_statement(self):
        # return_statement -> return <expr_list>
        node = Ast(NodeType.RETURN_STATEMENT,self.current_token)
        self.eat(TokenType.ID)
        node_expr_list = self.expr_list()
        node.add(node_expr_list)
        return node

    def return_list(self):
        # return_list -> <id> | <return_list>,<id>
        node = Ast(NodeType.RETURN_LIST)

        is_surrounded = False
        token_lparn = None
        if self.current_token.type == TokenType.LPARN:
            is_surrounded = True
            token_lparn = self.current_token
            self.eat(TokenType.LPARN)

        if self.current_token.type == TokenType.ID:
            node.add(Ast(NodeType.ID, self.current_token))
            self.eat(self.current_token.type)
            while self.current_token.type == TokenType.COMMA:
                self.eat(TokenType.COMMA)
                if not self.current_token.type == TokenType.ID:
                    self.draw_pointer(self.current_token)
                    print("Syntax Error: not allowed.")
                    sys.exit()

                node.add(Ast(NodeType.ID, self.current_token))
                self.eat(self.current_token.type)
        if is_surrounded and (not self.eat(TokenType.RPARN)):
            self.draw_pointer(token_lparn)
            print("Syntax Error: This bracket never closed.")
            sys.exit()
        return node

    def id_list(self):
        # id_list -> <id> | <id_list>,<id>
        node = Ast(NodeType.ID_LIST)
        node.add(Ast(NodeType.ID, self.current_token))
        self.eat(TokenType.ID)

        while self.current_token.type == TokenType.COMMA:
            self.eat(TokenType.COMMA)
            node.add(Ast(NodeType.ID, self.current_token))
            self.eat(TokenType.ID)
        return node

    def expr_list(self):
        # id_list -> <expr> | <expr>,<expr>
        # print(self.current_token)
        node = Ast(NodeType.EXPR_LIST)
        node.add(self.expr())
        while self.current_token.type == TokenType.COMMA:
            self.eat(TokenType.COMMA)
            node_expr = self.expr()
            if node_expr.type == NodeType.EMPTY_EXR:
                self.draw_pointer(self.prev_token)
                print("Syntax Error: Expected Expression here.")
                sys.exit()
            node.add(node_expr)
        return node

    def var_decl_with_init(self):
        pass

    def compund_assignment(self):
        #id -> id (+= -= ) expr
        var_name = Ast(NodeType.ID,self.current_token)
        self.eat(TokenType.ID)
        t = self.current_token
        self.eat(self.current_token.type)
        node = Ast(NodeType.COMPUND_ASSIGN,t)
        node.add(var_name)
        node.add(self.expr())
        return node


    def var_decl(self):
        # var_decl -> <id_list>:=<expr_list> | <id_list>:<id>=<expr_list> |
        # <id_list>  = <expr_list>
        id_list = self.id_list()

        # var_decl -> <id_list>:=<expr_list>
        if self.current_token.type == TokenType.COLON_EQUAL:
            self.eat(TokenType.COLON_EQUAL)
            expr_list = self.expr_list()
            node = Ast(NodeType.VAR_DECL)
            node.add(id_list, expr_list)
            return node

        # <id_list>  = <expr_list>
        if self.current_token.type == TokenType.EQUAL:
            ass_op = Ast(NodeType.ASSIGN_OP, self.current_token)
            self.eat(TokenType.EQUAL)
            right = self.expr_list()
            ass_op.add(id_list, right)
            return ass_op

        # <id_list>:<id>=<expr_list>
        self.eat(TokenType.COLON)

        pointer_level = 0
        if self.current_token.type == TokenType.STAR:
            while self.current_token.type == TokenType.STAR:
                pointer_level += 1
                self.eat(TokenType.STAR)
        if self.current_token.type == TokenType.ID:
            type_id = Ast(NodeType.ID, self.current_token)
            self.eat(self.current_token.type)
            if self.current_token.type == TokenType.EQUAL:
                self.eat(TokenType.EQUAL)
                expr_list = self.expr_list()
                node = Ast(NodeType.VAR_DECL_WITH_INIT)
                node.add(id_list, type_id, expr_list)
                return node
            # <id_list>:<id>
            node = Ast(NodeType.VAR_DECL_SPEC)
            node.add(id_list, Ast(NodeType.POINTER, pointer_level), type_id)
            return node
        else:
            print("Handle error")
            return

    def block_statement(self):
        # block_statement -> { statement }
        node = Ast(NodeType.BLOCK_STATEMENT)
        if not self.eat(TokenType.BLOCK_OPEN):
            self.draw_pointer(self.prev_token)
            print(f"Syntax Error: Expected '{{' but got '{self.current_token.lexeme}'.")
            sys.exit()
        while self.current_token.type != TokenType.BLOCK_CLOSE:
            node.add(self.statement())
        self.eat(TokenType.BLOCK_CLOSE)
        return node

    def function(self):
        # function -> <id> :: () <return_list> <block_statement>
        node = Ast(NodeType.FUNCTION)
        node.add(Ast(NodeType.ID, self.current_token))
        self.eat(TokenType.ID)
        self.eat(TokenType.COLON_COLON)
        self.eat(TokenType.LPARN)
        self.eat(TokenType.RPARN)
        node.add(self.return_list())
        node.add(self.block_statement())
        return node

    def struct(self):
        node = Ast(NodeType.STRUCT)
        node.add(Ast(NodeType.ID, self.current_token))
        self.eat(TokenType.ID)  # struct name
        self.eat(TokenType.COLON_COLON)
        self.eat(TokenType.ID)  # keyword struct
        node.add(self.block_statement())
        return node

    def break_statement(self):
        node = Ast(NodeType.BREAK)
        self.eat(TokenType.ID)
        if self.current_token.type == TokenType.NUM_INT:
            self.eat(TokenType.INT_LITERAL)
            node.add(NodeType.NUM_INT,self.current_token)
        return node

    def continue_statement(self):
        node = Ast(NodeType.CONTINUE)
        self.eat(TokenType.ID)
        if self.current_token.type == TokenType.NUM_INT:
            self.eat(TokenType.INT_LITERAL)
            node.add(NodeType.NUM_INT,self.current_token)
        return node

    def loop(self):
        node = Ast(NodeType.INFINITE_LOOP)
        self.eat(TokenType.ID)
        node.add(self.statement())
        return node

    def conditionl(self):
       self.eat(TokenType.ID) 
       expr = self.expr()

    def eat_semicolon(self):
        if not self.eat(TokenType.SEMICOLON):
            self.draw_pointer(self.prev_token)
            print("Syntax Error: Expected ';' here.")
            sys.exit()

    def statement(self):
        node = Ast(NodeType.STATEMENT)
        if self.current_token.type == TokenType.ID:
            if self.current_token.lexeme == "return":
                node.add(self.return_statement())
                self.eat_semicolon()
                return node
            elif self.current_token.lexeme == "for":
                return self.loop()
            elif self.current_token.lexeme == "if":
                return self.conditionl()
            peek1, peek2 = self.peek_list(2)
            if not peek1 or not peek2:
                print("TODO: Handle statement error")
                sys.exit(0)
            if peek1.type in (
                TokenType.EQUAL,
                TokenType.COMMA,
                TokenType.COLON_EQUAL,
                TokenType.COLON,
            ):
                node.add(self.var_decl())
                self.eat_semicolon()
                return node
            elif peek1.lexeme in ["+=","-=","*=","/=""|=""&="]:
                node.add(self.compund_assignment())
                self.eat_semicolon()
                return node
            elif peek1.type == TokenType.COLON_COLON and peek2.type == TokenType.LPARN:
                return self.function()
            elif (
                peek1.type == TokenType.COLON_COLON
                and peek2.type == TokenType.ID
                and peek2.lexeme == "struct"
            ):
                node.add(self.struct())
                return node

        if self.current_token.type == TokenType.BLOCK_OPEN:
            return self.block_statement()

        node.add(self.expr())
        self.eat_semicolon()
        return node

    def program(self):
        node_program = Ast(NodeType.PROGRAM)
        while self.current_token.type != TokenType.EOF:
            node_program.add(self.statement())

        return node_program


class Visit:
    def __init__(self, root, src=None):
        self.root = root
        self.src = src
        self.content_len = 0
        self.content = ""
        self.scopes = []
        self.defer_stack = []
        self.scope_level = 0
        self.init()

    def ident(self, s, offset=1):
        space = "    " * (self.scope_level - offset)
        return f"{space}{s}"

    def enter_scope(self, scope: Optional["Scope"] = None):
        self.scope_level += 1
        if scope is None:
            # default to a generic block scope
            scope = Scope(
                kind=ScopeType.BLOCK, parent=self.scopes[-1] if self.scopes else None
            )

        # print("enter scope",scope.kind)
        self.scopes.append(scope)
        self.defer_stack.append([])
        return scope

    def exit_scope(self):
        # print("Exit scope",self.scopes[-1].kind)
        self.scope_level -= 1
        self.scopes.pop()
        return list(reversed(self.defer_stack.pop()))

    def declare(self, name, value=None):
        if name in self.scopes[-1].symbols:
            return False
        self.scopes[-1].symbols[name] = value
        return True

    def resolve(self, name):
        for s in reversed(self.scopes):
            if name in s.symbols:
                return True
        return False

    def register_function_reference(self, node):
        symbol = Symbol(
            dtype=None
        )
        pass
        # print(node.type)

    def promote_type(self, x, y):
        numeric_rank = {
            "i8": 1,
            "i16": 2,
            "i32": 3,
            "int": 3,
            "i64": 4,
            "u8": 1,
            "u16": 2,
            "u32": 3,
            "u64": 4,
            "float": 5,
        }

        # if either type is not numeric, cannot promote
        if x not in numeric_rank or y not in numeric_rank:
            return None

        rank_x = numeric_rank[x]
        rank_y = numeric_rank[y]

        if rank_x >= rank_y:
            return dtype_map[x]
        else:
            return dtype_map[y]

    def infer_type(self, node):
        match node.type:
            case NodeType.BIN_OP:
                l = self.infer_type(node.childrens[0])
                r = self.infer_type(node.childrens[1])
                if l == r:
                    return l
                return self.promote_type(l, r)
            case (
                NodeType.NUM_INT
                | NodeType.NUM_OCT
                | NodeType.NUM_HEX
                | NodeType.NUM_BIN
            ):
                return "int"
            case NodeType.UNARY_OP:
                return self.infer_type(node.childrens)
            case NodeType.NUM_FLOAT:
                return "float"
            case NodeType.STRING:
                return "char*"
            case NodeType.EMPTY_EXR:
                return "None"
            case NodeType.ID:
                id_name = node.token.lexeme
                if id_name in dtype_map:
                    return dtype_map[id_name]
                return self.scopes[-1].symbols[id_name].dtype

    def init(self):
        if not os.path.isfile(self.src):
            print("Error: File", repr(self.src), "not found.")
            sys.exit(0)

        with open(self.src, "r") as f:
            self.content = f.read()
        self.content_len = len(self.content)

    def visit_binop(self, node):
        op = node.token.lexeme
        l = self.visit(node.childrens[0])
        r = self.visit(node.childrens[1])
        return f"({l}{op}{r})"

    def visit_uop(self, node):
        op = node.token.lexeme
        v = self.visit(node.childrens[0])
        return f"({op}{v})"

    def visit_num(self, node):
        return node.token.lexeme

    def visit_id(self, node):
        return node.token.lexeme

    def visit_assign(self, node):
        # TODO: Handle conflict
        # ids , exprs
        ids = node.childrens[0].childrens
        exprs = node.childrens[1].childrens
        x = []
        for i, j in zip(ids, exprs):
            if not self.resolve(i.token.lexeme):
                self.draw_pointer(i)
                print("Var donot declared.")
                sys.exit()

            var_name = self.visit(i)
            x.append(f"{var_name} = {self.visit(j)}")
        return x

    def draw_pointer(self, node):
        print(f'File: "{self.src}", line {node.token.line}')
        end_pos = node.token.start_pos + len(node.token.lexeme)
        l = end_pos - node.token.line_start - 1
        new_line_pos = node.token.line_start
        for i in range(node.token.line_start, self.content_len):
            if self.content[i] == "\n":
                break
            new_line_pos += 1
        print(self.content[node.token.line_start : new_line_pos])
        print((" " * l) + "^")

    def visit_id_list(self, node):
        return [self.visit(i) for i in node.childrens]

    def visit_var_decl_spec(self, node):
        # idlist,pointer,type;
        id_list = self.visit(node.childrens[0])
        pointer_level = node.childrens[1].token
        type_id = self.infer_type(node.childrens[2])
        dtype = f"{type_id}{'*'*pointer_level}"

        for var_name, curr_node in zip(id_list, node.childrens[0].childrens):
            symbol = Symbol(
                dtype=dtype, kind=SymbolKind.VAR, scope_level=self.scope_level
            )

            if not self.declare(var_name, symbol):
                self.draw_pointer(curr_node)
                print(f"Variable '{var_name}' already declared.")
                sys.exit()

        return [f"{dtype} {ids}" for ids in id_list]

    def visit_var_dec(self, node):
        # idlist , exprlist
        x = ""
        idlist_len = len(node.childrens[0].childrens)
        exprlist_len = len(node.childrens[1].childrens)
        if exprlist_len == 1:
            id_list = self.visit(node.childrens[0])
            expr_list = "".join(self.visit(node.childrens[1]))
            expr_type = self.infer_type(node.childrens[1].childrens[0])
            for var_name, curr_node in zip(id_list, node.childrens[0].childrens):
                symbol = Symbol(
                    dtype=expr_type, kind=SymbolKind.VAR, scope_level=self.scope_level
                )
                if not self.declare(var_name, symbol):
                    self.draw_pointer(curr_node)
                    print(f"Variable '{var_name}' already declared.")
                    sys.exit()
            return [
                f"{expr_type} {','.join(id_list)}",
                f"{'='.join(id_list)}={expr_list}",
            ]
        if idlist_len == exprlist_len:
            x = []
            for node_var,node_expr in zip(
                node.childrens[0].childrens, node.childrens[1].childrens
            ):
                var_type = self.infer_type(node_expr)
                x.append(f"{var_type} {self.visit(node_var)} = {self.visit(node_expr)}")
            return x


        elif idlist_len > exprlist_len:
            self.draw_pointer(node.childrens[0].childrens[exprlist_len])
            print(
                f"Error: Not enough values to unpack. Require {idlist_len-exprlist_len} more values."
            )
            sys.exit()
        elif idlist < exprlist_len:
            self.draw_pointer(node.childrens[1].childrens[idlist_len])
            print(
                f"Got More values than expected. Got {exprlist_len-idlist_len} more values"
            )
            sys.exit()

    def get_type(self, node):
        match node.type:
            case (
                NodeType.NUM_INT
                | NodeType.NUM_OCT
                | NodeType.NUM_HEX
                | NodeType.NUM_BIN
            ):
                return "int"
            case NodeType.NUM_FLOAT:
                return "float"
            case NodeType.BIN_OP:
                return "int"
            case NodeType.STRING:
                return "char*"
            case _:
                return self.infer_type(node)


    def visit_string(self, node):
        return enclose(node.token.lexeme)

    def visit_expr_list(self, node):
        return [self.visit(i) for i in node.childrens]

    def gen_fmt_str(self, dtype, base, function="printf"):
        """
        dtype: data type
        base: "d" for decimal, "x" for hex
        function: printf or scanf
        """
        return enclose("%") + fmt_map[dtype][function][base]

    def translate_to_cformat(self, fmt):
        n = len(fmt)
        new_fmt = ""
        while i < n:
            if fmt[i] == "\\":
                new_fmt += fmt[i]
            elif fmt[i] == "%":
                pass

    def build_formated_string(self, node, seperator=" "):
        formated_str = []
        for i in node.childrens:
            dtype = self.get_type(i)
            if dtype == "char*":
                formated_str.append(enclose("%s"))
                continue

            if dtype in fmt_map:
                formated_str.append(self.gen_fmt_str(dtype, "d"))
            else:
                formated_str.append("Unkonwn")

        return enclose(seperator).join(formated_str)

    def visit_compound_assign(self,node):
        #id,expr
        var_name = self.visit(node.childrens[0])
        expr = self.visit(node.childrens[1])
        # t = self.infer_type(node.childrens[1])
        return [f"{var_name} {node.token.lexeme} {expr}"]

    def visit_fn_call(self, node):
        # expression_list
        fn_id = node.token.lexeme
        if fn_id == "print":
            formated_str = self.build_formated_string(node.childrens[0])
            expr_list = ",".join(self.visit(node.childrens[0]))
            return [f"printf({formated_str},{expr_list})"]
        elif fn_id == "printf":
            return ""
        return [fn_id + "()"]

    def visit_block_statement(self, node):
        self.enter_scope()
        x = [f"\n{self.ident("{",2)}\n"]
        for i in node.childrens:
            x.append(self.visit(i))
        x.append(self.ident("}", 2))
        self.exit_scope()
        return x

    def visit_statement(self, node):
        x = ""
        ident = "    "
        for i in node.childrens:
            for j in self.visit(i):
                x += self.ident(f"{j};\n")
        return x

    def visit_return_statement(self, node):
        # exprlist
        types = []
        # print(node.childrens[0].childrens)
        # for i in node.childrens[0].childrens:
        #     types.append(self.infer_type(i))
        # print(types)
        # for i in node.childrens[0].childrens:
        #     print(i)
        inside_fn_scope = False
        for i in reversed(self.scopes):
            if i.kind == ScopeType.STRUCT:
                self.draw_pointer(node)
                print('return statement found inside struct')
                sys.exit(-1)
            if i.kind == ScopeType.FUNC:
                inside_fn_scope = True
                break
        if not inside_fn_scope:
            self.draw_pointer(node)
            print('return statement not found inside Function')
            sys.exit(-1)

        expr_list = ",".join(self.visit(node.childrens[0]))
        return [f"return {expr_list}"]

    def visit_return_list(self, node):
        if len(node.childrens) == 0:
            return "void"
        elif len(node.childrens) == 1:
            return node.childrens[0].token.lexeme
        else:
            for i in node.childrens:
                pass
        return "adf"

    def visit_infinite_loop(self,node):
        # block_statement
        x = "".join(self.visit(node.childrens[0]))
        return f"for(;;) {x}"

    def visit_struct(self, node):
        # statement->id,block statement

        struct_id = self.visit(node.childrens[0])

        struct_scope = Scope(kind=ScopeType.STRUCT, parent=self.scopes[-1])
        symbol = Symbol(kind=SymbolKind.STRUCT, scope_level=self.scope_level)

        defination = "typedef struct"
        # checking if Inside struct block
        for i in reversed(self.scopes):
            if i.kind == ScopeType.STRUCT:
                defination = "struct"

        self.enter_scope(struct_scope)
        block_statement = self.visit(node.childrens[1])
        struct_scope.parent.symbols[struct_id] = symbol
        self.exit_scope()
        return [f"{defination} {''.join(block_statement)} {struct_id}"]

    def visit_function(self, node):
        # fn_id , return_list , block_statement
        # self.s
        self.enter_scope(Scope(kind=ScopeType.FUNC,parent=self.scopes[-1]))
        fn_id = self.visit(node.childrens[0])
        return_list = self.visit(node.childrens[1])
        block_statement = "".join(self.visit(node.childrens[2]))
        self.exit_scope()
        return f"{return_list} {fn_id}() {block_statement}"

    def visit_program(self, node):
        self.enter_scope(Scope(kind=ScopeType.GLOBAL))

        for i in node.childrens:
            if i.type == NodeType.FUNCTION:
                self.register_function_reference(i)  # for forward refrence
        header = """
#include<stdio.h>
#include<stdint.h>
#include<inttypes.h>
        """
        x = [header]
        for i in node.childrens:
            x.append(self.visit(i))
        self.exit_scope()
        return "".join(x)

    def visit(self, node):
        match node.type:
            case NodeType.BIN_OP:
                return self.visit_binop(node)
            case NodeType.ASSIGN_OP:
                return self.visit_assign(node)
            case NodeType.ID:
                return self.visit_id(node)
            case NodeType.UNARY_OP:
                return self.visit_uop(node)
            case (
                NodeType.NUM_INT
                | NodeType.NUM_OCT
                | NodeType.NUM_HEX
                | NodeType.NUM_BIN
            ):
                return self.visit_num(node)
            case NodeType.NUM_FLOAT:
                return self.visit_num(node)
            case NodeType.STRING:
                return self.visit_string(node)
            case NodeType.ID_LIST:
                return self.visit_id_list(node)
            case NodeType.EXPR_LIST:
                return self.visit_expr_list(node)
            case NodeType.VAR_DECL:
                return self.visit_var_dec(node)
            case NodeType.FN_CALL:
                return self.visit_fn_call(node)
            case NodeType.PROGRAM:
                return self.visit_program(node)
            case NodeType.STATEMENT:
                return self.visit_statement(node)
            case NodeType.FUNCTION:
                return self.visit_function(node)
            case NodeType.BLOCK_STATEMENT:
                return self.visit_block_statement(node)
            case NodeType.TRUE | NodeType.FALSE:
                return node.token.lexeme
            case NodeType.RETURN_LIST:
                return self.visit_return_list(node)
            case NodeType.VAR_DECL_SPEC:
                return self.visit_var_decl_spec(node)
            case NodeType.VAR_DECL_WITH_INIT:
                return ""
            case NodeType.STRUCT:
                return self.visit_struct(node)
            case NodeType.RETURN_STATEMENT:
                return self.visit_return_statement(node)
            case NodeType.EMPTY_EXR:
                return ""
            case NodeType.COMPUND_ASSIGN:
                return self.visit_compound_assign(node)
            case NodeType.INFINITE_LOOP:
                return self.visit_infinite_loop(node)
            case _:
                print("Unhandled", node.type)
                return ""

src = sys.argv[1]
p = Parse(src)
ast = p.program()
v = Visit(ast,src)
exp = v.visit(ast)
print(exp)
sys.exit()
# l = Lexer("test.lang")
# while True:
#     x = l.next_token()
#     if x.type == TokenType.EOF:
#         break
#     print(x)
