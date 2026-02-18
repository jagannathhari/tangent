import os
import sys
from enum import Enum

from lexer import Lexer
from lexer import TokenType


class NodeType(Enum):
    UNARY_OP = "Unary_op"
    BINARY_OP = "Binary_op"
    ASSIGN_OP = "Assign_op"
    VAR_DECL = "Var_decl"
    VAR_DECL_SPEC = "Var_decl_SPEC"
    VAR_DECL_WITH_INIT = "Var_decl_with_init"
    FN_CALL = "function_call"
    STATEMENT = "statement"
    BLOCK_STATEMENT = "block_statement"
    PROGRAM = "Program"
    ID = "id"
    ID_LIST = "Id_list"
    RETURN_LIST = "Return_list"
    FUNCTION = "Function" 
    EXPR = "Expr"
    EXPR_LIST = "Expr_list"

    NUM_INT = "num_int"
    NUM_HEX = "num_hex"
    NUM_OCT = "num_oct"
    NUM_BIN = "num_bin"
    NUM_FLOAT = "num_float"
    TRUE = "true"
    FALSE = "false"
    STRING = "string"

class Ast:
    def __init__(self,node_type,token=None):
        self.type = node_type
        self.token = token
        self.childrens = []

    def __str__(self):
        return f"{self.token}"

    def add(self,*nodes):
        for i in nodes:
            self.childrens.append(i)



class Parse:
    def __init__(self,src):
        self.lexer = Lexer(src)
        self.prev_token = None
        self.current_token = self.lexer.next_token()

    def eat(self,token_type):
        if self.current_token.type == token_type:
            self.prev_token = self.current_token
            self.current_token = self.lexer.next_token()
            return True
        return False

    def draw_pointer(self,token):
        print(f'File: "{self.lexer.src}", line {token.line}:{token.start_pos-token.line_start+1}')
        new_line_pos = token.line_start
        for i in range(token.line_start,self.lexer.len):
            if self.lexer.content[i] == '\n':
                break
            new_line_pos += 1
        print(self.lexer.content[token.line_start:new_line_pos])
        x = ""
        for i in range(token.line_start,token.start_pos+len(token.lexeme)):
            x += " "
        print(x+"^")

    def is_premitive_dtype(self,token_type):
        ids = [ TokenType.I8,
               TokenType.I16,
               TokenType.I32,
               TokenType.I64,
               TokenType.U8,
               TokenType.U16,
               TokenType.U32,
               TokenType.U64,
               TokenType.FLOAT,
               TokenType.DOUBLE,
               TokenType.STR,
               TokenType.BOOL
               ]
        if token_type in ids:
            return True
        return False

    def peek(self,k=1):
        curr_state = self.lexer.get_state()
        t = None
        for i in range(k):
            t = self.lexer.next_token()
        self.lexer.set_state(curr_state)
        return t


    def bp(self, token_type):
        match token_type:
            case TokenType.PLUS | TokenType.MINUS:
                return 20
            case TokenType.DIVIDE | TokenType.STAR:
                return 30
            case TokenType.PREFIX:
                return 41
            case TokenType.STAR_STAR:
                return 50
        return -1

    def nud(self):

        t = self.current_token

        match self.current_token.type:

            case TokenType.MINUS|TokenType.PLUS:
                self.eat(self.current_token.type)
                unary_op = Ast(NodeType.UNARY_OP,t)
                unary_op.add(self.expr(self.bp(TokenType.PREFIX)))
                return unary_op

            case TokenType.INT_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_INT,t)

            case TokenType.HEX_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_HEX,t)

            case TokenType.OCT_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_OCT,t)

            case TokenType.BIN_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_BIN,t)
            case TokenType.FLOAT_LITERAL:
                self.eat(self.current_token.type)
                return Ast(NodeType.NUM_FLOAT,t)
            case TokenType.FALSE:
                self.eat(self.current_token.type)
                return Ast(NodeType.FALSE,t)
            case TokenType.TRUE:
                self.eat(self.current_token.type)
                return Ast(NodeType.TRUE,t)
            case TokenType.LPARN:
                self.eat(self.current_token.type)
                node = self.expr(0)
                if(not self.eat(TokenType.RPARN)):
                    print(f'File: "{self.lexer.src}", line {self.current_token.line}')
                    end_pos = self.current_token.start_pos + len(self.current_token.lexeme)
                    l =  end_pos - self.current_token.line_start-1
                    print(self.lexer.content[self.current_token.line_start:end_pos])
                    print(" "*l,"^")
                    print(f"\tExpected: ), but got {self.current_token.type.value}.")

                return node
            case TokenType.ID:
                self.eat(self.current_token.type)
                if(self.current_token.type == TokenType.LPARN):
                    self.eat(self.current_token.type)
                    node = Ast(NodeType.FN_CALL,t)
                    node.add(self.expr_list())
                    self.eat(TokenType.RPARN)
                    return node
                return Ast(NodeType.ID,t)
            case TokenType.STRING:
                self.eat(self.current_token.type)
                return Ast(NodeType.STRING,t)
            case TokenType.STAR:
                self.eat(self.current_token.type)
                n = Ast(NodeType.UNARY_OP,t)
                n.add(self.expr(self.bp(TokenType.PREFIX)))
                return n 

    def led(self,left):
        token_type = self.current_token.type
        t = self.current_token
        self.eat(token_type)
        match token_type:
            case TokenType.STAR_STAR:
                node = Ast(NodeType.BINARY_OP,t)
                node.add(left,self.expr(self.bp(token_type)-1))
                return node

        node = Ast(NodeType.BINARY_OP,t)
        node.add(left,self.expr(self.bp(token_type)+1))

        return node

    def expr(self,rbp=0):
        left = self.nud() # consumes the token
        while(self.bp(self.current_token.type)>rbp):
            left = self.led(left)
        return left

    def func_decl(self):
        # func_decl -> id :: () <block_statetment>
        self.eat(TokenType.ID)
        self.eat(TokenType.COLON_COLON)
        self.eat(TokenType.LPARN)
        self.eat(TokenType.RPARN)
        return self.block_statement()

    def return_list(self):
        #return_list -> <type>|<id> | <return_list>,(<id>|<type>)
        node = Ast(NodeType.RETURN_LIST)

        def is_allowed(token_type):
            return token_type == TokenType.ID or self.is_premitive_dtype(token_type)

        if(is_allowed(self.current_token.type)):
            node.add(Ast(NodeType.ID,self.current_token))
            self.eat(self.current_token.type)
            while self.current_token.type == TokenType.COMMA:
                self.eat(TokenType.COMMA)
                if(not is_allowed(self.current_token.type)):
                    self.draw_pointer(self.current_token)
                    print("Syntax Error, not allowed.")
                    sys.exit()

                node.add(Ast(NodeType.ID,self.current_token))
                self.eat(self.current_token.type)
        return node
    def id_list(self):
        #id_list -> <id> | <id_list>,<id>
        node = Ast(NodeType.ID_LIST)
        node.add(Ast(NodeType.ID,self.current_token))
        self.eat(TokenType.ID)

        while self.current_token.type == TokenType.COMMA:
            self.eat(TokenType.COMMA)
            node.add(Ast(NodeType.ID,self.current_token))
            self.eat(TokenType.ID)
        return node

    def expr_list(self):
        #id_list -> <expr> | <expr>,<expr>
        # print(self.current_token)
        node = Ast(NodeType.EXPR_LIST)
        node.add(self.expr())
        while self.current_token.type == TokenType.COMMA:
            self.eat(TokenType.COMMA)
            node.add(self.expr())
        return node

    def var_decl_with_init(self):
        pass

    def var_decl(self):
        #var_decl -> <id_list>:=<expr_list> | <id_list>:<type>=<expr_list> | 
        # <id_list>  = <expr_list> 

        id_list = self.id_list()
        if self.current_token.type == TokenType.COLON_EQUAL:
            self.eat(TokenType.COLON_EQUAL)
            expr_list = self.expr_list()
            node = Ast(NodeType.VAR_DECL)
            node.add(id_list,expr_list)
            return node 

        if self.current_token.type == TokenType.EQUAL:
            ass_op = Ast(NodeType.ASSIGN_OP,self.current_token)
            self.eat(TokenType.EQUAL)
            right = self.expr_list()
            ass_op.add(id_list,right)
            return ass_op

        self.eat(TokenType.COLON)
        if self.current_token.type == TokenType.ID or self.is_premitive_dtype(self.current_token.type):
            type_id = self.current_token
            self.eat(self.current_token.type)
            if(self.current_token.type==TokenType.EQUAL):
                self.eat(TokenType.EQUAL)
                expr_list = self.expr_list()
                node = Ast(NodeType.VAR_DECL_WITH_INIT)
                node.add(id_list,type_id,expr_list)
                return node
            node = Ast(NodeType.VAR_DECL_SPEC)
            node.add(id_list,type_id)
            return node
        else:
            print("Handle error")
            return

    def block_statement(self):
        #block_statement -> { statement }
        node = Ast(NodeType.BLOCK_STATEMENT)
        if(not self.eat(TokenType.BLOCK_OPEN)):
            self.draw_pointer(self.prev_token)
            print(f"Syntax Error: Expected '{{' but got '{self.current_token.lexeme}'.")
            sys.exit()
        while self.current_token.type != TokenType.BLOCK_CLOSE:
            node.add(self.statement())
        self.eat(TokenType.BLOCK_CLOSE)
        return node

    def function(self):
        # function -> <id> :: () <block_statement>
        node = Ast(NodeType.FUNCTION)
        node.add(Ast(NodeType.ID,self.current_token))
        self.eat(TokenType.ID)
        self.eat(TokenType.COLON_COLON)
        self.eat(TokenType.LPARN)
        self.eat(TokenType.RPARN)
        node.add(self.return_list())
        node.add(self.block_statement())
        return node

    def statement(self):
        node = Ast(NodeType.STATEMENT)
        if self.current_token.type == TokenType.ID:
            t = self.peek()
            if(not t):
                print("statement: Handle error")
                sys.exit(0)
            if(t.type == TokenType.EQUAL or t.type==TokenType.COMMA or t.type == TokenType.COLON_EQUAL):
                node.add(self.var_decl())
                self.eat(TokenType.SEMICOLON)
                return node 
            elif t.type == TokenType.COLON_COLON:
                return self.function()

        if self.current_token.type == TokenType.BLOCK_OPEN:
            return self.block_statement()

        node.add(self.expr())
        if(not self.eat(TokenType.SEMICOLON)):
            self.draw_pointer(self.prev_token) 
            print("Syntax Error: Expected ';' here.")
            sys.exit()
        return node

    def program(self):
        node_program = Ast(NodeType.PROGRAM)
        while self.current_token.type != TokenType.EOF:
            node_program.add(self.statement())

        return node_program



class Visit:
    def __init__(self,root,src=None):
        self.root = root
        self.src  = src 
        self.content_len = 0
        self.content = ""
        self.init()

    def init(self):
        if not os.path.isfile(self.src):
            print("Error: File",repr(self.src),"not found.")
            sys.exit(0) 

        with open(self.src,"r") as f:
            self.content = f.read()
        self.content_len = len(self.content)
 
    def visit_binop(self,node):
        op = node.token.lexeme
        l = self.visit(node.childrens[0])
        r = self.visit(node.childrens[1])
        return f"({l}{op}{r})"

    def visit_uop(self,node):
        op = node.token.lexeme
        v =  self.visit(node.childrens[0])
        return f"({op}{v})"

    def visit_num(self,node):
        return node.token.lexeme

    def visit_id(self,node):
        return node.token.lexeme

    def visit_assign(self,node):
        # TODO: Handle conflict
        ids = node.childrens[0].childrens
        exprs = node.childrens[1].childrens
        x = ""
        for n,i,j in zip(range(len(ids)),ids,exprs):
            x += f"{self.visit(i)} = {self.visit(j)}"
            if(n!=len(ids)-1):
                x+=";\n"
        return x

    def draw_pointer(self,node):
        print(f'File: "{self.src}", line {node.token.line}')
        end_pos = node.token.start_pos + len(node.token.lexeme)
        l =  end_pos - node.token.line_start-1
        new_line_pos = node.token.line_start
        for i in range(node.token.line_start,self.content_len):
            if self.content[i] == '\n':
                break
            new_line_pos += 1
        print(self.content[node.token.line_start:new_line_pos])
        print((" "*l)+"^")

    def visit_var_dec(self,node):
        x = ""
        n = len(node.childrens[0].childrens)
        m = len(node.childrens[1].childrens)

        if m == n:
            i = 0
            for var_name,var_val in zip(node.childrens[0].childrens,node.childrens[1].childrens):
                var_type = self.get_type(var_val)
                x += f"{var_type} {self.visit(var_name)} = {self.visit(var_val)}"
                if(i!=n-1):
                    x += ";\n"
                i+=1
            return x
        elif n > m:
            self.draw_pointer(node.childrens[0].childrens[m])
            print(f"Error: Not enough values to unpack. Require {n-m} more values.")
            sys.exit()
        elif n < m:
            self.draw_pointer(node.childrens[1].childrens[n])
            print(f"Got More values than expected. Got {m-n} more values")
            sys.exit()

        if m == 1:
            expr_type = self.get_type(node.childrens[1].childrens[0])
            val = self.visit(node.childrens[1].childrens[0])
            x = ""
            y = ""
            for i in range(n):
                identifier = self.visit(node.childrens[0].childrens[i])
                x += identifier 
                y += identifier
                if i!=n-1:
                    x += ","
                y+="="
            y += val
            return f"{expr_type} {x};\n{y}"
        


    def get_type(self,node):
        match node.type:
            case NodeType.NUM_INT|NodeType.NUM_OCT|NodeType.NUM_HEX|NodeType.NUM_BIN:
                return "int"
            case NodeType.NUM_FLOAT:
                return "float"
            case NodeType.BINARY_OP:
                return "int"
            case NodeType.STRING:
                return "char*"
            case NodeType.TRUE|NodeType.FALSE:
                return "bool"

    def visit_string(self,node):
        return f'"{node.token.lexeme}"'

    def visit_expr_list(self,node):
        n = len(node.childrens)
        x = ""
        for i in range(n):
            x += self.visit(node.childrens[i])
            if i!=n-1:
                x+=","

        return x

    def build_formated_string(self,node):
        seperator = " "
        formated_str = ""
        n = len(node.childrens)
        for i in range(n):
            dtype = self.get_type(node.childrens[i])
            if i == n-1:
                seperator = "" 
            if dtype == "float":
                formated_str += f"%f{seperator}"
            elif dtype == "int":
                formated_str += f"%d{seperator}"
            elif dtype == "char*":
                formated_str += f"%s{seperator}"
        return f'"{formated_str}"'

    def translate_to_cformat(self,fmt):
        n = len(fmt)
        new_fmt = ""
        while i < n:
            if fmt[i] == "\\":
                new_fmt += fmt[i]
            elif fmt[i] == "%":
                pass



    def visit_fn_call(self,node):
        fn_id = node.token.lexeme
        if fn_id == "print":
            formated_str = self.build_formated_string(node.childrens[0])
            return f"printf({formated_str},{self.visit(node.childrens[0])})"
        elif fn_id == "printf":
            return ""
        return fn_id

    def visit_block_statement(self,node):
        x = "\n{\n"
        for i in node.childrens:
            x += self.visit(i)
        x += "\n}\n"
        return x

    def visit_statement(self,node):
        x = ""
        for i in node.childrens:
            x += self.visit(i)
        return x + ";\n"

    def visit_return_list(self,node):
        if len(node.childrens) == 0:
            return "void"
        elif len(node.childrens) == 1:
            return node.childrens[0].token.lexeme
        else:
            for i in node.childrens:
                print(i)
        return "adf"
    def visit_function(self,node):
        fn_id = self.visit(node.childrens[0])
        return_list = self.visit(node.childrens[1])
        block_statement = self.visit(node.childrens[2])

        return f"{return_list} {fn_id} {block_statement}"
         

    def visit_program(self,node):
        x = ""
        for i in node.childrens:
            x += self.visit(i)
            x += "\n"
        return x

    def visit(self,node):
        match node.type:
            case NodeType.BINARY_OP:
               return self.visit_binop(node)
            case NodeType.ASSIGN_OP:
                return self.visit_assign(node)
            case NodeType.ID:
                return self.visit_id(node)
            case NodeType.UNARY_OP:
                return self.visit_uop(node)
            case NodeType.NUM_INT | NodeType.NUM_OCT| NodeType.NUM_HEX| NodeType.NUM_BIN:
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

p = Parse("test.lang")
ast = p.expr()
v = Visit(ast,"test.lang")
exp = v.visit(ast)
print(exp)
# sys.exit()
# l = Lexer("test.lang")
# while True:
#     x = l.next_token()
#     if x.type == TokenType.EOF:
#         break
#     print(x)
