class IRUnaryOp:
    def __init__(self, op, value):
        self.op = op
        self.value = value


class IRBinOp:
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

class IRAssign:
    def __init__(self, target, value):
        self.target = target
        self.value = value

class IRMultiAssign:
    def __init__(self, targets, value):
        self.ids = targets
        self.value = value

class IRCompoundAssign:
    def __init__(self, op, target, value):
        self.op = op
        self.target = target
        self.value = value

class IRVarDeclMulti:
    def __init__(self,ids, typ):
        self.ids = ids 
        self.type = typ

class IRVarDecl:
    def __init__(self,id_, typ):
        self.id = id_ 
        self.type = typ

class IRVarDeclWithInit:
    def __init__(self, name, typ, value):
        self.id = name
        self.typ = typ
        self.value = value


class IRFunction:
    def __init__(self, name, parameter, body, return_list):
        self.name = name
        self.parameter = parameter
        self.body = body
        self.return_list = return_list


class IRFunctionCall:
    def __init__(self, name, args):
        self.name = name
        self.args = args


class IRStatement:
    def __init__(self, stmt):
        self.stmt = stmt


class IRBlock:
    def __init__(self, body):
        self.body = body


class IRReturnStmt:
    def __init__(self, expr_list):
        self.expr_list = expr_list


class IRId:
    def __init__(self, name):
        self.name = name


class IRIdList:
    def __init__(self, ids):
        self.ids = ids


class IRprint:
    def __init__(self, name, types, expr_list, sep=" "):
        self.type_list = types
        self.expr_list = expr_list
        self.sep = sep


class IRReturnList:
    def __init__(self, values):
        self.values = values


class IRExpr:
    def __init__(self, value, typ):
        self.value = value
        self.type = typ


class IRExprList:
    def __init__(self, exprs):
        self.exprs = exprs


class IRPointer:
    def __init__(self, value):
        self.value = value


class IRNumberInt:
    def __init__(self, value):
        self.value = value


class IRNumberHex:
    def __init__(self, value):
        self.value = value


class IRNumberOct:
    def __init__(self, value):
        self.value = value


class IRNumberBin:
    def __init__(self, value):
        self.value = value


class IRNumberFloat:
    def __init__(self, value):
        self.value = value


class IRTrue:
    def __init__(self):
        pass


class IRFalse:
    def __init__(self):
        pass


class IRString:
    def __init__(self, value):
        self.value = value


class IRConst:
    def __init__(self, value):
        self.value = value


class IRStruct:
    def __init__(self, name, fields,is_nested):
        self.name = name
        self.fields = fields
        self.is_nested = is_nested


class IREnum:
    def __init__(self, name, values):
        self.name = name
        self.values = values


class IRLoop:
    def __init__(self, body):
        self.body = body


class IRInfiniteLoop:
    def __init__(self, body):
        self.body = body


class IRIf:
    def __init__(self, cond, then_body, else_body):
        self.cond = cond
        self.then_body = then_body
        self.else_body = else_body


class IRStaticArr:
    def __init__(self, typ, dimension):
        self.type = type
        self.dimension = dimension

class IRCstyleLoop:
    def __init__(self,var_decls=None,cond=None,updation=None):
        self.initilization = var_decls
        self.condition = cond
        self.updation = updation

class IRDynamicArr:
    def __init__(self, typ, dimension):
        self.type = type
        self.dimension = dimension


class IRBreak:
    def __init__(self, level=0):
        self.level = level


class IRContinue:
    def __init__(self, level=0):
        self.level = level
