import idautils
import ida_bytes
import hashlib
import ida_funcs
import ida_name

class CoreFunctionFixer():
    def __init__(self):
        pass
    
    def fix_funcs_by_hash(self):
        func_list = idautils.Functions()
        with open("./func_sha1", "r") as f:
            content = f.read().split("\n")[:-1]
        for func in func_list:
            b = ida_bytes.get_bytes(func, 50)
            b_sha1 = hashlib.sha1(b).hexdigest()
            for line in content:
                func_name = line.split("<===>")[0]
                hash = line.split("<===>")[1]
                old_name = ida_funcs.get_func_name(func)
                if b_sha1 == hash and func_name != old_name:
                    new_name = func_name.replace("<", "").replace(">", "").replace(" ", "") + "_" + hex(func).lstrip("0x")
                    ida_name.set_name(func, new_name)
                    print("old_name:", old_name, "b_sha1:", b_sha1, "new_name:", new_name, "hash:", hash)
                    print("hit!!!!")
            
    def try_unescape(self, sym):
        escape_dict = {
            "$C$": ",",
            "$SP$": "@",
            "$BP$": "*",
            "$RF$": "&",
            "$LT$": "<",
            "$GT$": ">",
            "$LP$": "(",
            "$RP$": ")",
            "$u20$": " ",
            "$u22$": "\"",
            "$u27$": "\'",
            "$u2b$": "+",
            "$u3b$": ";",
            "$u3d$": "=",
            "$u5b$": "[",
            "$u5d$": "]",
            "$u7b$": "{",
            "$u7d$": "}",
            "$u7e$": "~",
        }
        i = 0
        new_symbol = []
        while i < len(sym):
            if sym[i] == "$":
                escape_str = sym[i : sym[0:].find("$", i + 1) + 1]
                new_symbol.append(escape_dict[escape_str])
                i += len(escape_str)
                continue
            elif sym[i] == ".":
                new_symbol.append(":")
            else:
                new_symbol.append(sym[i])
            i += 1
        return "".join(new_symbol).lstrip("_")

    def parse_rust_symbol_legacy(self, sym):
        if sym is None: return sym
        if not sym.startswith("_"): return sym
        if "ZN" not in sym: return sym
        # Try to strip _ZN like symbols
        sym = sym.lstrip("_").lstrip("ZN")
        # Try to parse rest of symbols
        i = 0
        num = 0
        new_symbol = []
        while i < len(sym):
            if sym[i].isdigit():
                num *= 10
                num += int(sym[i])
            else:
                if num != 0:
                    new_symbol.append(sym[i : i + num])
                    i += num
                    num = 0
                    continue
            i += 1
        new_symbol = [self.try_unescape(symbol) for symbol in new_symbol]
        return "::".join(new_symbol[:len(new_symbol) - 1])

if __name__ == "__main__":
    CFF = CoreFunctionFixer()
    CFF.fix_funcs_by_hash()