import idautils
import ida_bytes
import hashlib
import ida_funcs

class FunctionHashDownloader():
    def __init__(self):
        pass
    
    def download_all_funcs(self):
        func_list = idautils.Functions()
        with open("./func_sha1", "w") as f:
            for func in func_list:
                b = ida_bytes.get_bytes(func, 50)
                b_sha1 = hashlib.sha1(b).hexdigest()
                old_func_name = ida_funcs.get_func_name(func)
                new_func_name = self.parse_rust_symbol_legacy(old_func_name)
                f.write(new_func_name + "<===>" + b_sha1 + "\n")
                print(new_func_name, b_sha1)
            
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
    FHD = FunctionHashDownloader()
    FHD.download_all_funcs()