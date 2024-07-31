import ida_funcs
import ida_name
import idaapi

class StringFunctionDetector():
    def __init__(self):
        self.depth = 0

    def find_all_xrefs(self, ea, s, depth):
        self.depth += 1
        func_addr = idc.get_func_attr(ea, FUNCATTR_START)
        func_name = ida_funcs.get_func_name(ea)
        if (func_addr != idaapi.BADADDR) and (func_name != None):
            ea = func_addr
            if s not in func_name:
                old_name = func_name
                new_name = s + "_" + old_name
                ida_name.set_name(func_addr, new_name)
                print("Old name: %s, New name: %s" % (old_name, new_name))
        for xref in XrefsTo(ea):
            if XrefTypeName(xref.type) != "Ordinary_Flow":
                if depth < 10:
                    self.find_all_xrefs(xref.frm, s, self.depth)

    def find_rs_string(self):
        string_list = Strings()
        for s in string_list:
            if ("\\" or "/" in str(s)) and (".rs" in str(s)):
                split_str = str(s).replace("/", ".").replace("\\", ".").split(".")[-2]
                self.depth = 0
                self.find_all_xrefs(s.ea, split_str, 0)

if __name__ == "__main__":
    SFD = StringFunctionDetector()
    SFD.find_rs_string()