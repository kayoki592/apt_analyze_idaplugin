import idaapi
import idautils
import idc
import ida_kernwin
import re

class APICallEntry:
    def __init__(self, ea, api_name):
        self.ea = ea
        self.api_name = api_name

class StringEntry:
    def __init__(self, ea, string_value):
        self.ea = ea
        self.string_value = string_value

class MultiTabChooser(ida_kernwin.Choose):
    def __init__(self, title, entries, is_api=True):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [ ["Address", 20 | ida_kernwin.Choose.CHCOL_PLAIN],
              ["API Name" if is_api else "String", 50 | ida_kernwin.Choose.CHCOL_PLAIN] ],
            flags=ida_kernwin.Choose.CH_MODAL
        )
        self.entries = entries
        self.items = [ [f"{hex(entry.ea)}", entry.api_name if is_api else entry.string_value] for entry in entries ]

    def OnSelectLine(self, n):
        ea = self.entries[n].ea
        idc.jumpto(ea)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

class APTAnalyzerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "APT Sample Analyzer"
    help = "APT sample quick analysis"
    wanted_name = "APT Analyzer"
    wanted_hotkey = "Ctrl-Shift-P"

    key_apis = [
        "CreateProcessA", "CreateProcessW", "VirtualAlloc", "LoadLibraryA", "LoadLibraryW",
        "GetProcAddress", "InternetOpenUrlA", "InternetOpenUrlW", "CreateThread",
        "WinExec", "ShellExecuteA", "ShellExecuteW", "VirtualAllocEx", "WriteProcessMemory",
        "ResumeThread", "InternetConnectA", "InternetConnectW", "HttpOpenRequestA", "HttpOpenRequestW"
    ]

    suspicious_patterns = [
        re.compile(rb"https?://[^\s]+"),       # URL
        re.compile(rb"\d{1,3}(\.\d{1,3}){3}"), # IP Address
        re.compile(rb"[A-Za-z]:\\[^\s]+"),     # File Path
        re.compile(rb"cmd\.exe|powershell"),   # Command
        re.compile(rb"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"),  # 注册表启动项
        re.compile(rb"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce"),
        re.compile(rb"HKEY_LOCAL_MACHINE"),    # 注册表关键路径
        re.compile(rb"HKEY_CURRENT_USER"),
        re.compile(rb"HKEY_CLASSES_ROOT"),
        re.compile(rb"Software\\Microsoft\\Windows\\CurrentVersion\\Run", re.IGNORECASE),
        re.compile(rb"Software/Microsoft/Windows/CurrentVersion/Run", re.IGNORECASE)
    ]

    def init(self):
        print("[*] APT Analyzer plugin loaded.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("[*] Running APT Analyzer...")
        api_calls = self.scan_key_apis()
        suspicious_strings = self.scan_suspicious_strings()

        if api_calls:
            chooser_api = MultiTabChooser("APT Analyzer - API Calls", api_calls, is_api=True)
            chooser_api.Show()

        if suspicious_strings:
            chooser_str = MultiTabChooser("APT Analyzer - Suspicious Strings", suspicious_strings, is_api=False)
            chooser_str.Show()

        if not api_calls and not suspicious_strings:
            ida_kernwin.info("No key API calls or suspicious strings found!")

    def scan_key_apis(self):
        print("[*] Scanning for key API calls...")
        imported_addrs = {}

        def imp_cb(ea, name, ordinal):
            if name is not None and name in self.key_apis:
                imported_addrs[ea] = name
                print(f"[*] Found API {name} at {hex(ea)}")
            return True

        nimps = idaapi.get_import_module_qty()
        for i in range(nimps):
            idaapi.enum_import_names(i, imp_cb)

        if not imported_addrs:
            print("[!] No key APIs found in import table.")
            return []

        api_calls = []
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if seg_name == ".text":
                for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                    if idc.is_code(idc.get_full_flags(head)):
                        if idc.print_insn_mnem(head) in ("call", "jmp"):
                            target = idc.get_operand_value(head, 0)
                            if target in imported_addrs:
                                idc.set_color(head, idc.CIC_ITEM, 0x00FF00)
                                idc.set_cmt(head, f"Call to {imported_addrs[target]}", 0)
                                api_calls.append(APICallEntry(head, imported_addrs[target]))

        print(f"[*] Highlighted {len(api_calls)} key API call instructions.")
        return api_calls

    def scan_suspicious_strings(self):
        print("[*] Scanning for suspicious strings...")
        suspicious_entries = []

        for string in idautils.Strings():
            s = str(string)
            for pattern in self.suspicious_patterns:
                if pattern.search(s.encode()):
                    idc.set_color(string.ea, idc.CIC_ITEM, 0x00FFFF)
                    idc.set_cmt(string.ea, f"Suspicious String: {s}", 0)
                    suspicious_entries.append(StringEntry(string.ea, s))
                    print(f"[*] Found suspicious string at {hex(string.ea)}: {s}")
                    break  # Prevent duplicate entries

        print(f"[*] Found {len(suspicious_entries)} suspicious strings.")
        return suspicious_entries

    def term(self):
        print("[*] APT Analyzer plugin unloaded.")

def PLUGIN_ENTRY():
    return APTAnalyzerPlugin()
