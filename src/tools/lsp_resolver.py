"""
LSP Resolver — 经 clangd(语言服务器)按坐标取定义源码、按名字查调用关系。

通过 clangd 解析符号定义、调用关系和类型信息。
索引/符号树定位(坐标或名字),克隆/重名安全地切出整段定义源码。

    with LspResolver("lcms") as lsp:
        # 坐标 -> JSON:{name,def_file,def_line,def_col,source}(无重名歧义)
        print(lsp.get_source({"file": "src/cmsio0.c", "line": 100, "col": 5}))
        for c in lsp.callees("OptimizeMatrixShaper"):     # 名字 -> 它调用了谁 + 坐标
            print(c["name"], c["def_file"], c["def_line"])

Pipeline runs use their frozen stages/scan/compile_commands.json. Standalone
use without a run environment retains the project-local .clangd behavior.
首次查询触发后台索引(几秒~几十秒),索引持久化于 .cache/clangd,后续很快。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from loguru import logger

# 文件扩展名 -> LSP languageId(didOpen 需要)
_LANG = {".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
         ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp"}

# semanticTokens 客户端声明的标准类型清单(clangd 仍按它自己返回的 legend 解码)
_STD_SEMTOK_TYPES = [
    "namespace", "type", "class", "enum", "interface", "struct", "typeParameter",
    "parameter", "variable", "property", "enumMember", "event", "function", "method",
    "macro", "keyword", "modifier", "comment", "string", "number", "regexp",
    "operator", "decorator",
]
# types_used 只留"类型类"的 token kind(clangd 把 struct 归为 class)
_TYPE_KINDS = {"type", "class", "struct", "enum", "union", "interface", "typeParameter"}


def _uri(path: str) -> str:
    return "file://" + path


class LspResolver:
    """按坐标查 定义源码 / 引用 / 调用关系 / 用到的类型 的最小 clangd 客户端(单进程贯穿多次查询)。"""

    def __init__(self, library_name: str, clangd: str | None = None):
        self.library_name = library_name
        self.source_root = Path(f"test_lib/{library_name}").resolve()
        if not self.source_root.exists():
            logger.warning(f"Source root not found: {self.source_root}")
        self._clangd = clangd or shutil.which("clangd") or "/usr/bin/clangd"
        self.compile_commands_path = self._resolve_compile_commands()
        self._id = 0
        self._opened: set[str] = set()
        clangd_args = [self._clangd, "--background-index", "--log=error"]
        if self.compile_commands_path is not None:
            clangd_args.append(
                f"--compile-commands-dir={self.compile_commands_path.parent}"
            )
        self._proc = subprocess.Popen(
            clangd_args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0,
        )
        _init = self._request("initialize", {
            "processId": os.getpid(),
            "rootUri": _uri(str(self.source_root)),
            "capabilities": {
                "window": {"workDoneProgress": True},  # 接收后台索引进度
                "textDocument": {
                    "documentSymbol": {"hierarchicalDocumentSymbolSupport": True},
                    "semanticTokens": {  # types_used 用:取整文件 token 再按函数区间过滤
                        "requests": {"range": True, "full": {"delta": False}},
                        "tokenTypes": _STD_SEMTOK_TYPES, "tokenModifiers": [],
                        "formats": ["relative"]},
                }},
        })
        # clangd 的 semanticTokens legend(token 类型索引 -> 名字),用于解码
        self._semtok_legend = (
            (((_init or {}).get("capabilities") or {}).get("semanticTokensProvider") or {})
            .get("legend", {}).get("tokenTypes", []))
        self._semtok_cache: dict[str, list] = {}
        self._notify("initialized", {})
        # 打开一个工程文件,触发 clangd 加载编译库 + 启动全工程后台索引
        # (callers/incomingCalls 依赖跨文件索引)。
        self._seed()

    # ---------- LSP JSON-RPC framing ----------
    def _send(self, msg: dict) -> None:
        data = json.dumps(msg).encode()
        self._proc.stdin.write(b"Content-Length: %d\r\n\r\n%s" % (len(data), data))
        self._proc.stdin.flush()

    def _read(self) -> dict | None:
        n = 0
        while True:  # 读头,直到空行
            line = b""
            while not line.endswith(b"\r\n"):
                c = self._proc.stdout.read(1)
                if not c:
                    return None
                line += c
            if line == b"\r\n":
                break
            key, _, val = line[:-2].partition(b": ")
            if key.lower() == b"content-length":
                n = int(val)
        body = b""
        while len(body) < n:
            chunk = self._proc.stdout.read(n - len(body))
            if not chunk:
                return None
            body += chunk
        return json.loads(body)

    def _request(self, method: str, params: dict, timeout: float = 60):
        self._id += 1
        rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self._read()
            if msg is None:
                return None
            self._track(msg)
            # 只认 id 匹配的应答(跳过通知/反向请求)
            if msg.get("id") == rid and ("result" in msg or "error" in msg):
                return msg.get("result")
        return None

    def _track(self, msg: dict) -> None:
        """顺带处理服务端消息:回应进度创建请求(server->client request 需应答)。"""
        if msg.get("method") == "window/workDoneProgress/create" and "id" in msg:
            self._send({"jsonrpc": "2.0", "id": msg["id"], "result": None})

    def _notify(self, method: str, params: dict) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    # ---------- internals ----------
    def _resolve_compile_commands(self) -> Path | None:
        run_dir = os.environ.get("RUN_DIR")
        if not run_dir:
            return None
        frozen = Path(run_dir) / "stages" / "scan" / "compile_commands.json"
        if not frozen.is_file():
            raise FileNotFoundError(
                f"run-frozen compile_commands.json is missing: {frozen}"
            )
        current = self.source_root / "build_analysis" / "compile_commands.json"
        if not current.is_file() or current.read_bytes() != frozen.read_bytes():
            raise RuntimeError(
                "build_analysis compile_commands.json differs from the run snapshot"
            )
        return frozen

    def _seed(self) -> None:
        """打开一个工程源文件,引导 clangd 发现编译库并开始后台索引。"""
        cdb = self.compile_commands_path or (
            self.source_root / "build_analysis" / "compile_commands.json"
        )
        if cdb.exists():
            try:
                entries = json.loads(cdb.read_text(encoding="utf-8"))
                if entries:
                    self._open(entries[0]["file"])
                    return
            except Exception:
                pass
        for ext in ("*.c", "*.cc", "*.cpp", "*.cxx"):
            hit = next(self.source_root.rglob(ext), None)
            if hit:
                self._open(str(hit))
                return

    def _open(self, path: str) -> None:
        if path in self._opened:
            return
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        self._notify("textDocument/didOpen", {"textDocument": {
            "uri": _uri(path),
            "languageId": _LANG.get(Path(path).suffix, "cpp"),
            "version": 1, "text": text}})
        self._opened.add(path)

    def _rel(self, path: str) -> str:
        """库内路径转相对 source_root;库外(系统头等)保留绝对路径。"""
        try:
            rel = os.path.relpath(path, self.source_root)
            return rel if not rel.startswith("..") else path
        except ValueError:
            return path

    @classmethod
    def _flatten(cls, syms):
        for s in syms or []:
            yield s
            yield from cls._flatten(s.get("children"))

    @staticmethod
    def _within(rng: dict, line: int, col: int | None) -> bool:
        """坐标是否落在符号 range 内(均 0-based)。给了 col 用全位置包含,否则只比行。"""
        s, e = rng["start"], rng["end"]
        if col is None:
            return s["line"] <= line <= e["line"]
        return (s["line"], s["character"]) <= (line, col) <= (e["line"], e["character"])

    def _pick(self, syms, line: int, col: int | None = None, name: str | None = None):
        """文档符号里取包含目标坐标、最贴合的符号(优先名字匹配,再取范围最小)。"""
        best = None
        for s in self._flatten(syms):
            rng = s.get("range") or s.get("location", {}).get("range")
            if not rng or not self._within(rng, line, col):
                continue
            name_match = name is not None and s.get("name", "").split("(")[0].strip() == name
            key = (0 if name_match else 1, rng["end"]["line"] - rng["start"]["line"])
            if best is None or key < best[0]:
                best = (key, s)
        return best[1] if best else None

    def _read_def(self, path: str, line: int, col: int | None = None,
                  name: str | None = None) -> dict:
        """文件 + 坐标(0-based,落在某符号内)-> {name, def_file, def_line, def_col, source}。

        get_source / goto_definition 共用:取包含该坐标的符号(给了 col 用全位置包含);
        def_line/def_col 指向其函数名(selectionRange),source 为整段(range)切片。
        宏等不在 documentSymbol 里则回退取该行(跨行尾反斜杠续行),name 为空串。
        """
        self._open(path)
        syms = self._request("textDocument/documentSymbol",
                             {"textDocument": {"uri": _uri(path)}})
        sym = self._pick(syms, line, col, name)
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        if sym:
            rng = sym.get("range") or sym.get("location", {}).get("range")
            sel = sym.get("selectionRange") or rng              # 函数名位置
            start, end = rng["start"]["line"], rng["end"]["line"]
            name_line, name_col = sel["start"]["line"], sel["start"]["character"]
            found = sym.get("name", "").split("(")[0].strip()
        else:
            start = end = line
            while end + 1 < len(lines) and lines[end].rstrip().endswith("\\"):
                end += 1
            name_line, name_col = line, 0
            found = name or ""
        body = "\n".join(lines[start:end + 1])
        return {
            "name": found,
            "def_file": self._rel(path),
            "def_line": name_line + 1,
            "def_col": name_col + 1,
            "source": f"// {self._rel(path)}:{start + 1}\n{body}",
        }

    def _semantic_tokens(self, path: str) -> list:
        """整文件 semanticTokens(只能 /full,clangd 不支持 /range)解码成
        [{name, kind, line, col}, ...](1-based)。同文件结果缓存。clangd 需先解析文件,
        故带重试;调用方一般已 documentSymbol 过该文件(已暖)。"""
        if path in self._semtok_cache:
            return self._semtok_cache[path]
        if not self._semtok_legend:
            return []
        self._open(path)
        data: list = []
        for _ in range(8):
            res = self._request("textDocument/semanticTokens/full",
                                {"textDocument": {"uri": _uri(path)}})
            data = (res or {}).get("data", []) if isinstance(res, dict) else []
            if data:
                break
            time.sleep(1)
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        leg = self._semtok_legend
        toks, cl, cc = [], 0, 0
        for i in range(0, len(data) - 4, 5):
            dl, dc, length, tt, _mod = data[i:i + 5]
            cl += dl
            cc = (cc + dc) if dl == 0 else dc          # 同行累加,换行重置
            name = lines[cl][cc:cc + length] if cl < len(lines) else ""
            kind = leg[tt] if 0 <= tt < len(leg) else "?"
            toks.append({"name": name, "kind": kind, "line": cl + 1, "col": cc + 1})
        self._semtok_cache[path] = toks
        return toks

    @staticmethod
    def _json_err(msg: str) -> str:
        """统一的失败返回:JSON 字符串 {"error": <简洁英文提示>}。"""
        return json.dumps({"error": msg}, ensure_ascii=False)

    # ---------- public ----------
    def get_source(self, site: dict) -> str:
        """传入完整坐标 {file, line, col}(均 1-based)-> JSON 字符串。
        成功: {"name","def_file","def_line","def_col","source"}(包含该坐标的函数或类型);
        失败: {"error": "<简洁英文>"}。永不抛异常。

        按"file 锚定文件 + (line,col) 全位置区间包含"定位符号,不按名字查,故无重名歧义。
        要 dict 的内部调用直接走私有 _read_def。
        """
        file = site.get("file", "")
        try:
            line = int(site.get("line"))
            col = int(site.get("col"))
        except (TypeError, ValueError):
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        if not file or line < 1 or col < 1:
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        path = file if os.path.isabs(file) else str(self.source_root / file)
        if not os.path.isfile(path):
            return self._json_err(f"File not found: {file}. Check the path and retry.")
        info = self._read_def(path, line - 1, col=col - 1)
        if not info.get("name"):
            return self._json_err(
                f"No definition at {file}:{line}:{col}. Verify the coordinate and query again.")
        return json.dumps(info, ensure_ascii=False)

    def types_used(self, site: dict) -> str:
        """传入完整坐标 {file, line, col}(函数的定义坐标 anchor)-> JSON 字符串。
        成功: 数组 [{name, kind, line, col}, ...] —— 该函数体内用到的【类型】(按名去重),
        每项坐标是它在本函数里的使用点,喂 goto_definition 即得该作用域下正确的定义(重名免疫);
        失败: {"error": ...}。

        范围限定在所在函数的定义区间内(documentSymbol 取区间)+ 类型类 kind 过滤
        (semanticTokens)。抓的是源码里写出名字的类型 token,抓不到无名隐式类型。
        """
        file = site.get("file", "")
        try:
            line = int(site.get("line"))
            col = int(site.get("col"))
        except (TypeError, ValueError):
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        if not file or line < 1 or col < 1:
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        path = file if os.path.isabs(file) else str(self.source_root / file)
        if not os.path.isfile(path):
            return self._json_err(f"File not found: {file}. Check the path and retry.")
        self._open(path)
        syms = self._request("textDocument/documentSymbol",
                             {"textDocument": {"uri": _uri(path)}})
        sym = self._pick(syms, line - 1, col - 1)
        rng = (sym or {}).get("range") or (sym or {}).get("location", {}).get("range")
        if not sym or not rng:
            return self._json_err(
                f"No function at {file}:{line}:{col}. Verify the coordinate and query again.")
        start, end = rng["start"]["line"], rng["end"]["line"]   # 0-based
        seen, out = set(), []
        for t in self._semantic_tokens(path):
            if start <= t["line"] - 1 <= end and t["kind"] in _TYPE_KINDS and t["name"] not in seen:
                seen.add(t["name"])
                out.append(t)
        return json.dumps(out, ensure_ascii=False)

    def _call_hierarchy(self, site: dict, method: str, key: str) -> str:
        """callees/callers 共用的一层调用层级查询。

        site = 完整坐标 {file, line, col}(1-based,目标函数的定义坐标 anchor)。
        内部先把坐标解析成所在函数的【名字位置】(prepareCallHierarchy 必须点在函数名上,
        而 anchor 是函数体首行),再查调用层级 —— 按坐标定位,克隆/重名安全。
        method = callHierarchy/outgoingCalls(被调)| .../incomingCalls(主调);
        key    = 'to'(被调)| 'from'(主调)。
        返回 JSON 字符串:成功是数组(无调用时为 []);失败 {"error": ...}。call_sites 落在
        「调用实际发生」的文件:被调=本函数文件;主调=对方文件,每点带 callee=该点实际被调函数。
        """
        file = site.get("file", "")
        try:
            line = int(site.get("line"))
            col = int(site.get("col"))
        except (TypeError, ValueError):
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        if not file or line < 1 or col < 1:
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        path = file if os.path.isabs(file) else str(self.source_root / file)
        if not os.path.isfile(path):
            return self._json_err(f"File not found: {file}. Check the path and retry.")
        info = self._read_def(path, line - 1, col=col - 1)  # 坐标 -> 所在函数(名字位置)
        if not info.get("name"):
            return self._json_err(
                f"No function at {file}:{line}:{col}. Verify the coordinate and query again.")
        name = info["name"]                                  # 主体函数名(callers 的 callee 用)
        items = self._request("textDocument/prepareCallHierarchy", {
            "textDocument": {"uri": _uri(path)},
            "position": {"line": info["def_line"] - 1, "character": info["def_col"] - 1}})
        if not items:
            return json.dumps([], ensure_ascii=False)
        calls = self._request(method, {"item": items[0]}) or []
        result = []
        for c in calls:
            other = c.get(key) or {}
            def_path = other.get("uri", "")[len("file://"):]
            pos = (other.get("selectionRange") or other.get("range") or {}).get("start", {})
            site_file = path if key == "to" else def_path  # 调用点所在文件
            callee_name = other.get("name", "?") if key == "to" else name  # 该点实际被调的函数
            sites = [{"file": self._rel(site_file),
                      "line": r["start"]["line"] + 1,
                      "col": r["start"]["character"] + 1,
                      "callee": callee_name}
                     for r in c.get("fromRanges", [])]
            result.append({
                "name": other.get("name", "?"),
                "def_file": self._rel(def_path) if def_path else "",
                "def_line": pos.get("line", 0) + 1,
                "def_col": pos.get("character", 0) + 1,
                "in_repo": bool(def_path) and def_path.startswith(str(self.source_root)),
                "call_sites": sites,
            })
        return json.dumps(result, ensure_ascii=False)

    def callees(self, site: dict) -> str:
        """坐标 {file,line,col}(主调函数的定义坐标 anchor)-> JSON 字符串。
        成功: 数组,每项 {name, def_file, def_line, def_col, in_repo, call_sites:[{file,line,col,callee}]}
              (无调用时为 []);失败: {"error": ...}。
          - def_*:      被调函数的定义位置(指向函数名;取定义就用这个,且能消歧重名)
          - call_sites: 在主调函数体内调用它的位置(在主调的文件里, 均 1-based);callee=该点被调函数
          - in_repo:    被调函数是否在本库内(False=系统库等,无法取源码)
        """
        return self._call_hierarchy(site, "callHierarchy/outgoingCalls", "to")

    def callers(self, site: dict) -> str:
        """坐标 {file,line,col}(被调函数的定义坐标 anchor)-> JSON 字符串。
        成功: 数组(结构同 callees,无调用时为 []);失败: {"error": ...}。但:
          - def_*:      调用方函数的定义位置(指向函数名)
          - call_sites: 调用方体内调用该函数的位置(在**调用方**的文件里);callee=被查询的函数
        注:只认直接调用;经函数指针派发的调用方查不到(clangd 无指针分析)。
        """
        return self._call_hierarchy(site, "callHierarchy/incomingCalls", "from")

    def goto_definition(self, site: dict) -> str:
        """传入使用点 {file, line, col}(1-based,如 callees 的 call_sites 项)-> JSON 字符串。
        成功: {"name","def_file","def_line","def_col","source"}(被引用符号的定义);
        失败: {"error": "<简洁英文>"}。永不抛异常。

        即 goToDefinition:在使用点上点一下,跳到被引用符号的定义,再切出整段源码。
        与 get_source 区别:goto_definition 是「使用点→被引用的定义」(textDocument/definition),
        get_source 是「坐标→包含它的那个定义」(documentSymbol 区间包含)。
        """
        file = site.get("file", "")
        try:
            line = int(site.get("line"))
            col = int(site.get("col"))
        except (TypeError, ValueError):
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        if not file or line < 1 or col < 1:
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        path = file if os.path.isabs(file) else str(self.source_root / file)
        if not os.path.isfile(path):
            return self._json_err(f"File not found: {file}. Check the path and retry.")
        self._open(path)
        res = self._request("textDocument/definition", {
            "textDocument": {"uri": _uri(path)},
            "position": {"line": line - 1, "character": col - 1}})
        loc = res[0] if isinstance(res, list) and res else (res if isinstance(res, dict) else None)
        no_def = f"No definition resolved at {file}:{line}:{col}. Verify the coordinate and query again."
        if not loc:
            return self._json_err(no_def)
        def_uri = loc.get("uri") or loc.get("targetUri") or ""
        rng = loc.get("range") or loc.get("targetSelectionRange") or loc.get("targetRange") or {}
        def_path = def_uri[len("file://"):]
        if not def_path or "start" not in rng:
            return self._json_err(no_def)
        return json.dumps(self._read_def(def_path, rng["start"]["line"]), ensure_ascii=False)

    def declaration(self, site: dict) -> str:
        """传入函数定义坐标 {file, line, col}(1-based,anchor,落在函数体内)-> JSON 字符串。
        成功: {"name","header_file","signature","decl_file","decl_line","decl_col"} ——
              该函数【声明】(公开函数=.h 原型;无独立原型的 static=其定义自身)。
              header_file: 声明所在 .h 的相对路径(可直接 #include);声明在 .c(无独立头)则空串;
              signature:   声明处源码切出的签名串(截到首个 ';'/'{' 前,折叠空白)。
        失败: {"error": ...}。永不抛异常。

        先按坐标取所在函数的名字位置(documentSymbol 区间包含,克隆/重名安全),再在名字位置发
        textDocument/declaration(go-to-declaration,区别于 goto_definition 的 go-to-definition)。
        clangd 经真实编译参数解析,内部头里需 include 上下文才暴露的声明也能解析到。
        """
        file = site.get("file", "")
        try:
            line = int(site.get("line"))
            col = int(site.get("col"))
        except (TypeError, ValueError):
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        if not file or line < 1 or col < 1:
            return self._json_err("Incomplete coordinate: file, line, and col are all required.")
        path = file if os.path.isabs(file) else str(self.source_root / file)
        if not os.path.isfile(path):
            return self._json_err(f"File not found: {file}. Check the path and retry.")
        info = self._read_def(path, line - 1, col=col - 1)  # anchor -> 所在函数名字位置
        if not info.get("name"):
            return self._json_err(
                f"No function at {file}:{line}:{col}. Verify the coordinate and query again.")
        res = self._request("textDocument/declaration", {
            "textDocument": {"uri": _uri(path)},
            "position": {"line": info["def_line"] - 1, "character": info["def_col"] - 1}})
        loc = res[0] if isinstance(res, list) and res else (res if isinstance(res, dict) else None)
        no_decl = f"No declaration resolved for {info['name']} at {file}:{line}:{col}."
        if not loc:
            return self._json_err(no_decl)
        decl_uri = loc.get("uri") or loc.get("targetUri") or ""
        rng = loc.get("range") or loc.get("targetSelectionRange") or loc.get("targetRange") or {}
        decl_path = decl_uri[len("file://"):]
        if not decl_path or "start" not in rng:
            return self._json_err(no_decl)
        decl = self._read_def(decl_path, rng["start"]["line"])
        decl_rel = decl["def_file"]
        header = decl_rel if decl_rel.endswith((".h", ".hpp", ".hh", ".hxx")) else ""
        return json.dumps({
            "name": info["name"],
            "header_file": header,
            "signature": self._extract_signature(decl.get("source", "")),
            "decl_file": decl_rel,
            "decl_line": decl["def_line"],
            "decl_col": decl["def_col"],
        }, ensure_ascii=False)

    @staticmethod
    def _extract_signature(source: str) -> str:
        """从声明/定义源码切出签名串:丢掉 `// path:line` 注释行,取到首个 ';' 或 '{' 前,
        折叠空白(多行原型也归一成一行)。"""
        text = " ".join(ln for ln in source.splitlines() if not ln.startswith("// "))
        cut = len(text)
        for stop in (";", "{"):
            i = text.find(stop)
            if i != -1:
                cut = min(cut, i)
        return " ".join(text[:cut].split())

    # ---------- lifecycle ----------
    def close(self) -> None:
        if self._proc.poll() is not None:
            return
        try:
            self._request("shutdown", {}, timeout=5)
            self._notify("exit", {})
        except Exception:
            pass
        try:
            self._proc.terminate()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
