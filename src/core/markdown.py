from typing import Any, List, Optional

def escape(text: str) -> str:
    if text is None:
        return ""
    s = str(text)
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|")
    s = s.replace("*", "\\*")
    s = s.replace("_", "\\_")
    s = s.replace("[", "\\[")
    s = s.replace("]", "\\]")
    s = s.replace("`", "\\`")
    s = s.replace("\n", "<br/>")
    return s

def header(level: int, text: str) -> str:
    level = max(1, min(6, level))
    return f"{'#' * level} {escape(text)}\n\n"

def link(text: str, target: str) -> str:
    return f"[{escape(text)}]({target})"

def code_block(language: Optional[str], content: str) -> str:
    lang = language or ""
    return f"```{lang}\n{content}\n```\n\n"

def _format_alignment(alignments: Optional[List[str]], cols: int) -> List[str]:
    if not alignments:
        return [":---"] * cols
    mapping = {"left": ":---", "center": ":---:", "right": "---:"}
    out: List[str] = []
    for i in range(cols):
        a = alignments[i] if i < len(alignments) else "left"
        out.append(mapping.get(a, ":---"))
    return out

def table(headers: List[str], rows: List[List[Any]], alignments: Optional[List[str]] = None) -> str:
    esc_headers = [escape(h) for h in headers]
    cols = len(esc_headers)
    sep = _format_alignment(alignments, cols)
    h = "| " + " | ".join(esc_headers) + " |\n"
    s = "| " + " | ".join(sep) + " |\n"
    body_lines: List[str] = []
    for r in rows:
        cells = [escape(r[i]) if i < len(r) else "" for i in range(cols)]
        body_lines.append("| " + " | ".join(cells) + " |")
    return h + s + "\n".join(body_lines) + ("\n" if body_lines else "")

def format_number(value: Any, kind: str = "count") -> str:
    try:
        if kind == "bytes":
            n = float(value)
            units = ["B", "KB", "MB", "GB", "TB"]
            i = 0
            while n >= 1024 and i < len(units) - 1:
                n /= 1024.0
                i += 1
            return f"{n:.2f} {units[i]}"
        if kind == "percent":
            n = float(value)
            return f"{n:.2f}%"
        if kind == "currency":
            n = float(value)
            return f"$${n:,.2f}"
        n = float(value)
        return f"{int(n):,}"
    except Exception:
        return str(value)

