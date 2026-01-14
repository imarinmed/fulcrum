import ast
import os
from collections import defaultdict

def get_imports(file_path):
    with open(file_path, "r") as f:
        try:
            tree = ast.parse(f.read())
        except Exception:
            return []
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                imports.append(n.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports

graph = defaultdict(set)
for root, dirs, files in os.walk("src"):
    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            mod = path.replace("/", ".").replace(".src.", "src.").replace(".py", "")
            if mod.startswith("src."):
                for imp in get_imports(path):
                    if imp.startswith("src."):
                        graph[mod].add(imp)

def find_cycle(v, visited, stack):
    visited.add(v)
    stack.append(v)
    for neighbor in graph.get(v, []):
        if neighbor not in visited:
            if find_cycle(neighbor, visited, stack):
                return True
        elif neighbor in stack:
            print(f"Cycle detected: {' -> '.join(stack[stack.index(neighbor):])} -> {neighbor}")
            return True
    stack.pop()
    return False

visited = set()
for node in list(graph.keys()):
    if node not in visited:
        find_cycle(node, visited, [])
