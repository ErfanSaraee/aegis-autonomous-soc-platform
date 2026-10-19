"""Formal Python Abstract Syntax Tree (AST) static verifier for generated SOAR remediation playbooks."""

import ast

from app.core.config import settings
from app.schemas.soc import ASTPlaybookVerification

FORBIDDEN_SOAR_IMPORTS: set[str] = {
    "os",
    "subprocess",
    "sys",
    "shutil",
    "socket",
    "pty",
    "ctypes",
    "pickle",
    "marshal",
    "builtins",
    "importlib",
}

FORBIDDEN_SOAR_CALLS: set[str] = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "globals",
    "locals",
    "getattr",
    "setattr",
    "delattr",
}

FORBIDDEN_DUNDER_ATTRIBUTES: set[str] = {
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__mro__",
    "__bases__",
    "__class__",
    "__code__",
}


class _SOARPlaybookASTVisitor(ast.NodeVisitor):
    """AST NodeVisitor enforcing Zero-Trust static invariants on SOAR Python scripts."""

    def __init__(self) -> None:
        self.violations: list[str] = []
        self.inspected_nodes: list[str] = []
        self.complexity: int = 1

    def generic_visit(self, node: ast.AST) -> None:
        node_type = type(node).__name__
        if len(self.inspected_nodes) < 45:
            self.inspected_nodes.append(node_type)
        super().generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root_mod = alias.name.split(".")[0]
            if root_mod in FORBIDDEN_SOAR_IMPORTS:
                self.violations.append(
                    f"Line {node.lineno}: Forbidden OS/system import '{alias.name}' in SOAR playbook."
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            root_mod = node.module.split(".")[0]
            if root_mod in FORBIDDEN_SOAR_IMPORTS:
                self.violations.append(
                    f"Line {node.lineno}: Forbidden from-import '{node.module}' in SOAR playbook."
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_SOAR_CALLS:
            self.violations.append(
                f"Line {node.lineno}: Prohibited dynamic builtin '{node.func.id}()' in SOAR playbook."
            )
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in {"system", "popen", "rmtree", "unlink", "remove", "spawn"}:
                self.violations.append(
                    f"Line {node.lineno}: Unsafe destructive method '.{node.func.attr}()' prohibited."
                )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in FORBIDDEN_DUNDER_ATTRIBUTES:
            self.violations.append(
                f"Line {node.lineno}: Dunder sandbox escape attribute '{node.attr}' prohibited."
            )
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            has_exit = any(
                isinstance(child, (ast.Break, ast.Return, ast.Raise))
                for child in ast.walk(node)
            )
            if not has_exit:
                self.violations.append(
                    f"Line {node.lineno}: Unbounded 'while True:' loop without break/return prohibited."
                )
        self.generic_visit(node)


class SOARPlaybookASTSandbox:
    """Stateless formal AST verifier for SOAR containment playbooks."""

    @staticmethod
    def verify_playbook(code: str) -> ASTPlaybookVerification:
        """Parse and statically verify a generated Python SOAR script before execution."""
        if not code or not code.strip():
            return ASTPlaybookVerification(
                is_safe=False,
                cyclomatic_complexity=0,
                violations=["Empty SOAR playbook script provided."],
                inspected_nodes=[],
            )

        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return ASTPlaybookVerification(
                is_safe=False,
                cyclomatic_complexity=0,
                violations=[f"SyntaxError at line {exc.lineno}: {exc.msg}"],
                inspected_nodes=["SyntaxError"],
            )

        visitor = _SOARPlaybookASTVisitor()
        visitor.visit(tree)

        if visitor.complexity > settings.AST_MAX_COMPLEXITY:
            visitor.violations.append(
                f"Cyclomatic complexity ({visitor.complexity}) exceeds max threshold ({settings.AST_MAX_COMPLEXITY})."
            )

        return ASTPlaybookVerification(
            is_safe=len(visitor.violations) == 0,
            cyclomatic_complexity=visitor.complexity,
            violations=visitor.violations,
            inspected_nodes=visitor.inspected_nodes,
        )


soar_ast_sandbox = SOARPlaybookASTSandbox()
