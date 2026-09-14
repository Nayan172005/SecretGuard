"""
Secret Reconstructor — CORE NOVELTY MODULE

Program-Flow-Aware Secret Reconstruction

This module implements the primary novelty of the system:
detecting secrets that are constructed from multiple source-code fragments
and reconstructing the complete value through static analysis.

Supported reconstruction patterns:
1. Direct string assignment
2. Variable-to-variable assignment
3. String concatenation (+ operator)
4. Multiple chained concatenation
5. Simple constant propagation
6. String formatting / f-strings / .format() where statically resolvable
7. Base64 decoding of static strings
8. List/tuple join operations

Limitations (by design — this is NOT a full compiler):
- Does not evaluate function calls (except known safe ones like base64.b64decode)
- Does not handle conditional assignments
- Does not cross file boundaries (single-file analysis)
- Reports PARTIAL status when any fragment is unresolvable
"""

import re
import ast
import base64
from typing import List, Dict, Optional, Tuple, Set
from .models import (
    SecretFragment, DetectionCandidate, ReconstructionStatus,
    mask_secret
)


class SecretReconstructor:
    """
    Reconstructs secrets assembled from multiple source-code fragments.

    Algorithm:
    1. Parse source code into an AST (for Python files)
    2. Build a symbol table of constant string assignments
    3. Find string concatenation operations
    4. Resolve concatenation operands using the symbol table
    5. Detect if the reconstructed value matches a known secret pattern
    6. Track reconstruction status (FULL, PARTIAL, UNRESOLVED)
    """

    def __init__(self):
        # Symbol table: variable_name -> (value, line_number, is_resolved)
        self.symbol_table: Dict[str, Tuple[str, int, bool]] = {}
        # Concatenation operations found
        self.concat_operations: List[Dict] = []
        # String format operations found
        self.format_operations: List[Dict] = []
        # Reconstructed secrets
        self.reconstructed: List[Dict] = []

    def analyze_python(self, content: str, file_path: str) -> List[Dict]:
        """
        Analyze Python source code for fragmented secrets.

        Uses Python's ast module for reliable parsing, with regex
        fallback for files that fail to parse.
        """
        self.symbol_table = {}
        self.concat_operations = []
        self.reconstructed = []

        try:
            tree = ast.parse(content)
            self._walk_python_ast(tree, content, file_path)
        except SyntaxError:
            # Fall back to regex-based analysis for invalid Python
            self._analyze_with_regex(content, file_path)

        return self.reconstructed

    def analyze_javascript(self, content: str, file_path: str) -> List[Dict]:
        """
        Analyze JavaScript/TypeScript source code for fragmented secrets.
        Uses regex-based approach since we don't have a JS AST parser.
        """
        self.symbol_table = {}
        self.concat_operations = []
        self.reconstructed = []

        self._analyze_js_with_regex(content, file_path)
        return self.reconstructed

    def analyze_generic(self, content: str, file_path: str, language: str) -> List[Dict]:
        """
        Analyze source code of any supported language.
        Dispatches to language-specific analyzers when available,
        falls back to regex-based analysis otherwise.
        """
        if language in ("Python",):
            return self.analyze_python(content, file_path)
        elif language in ("JavaScript", "TypeScript", "JavaScript (JSX)", "TypeScript (TSX)"):
            return self.analyze_javascript(content, file_path)
        else:
            self.symbol_table = {}
            self.concat_operations = []
            self.reconstructed = []
            self._analyze_with_regex(content, file_path)
            return self.reconstructed

    # ─── Python AST Analysis ───────────────────────────────────────────

    def _walk_python_ast(self, tree: ast.AST, content: str, file_path: str):
        """Walk the Python AST to build a symbol table and find concatenation operations."""
        lines = content.split('\n')

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                self._handle_python_assignment(node, lines, file_path)

        # After building the symbol table, resolve concatenation operations
        self._resolve_concatenations(file_path, lines)

    def _handle_python_assignment(self, node: ast.Assign, lines: List[str], file_path: str):
        """
        Handle a Python assignment statement.
        Records constant string assignments in the symbol table and
        detects concatenation operations.
        """
        # Only handle simple single-target assignments
        if len(node.targets) != 1:
            return
        target = node.targets[0]

        if not isinstance(target, ast.Name):
            return

        var_name = target.id
        value_node = node.value

        # Case 1: Direct string constant assignment
        #   part1 = "AKIA"
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            self.symbol_table[var_name] = (value_node.value, node.lineno, True)

        # Case 2: String concatenation with +
        #   key = part1 + part2 + part3
        elif isinstance(value_node, ast.BinOp) and isinstance(value_node.op, ast.Add):
            fragments = self._extract_concat_operands(value_node)
            if fragments:
                self.concat_operations.append({
                    "target": var_name,
                    "fragments": fragments,
                    "line": node.lineno,
                    "file": file_path,
                })

        # Case 3: Variable-to-variable assignment
        #   auth = key
        elif isinstance(value_node, ast.Name):
            source_var = value_node.id
            if source_var in self.symbol_table:
                val, _, resolved = self.symbol_table[source_var]
                self.symbol_table[var_name] = (val, node.lineno, resolved)

        # Case 4: f-string / formatted string
        #   key = f"{part1}{part2}"
        elif isinstance(value_node, ast.JoinedStr):
            self._handle_fstring(var_name, value_node, node.lineno, file_path)

        # Case 5: str.format() call
        #   key = "{}-{}".format(part1, part2)
        elif isinstance(value_node, ast.Call):
            self._handle_function_call(var_name, value_node, node.lineno, file_path)

        # Case 6: .join() call
        #   key = "".join([part1, part2])
        # Handled within _handle_function_call

    def _extract_concat_operands(self, node: ast.BinOp) -> List[Dict]:
        """
        Recursively extract operands from chained concatenation.
        E.g., a + b + c → [a, b, c]
        """
        operands = []

        # Process left operand
        if isinstance(node.left, ast.BinOp) and isinstance(node.left.op, ast.Add):
            operands.extend(self._extract_concat_operands(node.left))
        elif isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            operands.append({"type": "literal", "value": node.left.value, "line": node.left.lineno})
        elif isinstance(node.left, ast.Name):
            operands.append({"type": "variable", "name": node.left.id, "line": node.left.lineno})
        else:
            operands.append({"type": "unresolved", "line": getattr(node.left, 'lineno', 0)})

        # Process right operand
        if isinstance(node.right, ast.Constant) and isinstance(node.right.value, str):
            operands.append({"type": "literal", "value": node.right.value, "line": node.right.lineno})
        elif isinstance(node.right, ast.Name):
            operands.append({"type": "variable", "name": node.right.id, "line": node.right.lineno})
        else:
            operands.append({"type": "unresolved", "line": getattr(node.right, 'lineno', 0)})

        return operands

    def _handle_fstring(self, var_name: str, node: ast.JoinedStr, lineno: int, file_path: str):
        """Handle f-string reconstruction: key = f"{part1}{part2}" """
        fragments = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                fragments.append({"type": "literal", "value": value.value, "line": lineno})
            elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                fragments.append({"type": "variable", "name": value.value.id, "line": lineno})
            else:
                fragments.append({"type": "unresolved", "line": lineno})

        if fragments:
            self.concat_operations.append({
                "target": var_name,
                "fragments": fragments,
                "line": lineno,
                "file": file_path,
            })

    def _handle_function_call(self, var_name: str, node: ast.Call, lineno: int, file_path: str):
        """Handle function calls like str.format(), base64.b64decode(), ''.join()"""

        # Handle base64.b64decode() for simple static strings
        if (isinstance(node.func, ast.Attribute) and
            node.func.attr == 'b64decode' and
            len(node.args) == 1):
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                try:
                    decoded = base64.b64decode(arg.value).decode('utf-8')
                    self.symbol_table[var_name] = (decoded, lineno, True)
                    self.reconstructed.append({
                        "target": var_name,
                        "reconstructed_value": decoded,
                        "status": ReconstructionStatus.FULL,
                        "fragments": [
                            SecretFragment(
                                variable_name=f"base64({arg.value[:20]}...)",
                                value=decoded,
                                file_path=file_path,
                                line_number=lineno,
                                is_resolved=True,
                            )
                        ],
                        "line": lineno,
                        "file": file_path,
                        "method": "base64_decode",
                    })
                except Exception:
                    pass
            elif isinstance(arg, ast.Name) and arg.id in self.symbol_table:
                val, _, resolved = self.symbol_table[arg.id]
                if resolved:
                    try:
                        decoded = base64.b64decode(val).decode('utf-8')
                        self.symbol_table[var_name] = (decoded, lineno, True)
                        self.reconstructed.append({
                            "target": var_name,
                            "reconstructed_value": decoded,
                            "status": ReconstructionStatus.FULL,
                            "fragments": [
                                SecretFragment(
                                    variable_name=f"base64({arg.id})",
                                    value=decoded,
                                    file_path=file_path,
                                    line_number=lineno,
                                    is_resolved=True,
                                )
                            ],
                            "line": lineno,
                            "file": file_path,
                            "method": "base64_decode",
                        })
                    except Exception:
                        pass

        # Handle "".join([...]) pattern
        if (isinstance(node.func, ast.Attribute) and
            node.func.attr == 'join' and
            isinstance(node.func.value, ast.Constant) and
            isinstance(node.func.value.value, str)):

            separator = node.func.value.value
            if len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
                fragments = []
                for elt in node.args[0].elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        fragments.append({"type": "literal", "value": elt.value, "line": lineno})
                    elif isinstance(elt, ast.Name):
                        fragments.append({"type": "variable", "name": elt.id, "line": lineno})
                    else:
                        fragments.append({"type": "unresolved", "line": lineno})

                if fragments:
                    self.concat_operations.append({
                        "target": var_name,
                        "fragments": fragments,
                        "line": lineno,
                        "file": file_path,
                        "separator": separator,
                    })

        # Handle str.format()
        if (isinstance(node.func, ast.Attribute) and
            node.func.attr == 'format' and
            isinstance(node.func.value, ast.Constant) and
            isinstance(node.func.value.value, str)):

            template = node.func.value.value
            args = node.args
            fragments = [{"type": "literal", "value": template, "line": lineno}]
            format_args = []

            for arg in args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    format_args.append({"type": "literal", "value": arg.value, "line": lineno})
                elif isinstance(arg, ast.Name):
                    format_args.append({"type": "variable", "name": arg.id, "line": lineno})
                else:
                    format_args.append({"type": "unresolved", "line": lineno})

            if format_args:
                self.format_operations.append({
                    "target": var_name,
                    "template": template,
                    "args": format_args,
                    "line": lineno,
                    "file": file_path,
                })

    def _resolve_concatenations(self, file_path: str, lines: List[str]):
        """
        Resolve all found concatenation operations using the symbol table.
        This is where fragments are assembled into complete secrets.
        """
        for op in self.concat_operations:
            fragments: List[SecretFragment] = []
            reconstructed_parts: List[str] = []
            all_resolved = True
            separator = op.get("separator", "")

            for frag in op["fragments"]:
                if frag["type"] == "literal":
                    # Direct string literal
                    fragments.append(SecretFragment(
                        variable_name="[literal]",
                        value=frag["value"],
                        file_path=file_path,
                        line_number=frag.get("line", op["line"]),
                        is_resolved=True,
                    ))
                    reconstructed_parts.append(frag["value"])

                elif frag["type"] == "variable":
                    var_name = frag["name"]
                    if var_name in self.symbol_table:
                        val, var_line, resolved = self.symbol_table[var_name]
                        fragments.append(SecretFragment(
                            variable_name=var_name,
                            value=val,
                            file_path=file_path,
                            line_number=var_line,
                            is_resolved=resolved,
                        ))
                        if resolved:
                            reconstructed_parts.append(val)
                        else:
                            reconstructed_parts.append(f"[{var_name}:UNRESOLVED]")
                            all_resolved = False
                    else:
                        # Variable not found in symbol table
                        fragments.append(SecretFragment(
                            variable_name=var_name,
                            value="[DYNAMIC]",
                            file_path=file_path,
                            line_number=frag.get("line", op["line"]),
                            is_resolved=False,
                        ))
                        reconstructed_parts.append(f"[{var_name}:DYNAMIC]")
                        all_resolved = False

                elif frag["type"] == "unresolved":
                    fragments.append(SecretFragment(
                        variable_name="[unknown]",
                        value="[UNRESOLVED]",
                        file_path=file_path,
                        line_number=frag.get("line", op["line"]),
                        is_resolved=False,
                    ))
                    reconstructed_parts.append("[UNRESOLVED]")
                    all_resolved = False

            # Build the reconstructed value
            reconstructed_value = separator.join(reconstructed_parts)

            # Determine reconstruction status
            if all_resolved and len(fragments) >= 2:
                status = ReconstructionStatus.FULL
            elif any(f.is_resolved for f in fragments) and len(fragments) >= 2:
                status = ReconstructionStatus.PARTIAL
            else:
                status = ReconstructionStatus.UNRESOLVED

            # Only record if there are multiple fragments (actual reconstruction)
            if len(fragments) >= 2:
                # Store the resolved value in the symbol table for downstream propagation
                if all_resolved:
                    self.symbol_table[op["target"]] = (reconstructed_value, op["line"], True)
                else:
                    self.symbol_table[op["target"]] = (reconstructed_value, op["line"], False)

                self.reconstructed.append({
                    "target": op["target"],
                    "reconstructed_value": reconstructed_value,
                    "status": status,
                    "fragments": fragments,
                    "line": op["line"],
                    "file": file_path,
                    "method": "concatenation",
                })

        # Also resolve format operations
        for op in self.format_operations:
            template = op["template"]
            args = op["args"]
            resolved_args = []
            all_resolved = True
            fragments = [SecretFragment(
                variable_name="[template]",
                value=template,
                file_path=file_path,
                line_number=op["line"],
                is_resolved=True,
            )]

            for arg in args:
                if arg["type"] == "literal":
                    resolved_args.append(arg["value"])
                    fragments.append(SecretFragment(
                        variable_name="[literal]",
                        value=arg["value"],
                        file_path=file_path,
                        line_number=arg.get("line", op["line"]),
                        is_resolved=True,
                    ))
                elif arg["type"] == "variable":
                    var_name = arg["name"]
                    if var_name in self.symbol_table:
                        val, var_line, resolved = self.symbol_table[var_name]
                        resolved_args.append(val if resolved else f"[{var_name}]")
                        fragments.append(SecretFragment(
                            variable_name=var_name,
                            value=val,
                            file_path=file_path,
                            line_number=var_line,
                            is_resolved=resolved,
                        ))
                        if not resolved:
                            all_resolved = False
                    else:
                        resolved_args.append(f"[{var_name}:DYNAMIC]")
                        fragments.append(SecretFragment(
                            variable_name=var_name,
                            value="[DYNAMIC]",
                            file_path=file_path,
                            line_number=arg.get("line", op["line"]),
                            is_resolved=False,
                        ))
                        all_resolved = False
                else:
                    resolved_args.append("[UNRESOLVED]")
                    all_resolved = False

            # Try to format the template
            try:
                if all_resolved:
                    reconstructed_value = template.format(*resolved_args)
                else:
                    reconstructed_value = template + " [PARTIAL: " + ", ".join(resolved_args) + "]"
            except (IndexError, KeyError):
                reconstructed_value = template + "(" + ", ".join(resolved_args) + ")"

            status = ReconstructionStatus.FULL if all_resolved else ReconstructionStatus.PARTIAL

            if len(fragments) >= 2:
                self.symbol_table[op["target"]] = (reconstructed_value, op["line"], all_resolved)
                self.reconstructed.append({
                    "target": op["target"],
                    "reconstructed_value": reconstructed_value,
                    "status": status,
                    "fragments": fragments,
                    "line": op["line"],
                    "file": file_path,
                    "method": "format",
                })

    # ─── Regex-Based Analysis (Fallback for non-Python or invalid Python) ──

    def _analyze_with_regex(self, content: str, file_path: str):
        """
        Regex-based fragment detection and reconstruction.
        Used for languages without AST support and as a fallback.
        """
        lines = content.split('\n')
        # Step 1: Build symbol table from simple assignments
        #   var = "value"
        #   var = 'value'
        assignment_pattern = re.compile(
            r'''^\s*(?:(?:const|let|var|export|final|static)\s+)?(\w+)\s*[=:]\s*["']([^"']+)["']\s*[;]?\s*$'''
        )

        for i, line in enumerate(lines):
            match = assignment_pattern.match(line)
            if match:
                var_name = match.group(1)
                value = match.group(2)
                self.symbol_table[var_name] = (value, i + 1, True)

        # Step 2: Find concatenation patterns
        #   var = a + b + c
        #   var = a + "literal" + c
        concat_pattern = re.compile(
            r'^\s*(?:(?:const|let|var|export)\s+)?(\w+)\s*=\s*(.+\+.+)\s*[;]?\s*$'
        )

        for i, line in enumerate(lines):
            match = concat_pattern.match(line)
            if match:
                target = match.group(1)
                expr = match.group(2).strip().rstrip(';')
                fragments = self._parse_concat_expr(expr, i + 1, file_path)
                if fragments and len(fragments) >= 2:
                    self.concat_operations.append({
                        "target": target,
                        "fragments": fragments,
                        "line": i + 1,
                        "file": file_path,
                    })

        self._resolve_concatenations(file_path, lines)

    def _analyze_js_with_regex(self, content: str, file_path: str):
        """JavaScript-specific regex analysis with template literal support."""
        lines = content.split('\n')

        # Build symbol table
        assignment_pattern = re.compile(
            r'''^\s*(?:(?:const|let|var|export)\s+)?(\w+)\s*=\s*["'`]([^"'`]+)["'`]\s*[;]?\s*$'''
        )

        for i, line in enumerate(lines):
            match = assignment_pattern.match(line)
            if match:
                self.symbol_table[match.group(1)] = (match.group(2), i + 1, True)

        # Find concatenation and template literals
        concat_pattern = re.compile(
            r'^\s*(?:(?:const|let|var|export)\s+)?(\w+)\s*=\s*(.+\+.+)\s*[;]?\s*$'
        )

        # Template literal pattern: const key = `${part1}${part2}`
        template_pattern = re.compile(
            r'^\s*(?:(?:const|let|var|export)\s+)?(\w+)\s*=\s*`([^`]*)`\s*[;]?\s*$'
        )

        for i, line in enumerate(lines):
            # Check concatenation
            match = concat_pattern.match(line)
            if match:
                target = match.group(1)
                expr = match.group(2).strip().rstrip(';')
                fragments = self._parse_concat_expr(expr, i + 1, file_path)
                if fragments and len(fragments) >= 2:
                    self.concat_operations.append({
                        "target": target,
                        "fragments": fragments,
                        "line": i + 1,
                        "file": file_path,
                    })

            # Check template literals
            match = template_pattern.match(line)
            if match:
                target = match.group(1)
                template = match.group(2)
                fragments = self._parse_template_literal(template, i + 1, file_path)
                if fragments and len(fragments) >= 2:
                    self.concat_operations.append({
                        "target": target,
                        "fragments": fragments,
                        "line": i + 1,
                        "file": file_path,
                    })

        self._resolve_concatenations(file_path, lines)

    def _parse_concat_expr(self, expr: str, line: int, file_path: str) -> List[Dict]:
        """Parse a concatenation expression into operands."""
        parts = re.split(r'\s*\+\s*', expr)
        fragments = []

        for part in parts:
            part = part.strip()
            # String literal
            str_match = re.match(r'^["\'`](.*)["\'`]$', part)
            if str_match:
                fragments.append({"type": "literal", "value": str_match.group(1), "line": line})
            elif re.match(r'^\w+$', part):
                fragments.append({"type": "variable", "name": part, "line": line})
            elif part:
                fragments.append({"type": "unresolved", "line": line})

        return fragments

    def _parse_template_literal(self, template: str, line: int, file_path: str) -> List[Dict]:
        """Parse a JS template literal: `text${var}more`"""
        fragments = []
        parts = re.split(r'\$\{(\w+)\}', template)

        for i, part in enumerate(parts):
            if i % 2 == 0:
                # Text part
                if part:
                    fragments.append({"type": "literal", "value": part, "line": line})
            else:
                # Variable reference
                fragments.append({"type": "variable", "name": part, "line": line})

        return fragments

    def get_symbol_table(self) -> Dict[str, Tuple[str, int, bool]]:
        """Return the built symbol table (for use by dataflow tracker)."""
        return self.symbol_table.copy()
