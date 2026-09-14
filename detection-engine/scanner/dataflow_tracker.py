"""
Dataflow Tracker — CORE NOVELTY MODULE

Program-Flow Propagation Tracking

After secrets are reconstructed from fragments, this module tracks
how the reconstructed value propagates through the program via:
- Variable-to-variable assignments
- Dictionary/object insertions
- Function argument passing
- Return values

The propagation is represented as a directed graph where:
- Nodes = variables/expressions at specific code locations
- Edges = value flow (assignment, parameter passing, etc.)

Limitations (documented by design):
- Single-file analysis only
- Does not follow function calls across files
- Does not handle complex control flow (if/else branching)
- Reports what it CAN track and marks the rest as unknown
"""

import re
import ast
from typing import List, Dict, Set, Optional, Tuple
from .models import PropagationGraph, PropagationNode, PropagationEdge


class DataflowTracker:
    """
    Tracks how a secret value propagates through program flow.

    Given a set of variable names that hold secret values (from the
    secret reconstructor), this module traces all subsequent uses
    of those variables to build a propagation graph.
    """

    def __init__(self):
        self.propagation_graphs: Dict[str, PropagationGraph] = {}

    def track_python(
        self,
        content: str,
        file_path: str,
        secret_variables: Dict[str, Tuple[str, int]],
    ) -> Dict[str, PropagationGraph]:
        """
        Track propagation of secret variables through Python code.

        Args:
            content: Source code content
            file_path: Path to the file
            secret_variables: Dict of {variable_name: (value, line_number)}

        Returns:
            Dict mapping variable names to their propagation graphs
        """
        self.propagation_graphs = {}

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return self._track_with_regex(content, file_path, secret_variables)

        lines = content.split('\n')

        for var_name, (value, origin_line) in secret_variables.items():
            graph = PropagationGraph()

            # Add the origin node
            origin_code = lines[origin_line - 1].strip() if origin_line <= len(lines) else ""
            graph.add_node(PropagationNode(
                variable=var_name,
                file_path=file_path,
                line_number=origin_line,
                operation="assignment",
                code_snippet=origin_code,
            ))

            # Track through the AST
            tainted_vars: Set[str] = {var_name}
            self._trace_python_ast(tree, var_name, tainted_vars, graph, file_path, lines)

            self.propagation_graphs[var_name] = graph

        return self.propagation_graphs

    def track_generic(
        self,
        content: str,
        file_path: str,
        secret_variables: Dict[str, Tuple[str, int]],
        language: str,
    ) -> Dict[str, PropagationGraph]:
        """Track propagation for any language."""
        if language == "Python":
            return self.track_python(content, file_path, secret_variables)
        else:
            return self._track_with_regex(content, file_path, secret_variables)

    def _trace_python_ast(
        self,
        tree: ast.AST,
        origin_var: str,
        tainted_vars: Set[str],
        graph: PropagationGraph,
        file_path: str,
        lines: List[str],
    ):
        """
        Walk the AST and trace how tainted variables propagate.
        Uses a taint-tracking approach: any variable assigned from
        a tainted variable also becomes tainted.
        """
        # Collect all assignment nodes sorted by line number
        assignments = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                assignments.append(node)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                assignments.append(node)

        # Sort by line number for ordered processing
        assignments.sort(key=lambda n: getattr(n, 'lineno', 0))

        for node in assignments:
            if isinstance(node, ast.Assign):
                self._handle_assignment_propagation(
                    node, tainted_vars, graph, file_path, lines
                )
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                self._handle_call_propagation(
                    node.value, tainted_vars, graph, file_path, lines
                )

    def _handle_assignment_propagation(
        self,
        node: ast.Assign,
        tainted_vars: Set[str],
        graph: PropagationGraph,
        file_path: str,
        lines: List[str],
    ):
        """Handle taint propagation through assignments."""
        if len(node.targets) != 1:
            return

        target = node.targets[0]
        value = node.value
        line_code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""

        # Case 1: Simple assignment: x = tainted_var
        if isinstance(target, ast.Name) and isinstance(value, ast.Name):
            if value.id in tainted_vars:
                tainted_vars.add(target.id)
                graph.add_node(PropagationNode(
                    variable=target.id,
                    file_path=file_path,
                    line_number=node.lineno,
                    operation="assignment",
                    code_snippet=line_code,
                ))
                graph.add_edge(PropagationEdge(
                    source_variable=value.id,
                    target_variable=target.id,
                    edge_type="assignment",
                ))

        # Case 2: Dictionary assignment: headers = {"Authorization": tainted_var}
        if isinstance(target, ast.Name) and isinstance(value, ast.Dict):
            for key, val in zip(value.keys, value.values):
                if isinstance(val, ast.Name) and val.id in tainted_vars:
                    key_name = ""
                    if isinstance(key, ast.Constant):
                        key_name = str(key.value)
                    dict_entry = f"{target.id}.{key_name}" if key_name else f"{target.id}[?]"
                    tainted_vars.add(target.id)
                    graph.add_node(PropagationNode(
                        variable=dict_entry,
                        file_path=file_path,
                        line_number=node.lineno,
                        operation="dict_value",
                        code_snippet=line_code,
                    ))
                    graph.add_edge(PropagationEdge(
                        source_variable=val.id,
                        target_variable=dict_entry,
                        edge_type="dict_insertion",
                    ))

        # Case 3: Subscript assignment: headers["Authorization"] = tainted_var
        if isinstance(target, ast.Subscript):
            if isinstance(value, ast.Name) and value.id in tainted_vars:
                if isinstance(target.value, ast.Name):
                    container = target.value.id
                    key_name = ""
                    if isinstance(target.slice, ast.Constant):
                        key_name = str(target.slice.value)
                    entry = f"{container}[{key_name}]" if key_name else f"{container}[?]"
                    tainted_vars.add(container)
                    graph.add_node(PropagationNode(
                        variable=entry,
                        file_path=file_path,
                        line_number=node.lineno,
                        operation="subscript_assignment",
                        code_snippet=line_code,
                    ))
                    graph.add_edge(PropagationEdge(
                        source_variable=value.id,
                        target_variable=entry,
                        edge_type="subscript_assignment",
                    ))

        # Case 4: Concatenation involving tainted var
        if isinstance(target, ast.Name) and isinstance(value, ast.BinOp):
            if isinstance(value.op, ast.Add):
                left_tainted = (isinstance(value.left, ast.Name) and value.left.id in tainted_vars)
                right_tainted = (isinstance(value.right, ast.Name) and value.right.id in tainted_vars)
                if left_tainted or right_tainted:
                    tainted_vars.add(target.id)
                    source = value.left.id if left_tainted else value.right.id
                    graph.add_node(PropagationNode(
                        variable=target.id,
                        file_path=file_path,
                        line_number=node.lineno,
                        operation="concatenation",
                        code_snippet=line_code,
                    ))
                    graph.add_edge(PropagationEdge(
                        source_variable=source,
                        target_variable=target.id,
                        edge_type="concatenation",
                    ))

    def _handle_call_propagation(
        self,
        node: ast.Call,
        tainted_vars: Set[str],
        graph: PropagationGraph,
        file_path: str,
        lines: List[str],
    ):
        """Handle taint propagation through function calls (sinks)."""
        line_code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""

        # Check if any argument is tainted
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                func_name = self._get_func_name(node.func)
                graph.add_node(PropagationNode(
                    variable=f"{func_name}({arg.id})",
                    file_path=file_path,
                    line_number=node.lineno,
                    operation="function_argument",
                    code_snippet=line_code,
                ))
                graph.add_edge(PropagationEdge(
                    source_variable=arg.id,
                    target_variable=f"{func_name}()",
                    edge_type="parameter_pass",
                ))

        # Check keyword arguments
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name) and kw.value.id in tainted_vars:
                func_name = self._get_func_name(node.func)
                kw_name = kw.arg or "**kwargs"
                graph.add_node(PropagationNode(
                    variable=f"{func_name}({kw_name}={kw.value.id})",
                    file_path=file_path,
                    line_number=node.lineno,
                    operation="keyword_argument",
                    code_snippet=line_code,
                ))
                graph.add_edge(PropagationEdge(
                    source_variable=kw.value.id,
                    target_variable=f"{func_name}({kw_name}=)",
                    edge_type="parameter_pass",
                ))

    def _get_func_name(self, node) -> str:
        """Extract function name from a call expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
            elif isinstance(node.value, ast.Attribute):
                return f"...{node.attr}"
            return node.attr
        return "[function]"

    def _track_with_regex(
        self,
        content: str,
        file_path: str,
        secret_variables: Dict[str, Tuple[str, int]],
    ) -> Dict[str, PropagationGraph]:
        """
        Regex-based propagation tracking for non-Python files.
        Less precise but provides basic tracking.
        """
        lines = content.split('\n')
        graphs = {}

        for var_name, (value, origin_line) in secret_variables.items():
            graph = PropagationGraph()

            # Add origin node
            origin_code = lines[origin_line - 1].strip() if origin_line <= len(lines) else ""
            graph.add_node(PropagationNode(
                variable=var_name,
                file_path=file_path,
                line_number=origin_line,
                operation="assignment",
                code_snippet=origin_code,
            ))

            tainted_vars: Set[str] = {var_name}

            # Scan for uses of the tainted variable
            for i, line in enumerate(lines):
                if i + 1 <= origin_line:
                    continue

                for tainted in list(tainted_vars):
                    if tainted not in line:
                        continue

                    # Check for assignment: new_var = tainted_var
                    assign_match = re.match(
                        rf'^\s*(?:(?:const|let|var|export)\s+)?(\w+)\s*=\s*.*\b{re.escape(tainted)}\b',
                        line
                    )
                    if assign_match:
                        new_var = assign_match.group(1)
                        if new_var != tainted:
                            tainted_vars.add(new_var)
                            graph.add_node(PropagationNode(
                                variable=new_var,
                                file_path=file_path,
                                line_number=i + 1,
                                operation="assignment",
                                code_snippet=line.strip(),
                            ))
                            graph.add_edge(PropagationEdge(
                                source_variable=tainted,
                                target_variable=new_var,
                                edge_type="assignment",
                            ))

                    # Check for function call: func(tainted_var)
                    call_match = re.search(
                        rf'(\w+(?:\.\w+)*)\s*\([^)]*\b{re.escape(tainted)}\b[^)]*\)',
                        line
                    )
                    if call_match:
                        func_name = call_match.group(1)
                        graph.add_node(PropagationNode(
                            variable=f"{func_name}({tainted})",
                            file_path=file_path,
                            line_number=i + 1,
                            operation="function_argument",
                            code_snippet=line.strip(),
                        ))
                        graph.add_edge(PropagationEdge(
                            source_variable=tainted,
                            target_variable=f"{func_name}()",
                            edge_type="parameter_pass",
                        ))

                    # Check for dict/object: {"key": tainted_var} or key: tainted_var
                    dict_match = re.search(
                        rf'["\'](\w+)["\']\s*:\s*\b{re.escape(tainted)}\b',
                        line
                    )
                    if dict_match:
                        key_name = dict_match.group(1)
                        graph.add_node(PropagationNode(
                            variable=f"[dict].{key_name}",
                            file_path=file_path,
                            line_number=i + 1,
                            operation="dict_value",
                            code_snippet=line.strip(),
                        ))
                        graph.add_edge(PropagationEdge(
                            source_variable=tainted,
                            target_variable=f"[dict].{key_name}",
                            edge_type="dict_insertion",
                        ))

            graphs[var_name] = graph

        return graphs
