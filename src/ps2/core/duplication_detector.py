"""
Duplication Detector Module for PS2.

This module identifies and resolves code duplication in Python projects,
helping to maintain DRY (Don't Repeat Yourself) principles and reduce
maintenance burdens.
"""

import ast
import difflib
import hashlib
import logging
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional, Union


class DuplicationDetector:
    """
    Detector for code duplication in Python projects.
    
    This class identifies duplicated code blocks, functions, and patterns
    across a Python project, helping developers adhere to DRY principles
    and reduce maintenance burdens.
    """
    
    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the duplication detector.
        
        Args:
            project_path: Path to the Python project.
            config: Configuration dictionary for the detector.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.duplication_detector")
        self.enabled = False
        
        # Default settings
        self.default_settings = {
            "min_lines": 6,
            "min_tokens": 25,
            "ignore_comments": True,
            "ignore_docstrings": False,
            "ignore_imports": True,
            "ignore_variable_names": False,
            "function_similarity_threshold": 0.8,
        }
        
        # Apply config settings
        self.settings = {**self.default_settings, **self.config.get("duplication_detector", {})}
        
        # Cache for ASTs
        self._ast_cache = {}
    
    def enable(self) -> None:
        """Enable the duplication detector."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable the duplication detector."""
        self.enabled = False
    
    def detect(self, fix: bool = False) -> Dict:
        """
        Detect code duplications in the project.
        
        Args:
            fix: Whether to automatically fix duplication issues where possible.
            
        Returns:
            Dictionary with duplication detection results.
        """
        if not self.enabled:
            self.logger.warning("Duplication detector is disabled. Enabling for this run.")
            self.enable()
        
        self.logger.info(f"Detecting code duplications (fix: {fix})")
        
        # Collect Python files
        python_files = self._collect_python_files()
        
        # Build AST cache
        self._build_ast_cache(python_files)
        
        # Detect exact duplications (sequence-based)
        exact_duplications = self._detect_exact_duplications(python_files)
        
        # Detect function duplications (functionality-based)
        function_duplications = self._detect_function_duplications()
        
        # Detect similar code patterns
        pattern_duplications = self._detect_pattern_duplications()
        
        # Fix duplications if requested
        fixed_files = []
        if fix and (exact_duplications or function_duplications):
            fixed_files = self._fix_duplications(exact_duplications, function_duplications)
        
        # Build result
        result = {
            "files_analyzed": len(python_files),
            "exact_duplications": exact_duplications,
            "function_duplications": function_duplications,
            "pattern_duplications": pattern_duplications,
            "fixed_files": fixed_files,
        }
        
        # Determine overall status
        total_duplications = (
            len(exact_duplications) +
            len(function_duplications) +
            len(pattern_duplications)
        )
        
        if total_duplications == 0:
            result["status"] = "pass"
            result["message"] = "No code duplications found"
        elif fix and fixed_files:
            result["status"] = "fixed"
            result["message"] = f"Fixed {len(fixed_files)} files with duplications"
        else:
            result["status"] = "fail"
            result["message"] = f"Found {total_duplications} code duplications"
        
        return result
    
    def _collect_python_files(self) -> List[Path]:
        """
        Collect all Python files in the project.
        
        Returns:
            List of paths to Python files.
        """
        python_files = []
        exclude_patterns = self.config.get("analyzer", {}).get("exclude_patterns", [])
        
        for root, dirs, files in os.walk(self.project_path):
            # Filter out directories to exclude
            dirs[:] = [d for d in dirs if not any(re.match(pattern, d) for pattern in exclude_patterns)]
            
            for file in files:
                if file.endswith(".py"):
                    file_path = Path(root) / file
                    # Check if file matches any exclude pattern
                    if not any(re.match(pattern, str(file_path.relative_to(self.project_path))) for pattern in exclude_patterns):
                        python_files.append(file_path)
        
        self.logger.info(f"Found {len(python_files)} Python files")
        return python_files
    
    def _build_ast_cache(self, python_files: List[Path]) -> None:
        """
        Build and cache AST for each Python file.
        
        Args:
            python_files: List of paths to Python files.
        """
        self.logger.info("Building AST cache")
        self._ast_cache = {}
        
        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    source = f.read()
                tree = ast.parse(source, filename=str(file_path))
                
                # Add the source file to the AST for reference
                tree.source_file = file_path
                
                # Add source code for potential fixes
                tree.source_code = source
                
                # Add line mapping for reference
                tree.line_mapping = {}
                for i, line in enumerate(source.splitlines()):
                    tree.line_mapping[i+1] = line
                
                self._ast_cache[file_path] = tree
            except (SyntaxError, UnicodeDecodeError) as e:
                self.logger.warning(f"Failed to parse {file_path}: {e}")
    
    def _detect_exact_duplications(self, python_files: List[Path]) -> List[Dict]:
        """
        Detect exact code duplications using sequence-based approach.
        
        Args:
            python_files: List of paths to Python files.
            
        Returns:
            List of exact code duplication reports.
        """
        self.logger.info("Detecting exact code duplications")
        
        duplications = []
        
        # Extract code blocks from files
        code_blocks = []
        for file_path in python_files:
            file_blocks = self._extract_code_blocks(file_path)
            code_blocks.extend(file_blocks)
        
        # Group blocks by hash
        blocks_by_hash = defaultdict(list)
        for block in code_blocks:
            # Generate a hash of the block content
            block_hash = self._hash_code_block(block["content"])
            blocks_by_hash[block_hash].append(block)
        
        # Find duplicated blocks
        for block_hash, blocks in blocks_by_hash.items():
            if len(blocks) > 1:
                # Skip small blocks
                if len(blocks[0]["content"].splitlines()) < self.settings["min_lines"]:
                    continue
                
                # Check if blocks are from different files or locations
                if self._are_blocks_distinct(blocks):
                    duplications.append({
                        "type": "exact_duplication",
                        "hash": block_hash,
                        "instances": [
                            {
                                "file": str(block["file"].relative_to(self.project_path)),
                                "start_line": block["start_line"],
                                "end_line": block["end_line"],
                                "context": block["context"]
                            }
                            for block in blocks
                        ],
                        "content": blocks[0]["content"],
                        "line_count": len(blocks[0]["content"].splitlines()),
                        "suggested_action": self._suggest_action_for_duplication(blocks)
                    })
        
        return duplications
    
    def _detect_function_duplications(self) -> List[Dict]:
        """
        Detect duplicated functions based on their structure and functionality.
        
        Returns:
            List of function duplication reports.
        """
        self.logger.info("Detecting function duplications")
        
        duplications = []
        
        # Extract all functions from the AST cache
        functions = []
        for file_path, tree in self._ast_cache.items():
            file_functions = self._extract_functions(file_path, tree)
            functions.extend(file_functions)
        
        # Compare functions pairwise for similarity
        for i in range(len(functions)):
            for j in range(i + 1, len(functions)):
                function1 = functions[i]
                function2 = functions[j]
                
                # Skip if functions are from the same class
                if function1["class_name"] and function1["class_name"] == function2["class_name"] and function1["file"] == function2["file"]:
                    continue
                
                # Compute similarity
                similarity = self._compute_function_similarity(function1, function2)
                
                # Check if similarity exceeds threshold
                if similarity >= self.settings["function_similarity_threshold"]:
                    duplications.append({
                        "type": "function_duplication",
                        "similarity": round(similarity, 2),
                        "function1": {
                            "name": function1["name"],
                            "class": function1["class_name"],
                            "file": str(function1["file"].relative_to(self.project_path)),
                            "start_line": function1["start_line"],
                            "end_line": function1["end_line"],
                            "args": function1["args"],
                            "content": function1["content"]
                        },
                        "function2": {
                            "name": function2["name"],
                            "class": function2["class_name"],
                            "file": str(function2["file"].relative_to(self.project_path)),
                            "start_line": function2["start_line"],
                            "end_line": function2["end_line"],
                            "args": function2["args"],
                            "content": function2["content"]
                        },
                        "suggested_action": self._suggest_action_for_function_duplication(function1, function2)
                    })
        
        return duplications
    
    def _detect_pattern_duplications(self) -> List[Dict]:
        """
        Detect similar code patterns across the project.
        
        Returns:
            List of pattern duplication reports.
        """
        self.logger.info("Detecting code pattern duplications")

        # This is a more complex analysis that would use techniques like
        # abstract syntax tree pattern matching or token-based similarity.
        # For now, we'll implement a simplified version based on code sequences.

        # Extract all code sequences
        sequences = []
        for file_path, tree in self._ast_cache.items():
            file_sequences = self._extract_code_sequences(file_path, tree)
            sequences.extend(file_sequences)

        # Group similar sequences
        pattern_groups = self._group_similar_sequences(sequences)

        return [
            {
                "type": "pattern_duplication",
                "pattern_id": f"pattern_{group_id}",
                "instances": [
                    {
                        "file": str(seq["file"].relative_to(self.project_path)),
                        "start_line": seq["start_line"],
                        "end_line": seq["end_line"],
                        "context": seq["context"],
                    }
                    for seq in group
                ],
                "pattern_summary": self._summarize_pattern(group),
                "suggested_action": "Extract common pattern into a utility function or class",
            }
            for group_id, group in enumerate(pattern_groups)
            if len(group) > 1
        ]
    
    def _fix_duplications(self, exact_duplications: List[Dict], function_duplications: List[Dict]) -> List[str]:
        """
        Fix duplication issues where possible.
        
        Args:
            exact_duplications: List of exact duplication reports.
            function_duplications: List of function duplication reports.
            
        Returns:
            List of fixed file paths.
        """
        self.logger.info("Fixing duplication issues")
        
        fixed_files = set()
        
        # Fix exact duplications
        for duplication in exact_duplications:
            action = duplication["suggested_action"]
            if action["type"] == "extract_function":
                # Implement extraction of common code into a utility function
                # This would be a complex refactoring operation
                self.logger.debug(f"Would extract common code into function: {action.get('target_file', 'unknown')}")
            elif action["type"] == "extract_class":
                # Implement extraction of common code into a class
                self.logger.debug(f"Would extract common code into class: {action.get('target_file', 'unknown')}")
            elif action["type"] == "create_utility":
                # Implement creation of utility module
                self.logger.debug(f"Would create utility module: {action.get('target_file', 'unknown')}")
            else:
                self.logger.debug(f"No automatic fix available for exact duplication with hash {duplication['hash']}")
        
        # Fix function duplications
        for duplication in function_duplications:
            action = duplication["suggested_action"]
            if action["type"] == "merge_functions":
                # Implement merging of similar functions
                self.logger.debug(f"Would merge functions {duplication['function1']['name']} and {duplication['function2']['name']}")
            elif action["type"] == "extract_base_class":
                # Implement extraction of base class
                self.logger.debug(f"Would extract base class for {duplication['function1']['class']} and {duplication['function2']['class']}")
            elif action["type"] == "create_utility":
                # Implement creation of utility function
                self.logger.debug(f"Would create utility function: {action.get('target_name', 'unknown')}")
            else:
                self.logger.debug(f"No automatic fix available for function duplication between {duplication['function1']['name']} and {duplication['function2']['name']}")
        
        # Automatic fixing would require complex code transformation
        # For now, we'll just simulate fixes
        # In a full implementation, this would involve:
        # 1. Generate fixed code
        # 2. Write to files
        # 3. Track which files were modified
        
        return list(fixed_files)
    
    def _extract_code_blocks(self, file_path: Path) -> List[Dict]:
        """
        Extract code blocks from a file for duplication detection.
        
        Args:
            file_path: Path to the Python file.
            
        Returns:
            List of code blocks from the file.
        """
        blocks = []
        
        # Get the AST for this file
        if file_path not in self._ast_cache:
            return blocks
        
        tree = self._ast_cache[file_path]
        
        # Get the source code
        if not hasattr(tree, "source_code"):
            return blocks
        
        source_code = tree.source_code
        lines = source_code.splitlines()
        
        # Define block size
        min_lines = self.settings["min_lines"]
        
        # Extract blocks of code
        for start_line in range(1, len(lines) - min_lines + 2):
            for end_line in range(start_line + min_lines - 1, len(lines) + 1):
                # Extract the block
                block_lines = lines[start_line-1:end_line]
                block_content = "\n".join(block_lines)
                
                # Skip if block is too small
                if len(block_content) < self.settings["min_tokens"]:
                    continue
                
                # Process the block content based on settings
                processed_content = self._process_block_content(block_content)
                
                # Skip if processed content is too small
                if len(processed_content) < self.settings["min_tokens"]:
                    continue
                
                # Determine context (e.g., class or function name)
                context = self._get_context_for_lines(file_path, start_line, end_line)
                
                blocks.append({
                    "file": file_path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "content": processed_content,
                    "context": context
                })
        
        return blocks
    
    def _process_block_content(self, content: str) -> str:
        """
        Process block content based on settings.
        
        Args:
            content: Original code block content.
            
        Returns:
            Processed code block content.
        """
        # Remove comments if configured
        if self.settings["ignore_comments"]:
            content = re.sub(r"#.*$", "", content, flags=re.MULTILINE)
        
        # Remove docstrings if configured
        if self.settings["ignore_docstrings"]:
            content = re.sub(r'""".*?"""', "", content, flags=re.DOTALL)
            content = re.sub(r"'''.*?'''", "", content, flags=re.DOTALL)
        
        # Remove import statements if configured
        if self.settings["ignore_imports"]:
            content = re.sub(r"^\s*from\s+.*?import\s+.*$", "", content, flags=re.MULTILINE)
            content = re.sub(r"^\s*import\s+.*$", "", content, flags=re.MULTILINE)
        
        # Normalize variable names if configured
        if self.settings["ignore_variable_names"]:
            # This is a simplified approach - a real implementation would use the AST
            # to identify variables and replace them with placeholders
            var_pattern = r"\b[a-zA-Z_][a-zA-Z0-9_]*\b"
            vars_found = set(re.findall(var_pattern, content))
            
            # Skip keywords
            keywords = {
                "and", "as", "assert", "break", "class", "continue", "def", "del",
                "elif", "else", "except", "False", "finally", "for", "from", "global",
                "if", "import", "in", "is", "lambda", "None", "nonlocal", "not", "or",
                "pass", "raise", "return", "True", "try", "while", "with", "yield"
            }
            
            var_map = {}
            var_counter = 0
            
            for var in vars_found:
                if var not in keywords and var not in var_map:
                    var_map[var] = f"VAR_{var_counter}"
                    var_counter += 1
            
            # Replace variables with placeholders
            for var, placeholder in var_map.items():
                content = re.sub(r"\b" + re.escape(var) + r"\b", placeholder, content)
        
        # Normalize whitespace
        content = re.sub(r"\s+", " ", content)
        content = content.strip()
        
        return content
    
    def _hash_code_block(self, content: str) -> str:
        """
        Generate a hash for a code block.
        
        Args:
            content: Code block content.
            
        Returns:
            Hash string.
        """
        return hashlib.md5(content.encode("utf-8")).hexdigest()
    
    def _are_blocks_distinct(self, blocks: List[Dict]) -> bool:
        """
        Check if blocks are from distinct locations.
        
        Args:
            blocks: List of code blocks.
            
        Returns:
            True if blocks are from distinct locations, False otherwise.
        """
        # Check if blocks are from different files
        files = {block["file"] for block in blocks}
        if len(files) > 1:
            return True

        # Check if blocks are from different functions or classes
        contexts = {block["context"] for block in blocks}
        if len(contexts) > 1:
            return True

        # Check if blocks are from different parts of the same file
        # and don't overlap
        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                if blocks[i]["file"] == blocks[j]["file"] and (blocks[i]["start_line"] <= blocks[j]["end_line"] and 
                                        blocks[i]["end_line"] >= blocks[j]["start_line"]):
                    return False

        return True
    
    def _suggest_action_for_duplication(self, blocks: List[Dict]) -> Dict:
        """
        Suggest an action to fix a duplication.
        
        Args:
            blocks: List of duplicated code blocks.
            
        Returns:
            Dictionary with suggested action.
        """
        # Simple heuristic:
        # - If blocks are in different classes, suggest extracting to a utility function
        # - If blocks are in different files, suggest creating a common utility module
        # - Otherwise, suggest extracting to a method in the common parent class

        contexts = {block["context"] for block in blocks}
        files = {block["file"] for block in blocks}

        if len(files) > 1:
            # Blocks are in different files
            # Suggest creating a utility module
            return {
                "type": "create_utility",
                "target_file": "utils/common.py",
                "description": "Create a utility function in a common module"
            }
        elif len(contexts) > 1 and all("class:" in ctx for ctx in contexts):
            # Blocks are in different classes
            # Suggest extracting to a base class or utility method
            classes = [ctx.split("class:")[1].strip() for ctx in contexts if "class:" in ctx]
            return {
                "type": "extract_class",
                "target_file": str(blocks[0]["file"]),
                "target_class": f"Base{''.join(c[0].upper() + c[1:] for c in classes)}",
                "description": f"Extract common functionality to a base class for {', '.join(classes)}"
            }
        else:
            # Blocks are in the same context
            # Suggest extracting to a function
            return {
                "type": "extract_function",
                "target_file": str(blocks[0]["file"]),
                "target_function": "_common_operation",
                "description": "Extract duplicated code to a common function"
            }
    
    def _extract_functions(self, file_path: Path, tree: ast.Module) -> List[Dict]:
        """
        Extract all functions from an AST.
        
        Args:
            file_path: Path to the Python file.
            tree: AST of the module.
            
        Returns:
            List of function information.
        """
        # Get the source code
        if not hasattr(tree, "source_code"):
            return []
        source_code = tree.source_code



        class FunctionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.current_class = None
                self.functions = []

            def visit_ClassDef(self, node):
                old_class = self.current_class
                self.current_class = node.name
                self.generic_visit(node)
                self.current_class = old_class

            def visit_FunctionDef(self, node):
                # Skip very small functions
                if len(node.body) < 3:
                    return

                # Get function source code
                if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                    start_line = node.lineno
                    end_line = node.end_lineno

                    args = [arg.arg for arg in node.args.args]
                    # Extract function content
                    func_lines = source_code.splitlines()[start_line-1:end_line]
                    func_content = "\n".join(func_lines)

                    # Process function content based on settings
                    processed_content = self._process_function_content(func_content)

                    self.functions.append({
                        "name": node.name,
                        "class_name": self.current_class,
                        "file": file_path,
                        "start_line": start_line,
                        "end_line": end_line,
                        "args": args,
                        "content": processed_content,
                        "original_content": func_content
                    })

                self.generic_visit(node)

            def _process_function_content(self, content):
                # Remove function definition line
                content_lines = content.splitlines()
                if content_lines and content_lines[0].strip().startswith("def "):
                    content = "\n".join(content_lines[1:])

                # Process the content based on settings
                return DuplicationDetector._process_block_content(self, content)


        visitor = FunctionVisitor()
        visitor.visit(tree)

        return visitor.functions
    
    def _compute_function_similarity(self, function1: Dict, function2: Dict) -> float:
        """
        Compute similarity between two functions.
        
        Args:
            function1: First function information.
            function2: Second function information.
            
        Returns:
            Similarity score (0-1).
        """
        # Use difflib's SequenceMatcher for similarity
        matcher = difflib.SequenceMatcher(None, function1["content"], function2["content"])
        content_similarity = matcher.ratio()
        
        # Consider argument similarity
        arg_similarity = self._compute_argument_similarity(function1["args"], function2["args"])
        
        # Weighted combination
        return 0.8 * content_similarity + 0.2 * arg_similarity
    
    def _compute_argument_similarity(self, args1: List[str], args2: List[str]) -> float:
        """
        Compute similarity between function arguments.
        
        Args:
            args1: Arguments of first function.
            args2: Arguments of second function.
            
        Returns:
            Similarity score (0-1).
        """
        if not args1 and not args2:
            return 1.0
        
        if not args1 or not args2:
            return 0.0
        
        # Count common arguments (ignore self in class methods)
        common_args = set(args1) & set(args2)
        if "self" in common_args:
            common_args.remove("self")
            args1_filtered = [arg for arg in args1 if arg != "self"]
            args2_filtered = [arg for arg in args2 if arg != "self"]
        else:
            args1_filtered = args1
            args2_filtered = args2
        
        if not args1_filtered and not args2_filtered:
            return 1.0
        
        if not args1_filtered or not args2_filtered:
            return 0.0
        
        # Compute Jaccard similarity: |A ∩ B| / |A ∪ B|
        union_size = len(set(args1_filtered) | set(args2_filtered))
        common_size = len(set(args1_filtered) & set(args2_filtered))
        
        return common_size / union_size
    
    def _suggest_action_for_function_duplication(self, function1: Dict, function2: Dict) -> Dict:
        """
        Suggest an action to fix function duplication.
        
        Args:
            function1: First function information.
            function2: Second function information.
            
        Returns:
            Dictionary with suggested action.
        """
        if function1["file"] != function2["file"]:
            # Functions are in different files
            return {
                "type": "create_utility",
                "target_file": "utils/common.py",
                "target_name": self._merge_function_names(function1["name"], function2["name"]),
                "description": "Create a common utility function"
            }
        if function1["class_name"] and function2["class_name"]:
            # Functions are in classes in the same file
            return {
                "type": "extract_base_class",
                "target_file": str(function1["file"]),
                "base_class": f"Base{function1['class_name']}",
                "description": f"Extract a base class with common functionality for {function1['class_name']} and {function2['class_name']}"
            }
        else:
            # Functions are in the same file but not in classes
            return {
                "type": "merge_functions",
                "target_file": str(function1["file"]),
                "target_function": self._merge_function_names(function1["name"], function2["name"]),
                "description": f"Merge similar functions {function1['name']} and {function2['name']}"
            }
    
    def _merge_function_names(self, name1: str, name2: str) -> str:
        """
        Merge two function names.
        
        Args:
            name1: First function name.
            name2: Second function name.
            
        Returns:
            Merged function name.
        """
        # Find common prefix or suffix
        common_prefix = os.path.commonprefix([name1, name2])
        common_suffix = os.path.commonprefix([name1[::-1], name2[::-1]])[::-1]

        if len(common_prefix) >= 3:
            return f"{common_prefix}Common"
        elif len(common_suffix) >= 3:
            return f"Common{common_suffix.capitalize()}"
        else:
            return f"common_{name1.lower()}_operation"
    
    def _extract_code_sequences(self, file_path: Path, tree: ast.Module) -> List[Dict]:
        """
        Extract code sequences for pattern detection.
        
        Args:
            file_path: Path to the Python file.
            tree: AST of the module.
            
        Returns:
            List of code sequences.
        """
        sequences = []



        class SequenceVisitor(ast.NodeVisitor):
            def __init__(self):
                self.sequences = []
                self.current_context = "module"

            def visit_ClassDef(self, node):
                self._extracted_from_visit_ClassDef_23('class:', node, "class_body")

            def _extracted_from_visit_ClassDef_23(self, arg0, node, arg2):
                old_context = self.current_context
                self.current_context = f"{arg0}{node.name}"

                # Check class body for patterns
                self._extract_sequence_from_nodes(node.body, arg2)

                self.generic_visit(node)
                self.current_context = old_context

            def visit_FunctionDef(self, node):
                self._extracted_from_visit_ClassDef_23('function:', node, "function_body")

            def _extract_sequence_from_nodes(self, nodes: List[ast.stmt], context: str):
                for node in nodes:
                    if isinstance(node, (ast.Expr, ast.FunctionDef, ast.ClassDef)):
                        continue

                    sequence = {
                        "context": self.current_context,
                        "type": context,
                        "start_line": node.lineno,
                        "end_line": node.end_lineno,
                        "content": self._get_node_content(node)
                    }
                    sequences.append(sequence)

                # Check function body for patterns
                self._extract_sequence_from_nodes(node.body, "function_body")

                visitor = SequenceVisitor()
                visitor.visit(tree)
                return sequences





