"""
Task Manager Module for PS2.

This module manages a task list for issues that require manual intervention,
tracking technical debt and providing a "scratchpad" for developers to address
issues that cannot be automatically fixed by PS2.
"""

from typing import Dict, List, Set, Tuple, Any, Optional, Union  # TODO: Remove unused imports


class TaskManager:
    """
from typing import Dict, List, Set, Tuple, Any, Optional, Union  # TODO: Remove unused imports  # TODO: Line too long, needs manual fixing  # TODO: Remove unused imports

    This class creates and manages a task list for issues that require manual
    intervention, providing a "scratchpad" for developers to track and address
    technical debt and other issues in the codebase.
    """

    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the task manager.

        Args:
            project_path: Path to the Python project.
            config: Configuration dictionary for the manager.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.task_manager")
        self.enabled = False

        # Default settings
        self.default_settings = {
            "task_file": "ps2_tasks.json",
            "priority_levels": ["critical", "high", "medium", "low"],
            "default_priority": "medium",
            "assign_tasks": False,
            "track_resolution_time": True,
        }

        # Apply config settings
        self.settings = {**self.default_settings, **self.config.get(
            "task_manager",
            {})

        # Tasks storage
        self._tasks = []
        self._task_file_path = self.project_path / self.settings["task_file"]

        # Load existing tasks if available
        self._load_tasks()

    def enable(self) -> None:
        """Enable the task manager."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the task manager."""
        self.enabled = False

    def generate_tasks(self) -> Dict:
        """
        Generate a task list from all registered issues.

        Returns:
            Dictionary with task generation results.
        """
        if not self.enabled:
            self.logger.warning("Task manager is disabled. Enabling for this run.")
            self.enable()

        self.logger.info("Generating task list")

        # Note: In a real implementation, other PS2 modules would register tasks
        # throughout their operations. Here we'll simulate this by creating tasks
        # from scratch each time (normally we would update existing tasks).

        # Scan the project for issues that need manual intervention
        new_tasks = self._scan_for_tasks()

        # Merge with existing tasks
        updated_tasks = self._merge_tasks(new_tasks)

        # Save tasks to file
        self._save_tasks()

        # Build result
        result = {
            "total_tasks": len(self._tasks),
            "new_tasks": len(new_tasks),
            "updated_tasks": len(updated_tasks),
            "active_tasks": len([t for t in self._tasks if t["status"] == "open"]),
            "tasks_by_priority": self._count_tasks_by_priority(),
            "tasks_by_category": self._count_tasks_by_category(),
            "tasks_by_status": self._count_tasks_by_status(),
            "task_file": str(self._task_file_path.relative_to(self.project_path)),
        }

        # Determine overall status
        if result["total_tasks"] == 0:
            result["status"] = "pass"
            result["message"] = "No tasks requiring manual intervention"
        else:
            result["status"] = "info"
            result["message"] = (
                f"Found {result['active_tasks']} active tasks requiring attention"
            )

        return result

    def add_task(
        self,
        title: str,
        category: str,
        description: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> Dict:
        """
        Add a new task to the task list.

        Args:
            title: Task title.
            category: Task category (e.g., 'code_quality', 'security', etc.).
            description: Detailed description of the task.
            file_path: Path to the file needing attention.
            line_number: Line number in the file.
            priority: Task priority (e.g., 'high', 'medium', 'low').
            assignee: Person assigned to the task.

        Returns:
            The created task.
        """
        if not self.enabled:
            self.logger.warning("Task manager is disabled. Enabling for this run.")
            self.enable()

        # Set default priority if not provided
        if priority is None:
            priority = self.settings["default_priority"]

        # Validate priority
        if priority not in self.settings["priority_levels"]:
            self.logger.warning(f"Invalid priority: {priority}. Using default.")
            priority = self.settings["default_priority"]

        # Create task
        task = {
            "id": self._generate_task_id(),
            "title": title,
            "category": category,
            "description": description,
            "file_path": file_path,
            "line_number": line_number,
            "priority": priority,
            "status": "open",
            "created_date": self._get_current_datetime(),
            "updated_date": self._get_current_datetime(),
            "assignee": assignee if self.settings["assign_tasks"] else None,
            "resolution": None,
            "resolution_date": None,
        }

        # Add to tasks list
        self._tasks.append(task)

        # Save tasks to file
        self._save_tasks()

        return task

    def update_task(self, task_id: str, updates: Dict) -> Optional[Dict]:
        """
        Update an existing task.

        Args:
            task_id: ID of the task to update.
            updates: Dictionary of fields to update.

        Returns:
            Updated task or None if task not found.
        """
        if not self.enabled:
            self.logger.warning("Task manager is disabled. Enabling for this run.")
            self.enable()

        # Find task
        task_index = next(
            (i for i, t in enumerate(self._tasks) if t["id"] == task_id), None
        )
        if task_index is None:
            self.logger.warning(f"Task not found: {task_id}")
            return None

        # Update task
        task = self._tasks[task_index]

        # Handle status change
        if "status" in updates and updates["status"] != task["status"]:
            if updates["status"] == "resolved":
                updates["resolution_date"] = self._get_current_datetime()
            elif task["status"] == "resolved":
                # Re-opening a resolved task
                updates["resolution_date"] = None
                updates["resolution"] = None

        # Apply updates
        for key, value in updates.items():
            if key in task:
                task[key] = value

        # Update modified date
        task["updated_date"] = self._get_current_datetime()

        # Save tasks to file
        self._save_tasks()

        return task

    def get_tasks(
        self,
        status: Optional[str] = None,
        category: Optional[str] = None,
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> List[Dict]:
        """
        Get tasks filtered by criteria.

        Args:
            status: Filter by status.
            category: Filter by category.
            priority: Filter by priority.
            assignee: Filter by assignee.

        Returns:
            List of tasks matching the criteria.
        """
        if not self.enabled:
            self.logger.warning("Task manager is disabled. Enabling for this run.")
            self.enable()

        # Start with all tasks
        filtered_tasks = self._tasks.copy()

        # Apply filters
        if status is not None:
            filtered_tasks = [t for t in filtered_tasks if t["status"] == status]

        if category is not None:
            filtered_tasks = [t for t in filtered_tasks if t["category"] == category]

        if priority is not None:
            filtered_tasks = [t for t in filtered_tasks if t["priority"] == priority]

        if assignee is not None:
            filtered_tasks = [t for t in filtered_tasks if t["assignee"] == assignee]

        return filtered_tasks

    def get_task(self, task_id: str) -> Optional[Dict]:
        """
        Get a specific task by ID.

        Args:
            task_id: ID of the task to retrieve.

        Returns:
            Task dictionary or None if not found.
        """
        if not self.enabled:
            self.logger.warning("Task manager is disabled. Enabling for this run.")
            self.enable()

        return next((t for t in self._tasks if t["id"] == task_id), None)

    def resolve_task(self, task_id: str, resolution: str) -> Optional[Dict]:
        """
        Mark a task as resolved.

        Args:
            task_id: ID of the task to resolve.
            resolution: Description of how the task was resolved.

        Returns:
            Updated task or None if task not found.
        """
        if not self.enabled:
            self.logger.warning("Task manager is disabled. Enabling for this run.")
            self.enable()

        # Update task
        return self.update_task(
            task_id,
            {
                "status": "resolved",
                "resolution": resolution,
                "resolution_date": self._get_current_datetime(),
            },
    def reopen_task(self,
        task_id: str,
        reason: Optional[str] = None)

    def reopen_task(self, task_id: str, reason: Optional[str] = None) -> Optional[Dict]:
        """
        Reopen a resolved task.

        Args:
            task_id: ID of the task to reopen.
            reason: Reason for reopening the task.

        Returns:
            Updated task or None if task not found.
        """
        if not self.enabled:
            self.logger.warning("Task manager is disabled. Enabling for this run.")
            self.enable()

        # Get current task
        task = self.get_task(task_id)
        if task is None:
            return None

        # Update description if reason provided
        description = task["description"]
        if reason:
            description = f"{description}\n\nReopened: {reason}"

        # Update task
        return self.update_task(
            task_id,
            {
                "status": "open",
                "resolution": None,
                "resolution_date": None,
                "description": description,
            },
        )

    def _scan_for_tasks(self) -> List[Dict]:
        """
        Scan the project for issues that need manual intervention.

        Returns:
            List of new tasks.
        """
        # This would normally involve scanning the project for issues
        # and collecting them from other PS2 modules
        # For now, we'll just return an empty list

        return []

    def _merge_tasks(self, new_tasks: List[Dict]) -> List[Dict]:
        """
        Merge new tasks with existing tasks.

        Args:
            new_tasks: List of new tasks.

        Returns:
            List of updated tasks.
        """
        updated_tasks = []

        # Check each new task against existing tasks
        for new_task in new_tasks:
            # Try to find a matching existing task
            existing_task = None

            # Match by file path and line number if available
            if new_task.get("file_path") and new_task.get("line_number"):
                existing_task = next(
                    (
                        t
                        for t in self._tasks
                        if t.get("file_path") == new_task["file_path"]
                        and t.get("line_number") == new_task["line_number"]
                        and t["status"] != "resolved"
                    ),
                    None,
                )

            # Match by title and category if no match by location
            if existing_task is None:
                existing_task = next(
                    (
                        t
                        for t in self._tasks
                        if t["title"] == new_task["title"]
                        and t["category"] == new_task["category"]
                        and t["status"] != "resolved"
                    ),
                    None,
                )

            # Update existing task or add new task
            if existing_task:
                # Update existing task
                existing_task["updated_date"] = self._get_current_datetime()
                existing_task["description"] = new_task["description"]

                # Keep the higher priority
                if self._get_priority_level(
                    new_task["priority"]
                ) > self._get_priority_level(existing_task["priority"]):
                    existing_task["priority"] = new_task["priority"]

                updated_tasks.append(existing_task)
            else:
                self._extracted_from__merge_tasks_59(new_task, updated_tasks)
        return updated_tasks

    # TODO Rename this here and in `_merge_tasks`
    def _extracted_from__merge_tasks_59(self, new_task, updated_tasks):
        # Add new task with generated ID
        new_task["id"] = self._generate_task_id()
        new_task["created_date"] = self._get_current_datetime()
        new_task["updated_date"] = self._get_current_datetime()
        new_task["status"] = "open"
        new_task["resolution"] = None
        new_task["resolution_date"] = None

        self._tasks.append(new_task)
        updated_tasks.append(new_task)

    def _load_tasks(self) -> None:
        """Load tasks from the task file."""
        if self._task_file_path.exists():
            try:
                with open(self._task_file_path, "r", encoding="utf-8") as f:
                    self._tasks = json.load(f)
                    self.logger.info(
                        f"Loaded {len(self._tasks)} tasks from {self._task_file_path}"
                    )
            except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
                self.logger.warning(f"Failed to load tasks: {e}")
                self._tasks = []
        else:
            self._tasks = []

    def _save_tasks(self) -> None:
        """Save tasks to the task file."""
        try:
            with open(self._task_file_path, "w", encoding="utf-8") as f:
                json.dump(self._tasks, f, indent=2)
                self.logger.info(
                    f"Saved {len(self._tasks)} tasks to {self._task_file_path}"
                )
        except (FileNotFoundError, PermissionError) as e:
            self.logger.warning(f"Failed to save tasks: {e}")

    def _generate_task_id(self) -> str:
        """
        Generate a unique task ID.

        Returns:
            Unique task ID.
        """
        # Get current timestamp for uniqueness
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

        # Generate sequential ID based on number of existing tasks
        task_number = len(self._tasks) + 1

        return f"PS2-{task_number:04d}-{timestamp}"

    def _get_current_datetime(self) -> str:
        """
        Get current datetime as string.

        Returns:
            Current datetime string.
        """
        return datetime.now().isoformat()

    def _count_tasks_by_priority(self) -> Dict[str, int]:
        """
        Count tasks by priority.

        Returns:
            Dictionary mapping priority levels to counts.
        """
        result = {priority: 0 for priority in self.settings["priority_levels"]}

        for task in self._tasks:
            if task["priority"] in result:
                result[task["priority"]] += 1

        return result

    def _count_tasks_by_category(self) -> Dict[str, int]:
        """
        Count tasks by category.

        Returns:
            Dictionary mapping categories to counts.
        """
        result = {}

        for task in self._tasks:
            category = task["category"]
            if category not in result:
                result[category] = 0
            result[category] += 1

        return result

    def _count_tasks_by_status(self) -> Dict[str, int]:
        """
        Count tasks by status.

        Returns:
            Dictionary mapping status values to counts.
        """
        result = {"open": 0, "resolved": 0}

        for task in self._tasks:
            status = task["status"]
            if status in result:
                result[status] += 1

        return result

    def _get_priority_level(self, priority: str) -> int:
        """
        Get numeric level for a priority string.

        Args:
            priority: Priority string.

        Returns:
            Numeric priority level (higher is more important).
        """
        try:
            return self.settings["priority_levels"].index(priority)
        except ValueError:
            return self.settings["priority_levels"].index(
                self.settings["default_priority"]
            )