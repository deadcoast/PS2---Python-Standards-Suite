"""
Logging Utilities Module for PS2.

This module provides utility functions for setting up and using logging
throughout the PS2 system, including decorators for function call logging
and execution time tracking.
"""

from typing import Any, Callable, Dict, List, Optional, Union, TypeVar, cast  # TODO: Remove unused imports

# Type variable for decorator return types
F = TypeVar("F", bound=Callable[..., Any])


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[Union[str, Path]] = None,
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
from typing import Any, Callable, Dict, List, Optional, Union, TypeVar, cast  # TODO: Remove unused imports  # TODO: Line too long, needs manual fixing  # TODO: Remove unused imports
    use_colors: bool = True,
    max_file_size: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
) -> logging.Logger:
    """
    Set up logging configuration for PS2.

    Args:
        level: Logging level. Defaults to INFO.
        log_file: Path to log file. If None, logs only to console. Defaults to None.  # TODO: Line too long, needs manual fixing
        log_format: Log message format. Defaults to standard format with timestamp, name, level, and message.  # TODO: Line too long, needs manual fixing
        date_format: Date format for log messages. Defaults to ISO-like format.
        use_colors: Whether to use colored output in console (if supported). Defaults to True.
        max_file_size: Maximum size of log file before rotation (in bytes). Defaults to 10 MB.
        backup_count: Number of backup log files to keep. Defaults to 5.

    Returns:
        Configured root logger.
    """
    # Get the root logger
    root_logger = logging.getLogger()

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Set log level
    root_logger.setLevel(level)

    # Create formatter
    formatter = logging.Formatter(log_format, date_format)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Use colored output if requested and supported
    if use_colors:
        try:

            coloredlogs.install(
                level = (
                    level, logger=root_logger, fmt=log_format, datefmt=date_format
                )
            )
        except ImportError:
            # Fall back to standard logging if coloredlogs is not available
            pass

    # Create file handler if log file is specified
    if log_file:
        # Ensure the log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Create rotating file handler
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_file_size, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Create PS2 logger with same settings
    ps2_logger = logging.getLogger("ps2")
    ps2_logger.setLevel(level)

    return ps2_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name, properly namespaced under ps2.

    Args:
        name: Logger name (without ps2 prefix).

    Returns:
        Logger instance.
    """
    if name.startswith("ps2."):
        return logging.getLogger(name)
    else:
        return logging.getLogger(f"ps2.{name}")


def log_function_call(level: int = logging.DEBUG) -> Callable[[F], F]:
    """
    Decorator to log function calls with arguments and return values.

    Args:
        level: Logging level to use. Defaults to DEBUG.

    Returns:
        Decorator function.
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get function details
            module = func.__module__
            name = func.__qualname__

            # Get logger
            logger = get_logger(module)

            # Format args and kwargs for logging
            args_str = ", ".join(repr(a) for a in args)
            kwargs_str = ", ".join(f"{k}={repr(v)}" for k, v in kwargs.items())
            params_str = ", ".join(filter(None, [args_str, kwargs_str]))

            # Log function call
            logger.log(level, f"Calling {name}({params_str})")

            # Call function
            try:
                result = func(*args, **kwargs)

                # Log return value (truncate if too long)
                result_str = repr(result)
                if len(result_str) > 1000:
                    result_str = result_str[:1000] + "..."

                logger.log(level, f"{name} returned: {result_str}")

                return result

            except Exception as e:
                # Log exception
                logger.exception(f"{name} raised {type(e).__name__}: {e}")
                raise

        return cast(F, wrapper)

    return decorator


def log_execution_time(level: int = logging.DEBUG) -> Callable[[F], F]:
    """
    Decorator to log function execution time.

    Args:
        level: Logging level to use. Defaults to DEBUG.

    Returns:
        Decorator function.
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get function details
            module = func.__module__
            name = func.__qualname__

            # Get logger
            logger = get_logger(module)

            # Record start time
            start_time = time.time()

            # Call function
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                # Calculate execution time
                execution_time = time.time() - start_time
                logger.log(level,
                    f"{name} executed in {execution_time:.6f} seconds")
                # Log execution time
                logger.log(level, f"{name} executed in {execution_time:.6f} seconds")

        return cast(F, wrapper)

    return decorator


class LoggingContext:
    """
    Context manager for temporarily changing the logging level.

    Example:
        with LoggingContext("ps2.analyzer", logging.DEBUG):
            # Code here will have DEBUG logging for ps2.analyzer
        # Logging level is restored after the block
    """

    def __init__(self, logger_name: str, level: int):
        """
        Initialize the logging context.

        Args:
            logger_name: Name of the logger to modify.
            level: Temporary logging level to set.
        """
        self.logger = logging.getLogger(logger_name)
        self.level = level
        self.old_level = self.logger.level

    def __enter__(self) -> logging.Logger:
        """
        Enter the context, setting the temporary logging level.

        Returns:
            The logger with the modified level.
        """
        self.old_level = self.logger.level
        self.logger.setLevel(self.level)
        return self.logger

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """
        Exit the context, restoring the original logging level.

        Args:
            exc_type: Exception type, if an exception was raised.
            exc_val: Exception value, if an exception was raised.
            exc_tb: Exception traceback, if an exception was raised.
        """
        self.logger.setLevel(self.old_level)