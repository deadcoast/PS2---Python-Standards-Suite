"""
CLI Commands Package for PS2.

This package contains the individual command modules for the PS2 CLI,
providing specific functionality for different PS2 operations.
"""

from ps2.cli.commands.analyze import AnalyzeCommand
from ps2.cli.commands.check import CheckCommand
from ps2.cli.commands.fix import FixCommand
from ps2.cli.commands.generate import GenerateCommand
from ps2.cli.commands.monitor import MonitorCommand
from ps2.cli.commands.report import ReportCommand

# Map of command names to command classes
COMMANDS = {
    "analyze": AnalyzeCommand,
    "check": CheckCommand,
    "fix": FixCommand,
    "generate": GenerateCommand,
    "monitor": MonitorCommand,
    "report": ReportCommand,
}
