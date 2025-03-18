"""
Monitor Command Module for PS2 CLI.

This module provides the 'monitor' command for the PS2 CLI, allowing users
to monitor code performance from the command line.
"""
import time
import argparse
import sys
import traceback

from typing import Any, Dict

from ps2.cli.helpers.formatting import format_result, output_formats


class MonitorCommand:
    """
    Command class for monitoring code performance.

    This command tracks and analyzes performance metrics for Python code,
    helping developers identify and fix bottlenecks.
    """

    name = "monitor"
    help = "Monitor code performance"

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """
        Add command-specific arguments to the parser.

        Args:
            parser: ArgumentParser instance for this command.
        """
        parser.add_argument(
            "--output",
            "-o",
            choices=output_formats.keys(),
            default="pretty",
            help="Output format (default: pretty)",
        )
        parser.add_argument(
            "--output-file", "-f", help="Output file path (default: stdout)"
        )
        parser.add_argument(
            "--duration",
            "-d",
            type=int,
            default=3600,
            help="Duration to monitor in seconds (default: 3600)",
        )
        parser.add_argument(
            "--live",
            "-l",
            action="store_true",
            help="Display live metrics during monitoring",
        )
        parser.add_argument(
            "--memory", "-m", action="store_true", help="Monitor memory usage"
        )
        parser.add_argument(
            "--time", "-t", action="store_true", help="Monitor execution time"
        )
        parser.add_argument("--script", "-s", help="Script to run and monitor")

    @staticmethod
    def _configure_monitoring(ps2, args):
        """
        Configure monitoring options based on command-line arguments.
        
        Args:
            ps2: Initialized PS2 instance.
            args: Parsed command-line arguments.
        """
        if args.memory:
            # Enable memory tracking
            memory_config = ps2.config.get("performance_monitor", {})
            memory_config["track_memory_usage"] = True
            
        if args.time:
            # Enable execution time tracking
            time_config = ps2.config.get("performance_monitor", {})
            time_config["track_execution_time"] = True

    @staticmethod
    def _handle_live_monitoring(ps2, args):
        """
        Handle live monitoring of performance metrics.
        
        Args:
            ps2: Initialized PS2 instance.
            args: Parsed command-line arguments.
            
        Returns:
            Result dictionary with monitoring data.
            
        Raises:
            Exception: If monitoring fails.
        """
        # Set up live monitoring display
        print("Starting performance monitoring...")
        print("Press Ctrl+C to stop")

        # Start monitoring (non-blocking)
        monitor_thread = ps2.monitor_performance(duration=0)

        # Display live updates
        start_time = time.time()
        end_time = start_time + args.duration
        
        try:
            # Main monitoring loop
            while time.time() < end_time:
                MonitorCommand._display_current_metrics(ps2, start_time)
                time.sleep(1)

        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")

        # Stop monitoring and get final results
        if monitor_thread and isinstance(monitor_thread, dict) and monitor_thread.get("thread"):
            ps2.stop_monitoring(thread=monitor_thread.get("thread"))
        
        return ps2.stop_monitoring()

    @staticmethod
    def _display_current_metrics(ps2, start_time):
        """
        Display current performance metrics.
        
        Args:
            ps2: Initialized PS2 instance.
            start_time: Time when monitoring started.
        """
        # Get current metrics
        current_metrics = ps2.get_current_metrics()

        # Clear screen and display metrics
        print("\033c", end="")  # Clear screen
        print(f"Performance Monitoring (running for {int(time.time() - start_time)} seconds)")
        print("-" * 50)

        if current_metrics:
            for metric in current_metrics:
                print(f"{metric['name']}: {metric['value']} {metric['unit']}")
        else:
            print("No metrics available yet...")

    @staticmethod
    def _handle_regular_monitoring(ps2, args):
        """
        Handle regular (non-live) monitoring.
        
        Args:
            ps2: Initialized PS2 instance.
            args: Parsed command-line arguments.
            
        Returns:
            Result dictionary with monitoring data.
            
        Raises:
            Exception: If monitoring fails.
        """
        # Run script if specified
        if args.script:
            print(f"Running and monitoring script: {args.script}")
            # This is a placeholder - in a real implementation, we'd
            # need to run the script and collect metrics
            print("Script monitoring not fully implemented")

        # Regular monitoring
        print(f"Monitoring for {args.duration} seconds...")
        result = ps2.monitor_performance(duration=args.duration)
        print("Monitoring complete")
        
        return result

    @staticmethod
    def _output_results(result, args):
        """
        Format and output monitoring results.
        
        Args:
            result: Monitoring result dictionary.
            args: Parsed command-line arguments.
        """
        # Format the output
        output = format_result(result, args.output)

        # Write the output
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(output)
        else:
            print(output)

    @staticmethod
    def _handle_error(error: Exception, error_type: str, verbose: bool) -> int:
        """
        Handle errors during command execution.
        
        Args:
            error: The exception that occurred.
            error_type: Description of what was happening when the error occurred.
            verbose: Whether to print the full traceback.
            
        Returns:
            Exit code (always 1 for errors).
        """
        print(f"Error during {error_type}: {error}", file=sys.stderr)
        if verbose:
            traceback.print_exc()
        return 1
    
    @staticmethod
    def _process_monitoring_result(result: Dict[str, Any]) -> int:
        """
        Process monitoring result and determine exit code.
        
        Args:
            result: Monitoring result dictionary.
            
        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        return 0 if result.get("status") in ["pass", "fixed", "info"] else 1
    
    @staticmethod
    def execute(args: argparse.Namespace, ps2: Any) -> int:
        """
        Execute the monitor command.

        Args:
            args: Parsed command-line arguments.
            ps2: Initialized PS2 instance.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        # Configure monitoring options
        MonitorCommand._configure_monitoring(ps2, args)

        try:
            # Determine monitoring mode and execute
            if args.live:
                result = MonitorCommand._handle_live_monitoring(ps2, args)
            else:
                result = MonitorCommand._handle_regular_monitoring(ps2, args)
            
            # Output the results
            MonitorCommand._output_results(result, args)
            
            # Return appropriate exit code
            return MonitorCommand._process_monitoring_result(result)
            
        except Exception as e:
            error_type = "live monitoring" if args.live else "monitoring performance"
            return MonitorCommand._handle_error(e, error_type, args.verbose)