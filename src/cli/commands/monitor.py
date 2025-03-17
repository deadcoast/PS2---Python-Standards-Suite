"""
Monitor Command Module for PS2 CLI.

This module provides the 'monitor' command for the PS2 CLI, allowing users
to monitor code performance from the command line.
"""

from typing import (  # TODO: Remove unused imports; TODO: Remove unused imports  # TODO: Remove unused imports
    Any, Dict, Optional)

from ps2.cli.helpers.formatting import format_result, output_formats

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
        if args.memory:
            ps2.config.get("performance_monitor",
                {})

            ps2.config.get("performance_monitor",
                {})
            ps2.config.get("performance_monitor", {})["track_execution_time"] = True

        # Handle live monitoring if requested
        if args.live:
            try:
                # Set up live monitoring display
                result = {"status": "running", "metrics": []}

                print("Starting performance monitoring...")
                print("Press Ctrl+C to stop")

                # Start monitoring
                monitor_thread = ps2.monitor_performance(duration=0)  # Non-blocking

                # Display live updates
                start_time = time.time()
                end_time = start_time + args.duration

                try:
                    while time.time() < end_time:
                        # Get current metrics
                        current_metrics = ps2.get_current_metrics()

                        # Clear screen and display metrics
                        print("\033c", end="")  # Clear screen
                        print(
                            f"Performance Monitoring (running for {int(time.time() - start_time)} seconds)"
                        )
                        print("-" * 50)

                        if current_metrics:
                            for metric in current_metrics:
                                print(
                                    f"{metric['name']}: {metric['value']} {metric['unit']}"
                                )
                        else:
                            print("No metrics available yet...")

                        # Sleep briefly
                        time.sleep(1)

                except KeyboardInterrupt:
                    print("\nMonitoring stopped by user")

                # Stop monitoring and get final results
                result = ps2.stop_monitoring()

            except Exception as e:
                print(f"Error during live monitoring: {e}", file=sys.stderr)
                if args.verbose:

                    traceback.print_exc()
                return 1

        # Regular (non-live) monitoring
        else:
            try:
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

            except Exception as e:
                print(f"Error monitoring performance: {e}", file=sys.stderr)
                if args.verbose:

                    traceback.print_exc()
                return 1

        # Format the output
        output = format_result(result, args.output)

        # Write the output
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(output)
        else:
            print(output)

        # Return appropriate exit code
        return 0 if result.get("status") in ["pass", "fixed", "info"] else 1