#!/usr/bin/env python3
import sys
import io

# Fix Windows terminal encoding (handles emoji/unicode safely)
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

"""
Docker Security Scanner - CLI Entry Point
Usage: python cli.py --image nginx:latest
       python cli.py --dockerfile ./Dockerfile
       python cli.py --image nginx:latest --dockerfile ./Dockerfile
"""

import argparse
import sys
from scanner.image_scanner import scan_image
from scanner.dockerfile_linter import lint_dockerfile
from scanner.report_generator import generate_report, print_console_report


def main():
    parser = argparse.ArgumentParser(
        description="🔒 Docker Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --image nginx:latest
  python cli.py --dockerfile ./Dockerfile
  python cli.py --image myapp:v1 --dockerfile ./Dockerfile --output report.html
        """
    )

    parser.add_argument("--image",      type=str, help="Docker image to scan (e.g., nginx:latest)")
    parser.add_argument("--dockerfile", type=str, help="Path to Dockerfile to lint")
    parser.add_argument("--output",     type=str, help="Save HTML report to this file (e.g., report.html)")
    parser.add_argument("--json",       action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    if not args.image and not args.dockerfile:
        parser.print_help()
        print("\n❌ Error: Please provide --image and/or --dockerfile")
        sys.exit(1)

    results = {
        "image":       args.image,
        "dockerfile":  args.dockerfile,
        "image_scan":  None,
        "lint_results": None,
    }

    # --- Scan Docker Image ---
    if args.image:
        print(f"\n🔍 Scanning image: {args.image}")
        results["image_scan"] = scan_image(args.image)

    # --- Lint Dockerfile ---
    if args.dockerfile:
        print(f"\n📋 Linting Dockerfile: {args.dockerfile}")
        results["lint_results"] = lint_dockerfile(args.dockerfile)

    # --- Output ---
    if args.json:
        import json
        print(json.dumps(results, indent=2))
    elif args.output:
        generate_report(results, args.output)
        print(f"\n✅ HTML report saved to: {args.output}")
    else:
        print_console_report(results)


if __name__ == "__main__":
    main()