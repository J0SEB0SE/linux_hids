import argparse
import time
from config import Config
from scanner import Scanner

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    config = Config()
    scanner = Scanner(config)

    if args.build:
        scanner.build_baseline()
    elif args.once:
        if scanner.load_baseline():
            scanner.scan_files()
            scanner.scan_processes()
        else:
            print("No baseline found. Run with --build first.")
    else:
        if not scanner.load_baseline():
            scanner.build_baseline()
        print("Starting continuous HIDS monitoring... (Press Ctrl+C to stop)")
        try:
            while True:
                scanner.scan_files()
                scanner.scan_processes()
                time.sleep(config.settings["scan_interval_seconds"])
        except KeyboardInterrupt:
            print("\nHIDS stopped.")

if __name__ == "__main__":
    main()