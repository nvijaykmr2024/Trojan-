"""Direct execution entry point for `python -m trojan_defense`."""

import sys
from trojan_defense.main import main

if __name__ == "__main__":
    sys.exit(main())
