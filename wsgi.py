import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server.app import app

if __name__ == "__main__":
    app.run()
