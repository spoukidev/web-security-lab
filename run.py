"""Local entry point. It binds to loopback by default."""
import os
from app import create_app
app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("LAB_HOST", "127.0.0.1"), port=5000, debug=True)
