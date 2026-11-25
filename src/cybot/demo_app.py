"""Local demo application.

It listens on 127.0.0.1 only. Two routes are intentionally weak so CYBOT can
practice validation without leaving the machine: a reflected query parameter,
and a boolean SQLite lookup. CYBOT does not treat either as a confirmed issue.
"""

from __future__ import annotations

import sqlite3

from flask import Flask, request

DEMO_HOST = "127.0.0.1"
DEMO_PORT = 8765


def create_demo_app() -> Flask:
    app = Flask(__name__)
    database = sqlite3.connect(":memory:", check_same_thread=False)
    database.execute("CREATE TABLE items (name TEXT, note TEXT)")
    database.execute("INSERT INTO items (name, note) VALUES ('widget', 'demo row')")
    database.commit()

    @app.get("/health")
    def health():
        return {"ok": True, "bind": DEMO_HOST}

    @app.get("/reflect")
    def reflect():
        value = request.args.get("q", "")
        return f"<html><body><p>Result: {value}</p></body></html>"

    @app.get("/lookup")
    def lookup():
        name = request.args.get("name", "")
        try:
            rows = database.execute(f"SELECT name, note FROM items WHERE name = '{name}'").fetchall()
        except sqlite3.Error:
            rows = []
        if not rows:
            return "<html><body><p>none</p></body></html>"
        lines = "".join(f"<li>{row[0]}: {row[1]}</li>" for row in rows)
        return f"<html><body><ul>{lines}</ul></body></html>"

    return app


def serve(host: str = DEMO_HOST, port: int = DEMO_PORT) -> None:
    if host != DEMO_HOST:
        raise RuntimeError("The demo app binds to 127.0.0.1 only.")
    create_demo_app().run(host=DEMO_HOST, port=port, debug=False, use_reloader=False)
