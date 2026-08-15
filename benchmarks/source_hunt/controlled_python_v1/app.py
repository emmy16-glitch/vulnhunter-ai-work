"""Parse-only controlled Source Hunt fixture.

This module is benchmark input, not an application entry point. Nothing in this file
starts a server or invokes a route. Vulnerable and guarded examples are paired so the
benchmark measures both detection and false-positive behaviour.
"""

import json
import pickle
import subprocess

import requests


class DemoApp:
    def route(self, _path):
        def decorate(function):
            return function

        return decorate


app = DemoApp()


def sanitize_path(value):
    return value.replace("..", "").lstrip("/")


def validate_host(value):
    if not value.replace(".", "").isalnum():
        raise ValueError("host is outside the controlled allowlist shape")
    return value


def validate_query_name(value):
    if not value.replace("_", "").isalnum():
        raise ValueError("name is outside the controlled query shape")
    return value


def validate_internal_url(value):
    if not value.startswith("https://internal.example/"):
        raise ValueError("URL is outside the controlled internal origin")
    return value


@app.route("/download-vulnerable")
def download_vulnerable(request):
    name = request.args.get("name")
    return open(name).read()  # VH-GT:PT-VULN


@app.route("/download-safe")
def download_safe(request):
    name = request.args.get("name")
    safe_name = sanitize_path(name)
    return open(safe_name).read()  # VH-GT:PT-SAFE


@app.route("/command-vulnerable")
def command_vulnerable(request):
    command = request.args.get("command")
    return subprocess.run(command, shell=True, check=False)  # VH-GT:CMD-VULN


@app.route("/command-safe")
def command_safe(request):
    host = validate_host(request.args.get("host"))
    return subprocess.run(["ping", "-c", "1", host], check=True)  # VH-GT:CMD-SAFE


@app.route("/query-vulnerable")
def query_vulnerable(request, db):
    name = request.args.get("name")
    query = f"SELECT id FROM users WHERE name = '{name}'"
    return db.execute(query)  # VH-GT:SQL-VULN


@app.route("/query-safe")
def query_safe(request, db):
    name = validate_query_name(request.args.get("name"))
    return db.execute("SELECT id FROM users WHERE name = ?", (name,))  # VH-GT:SQL-SAFE


@app.route("/fetch-vulnerable")
def fetch_vulnerable(request):
    url = request.args.get("url")
    return requests.get(url, timeout=2)  # VH-GT:SSRF-VULN


@app.route("/fetch-safe")
def fetch_safe(request):
    url = validate_internal_url(request.args.get("url"))
    return requests.get(url, timeout=2)  # VH-GT:SSRF-SAFE


@app.route("/decode-vulnerable")
def decode_vulnerable(request):
    payload = request.body
    return pickle.loads(payload)  # VH-GT:DESER-VULN


@app.route("/decode-safe")
def decode_safe(request):
    payload = request.body.decode("utf-8")
    return json.loads(payload)  # VH-GT:DESER-SAFE
