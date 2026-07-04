"""HTTP backend for privacy-adblocker-rpi.

Two layers:
  service.py - all logic, framework-agnostic and unit-testable without a server
  api.py     - a thin FastAPI wrapper exposing the service over REST
"""
