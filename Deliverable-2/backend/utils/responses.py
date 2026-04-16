"""
Standardised JSON response helpers.
All error messages are deliberately vague to avoid leaking internals.
"""
from flask import jsonify


def success(data=None, message=None, status=200):
    body = {}
    if message:
        body["message"] = message
    if data is not None:
        body.update(data) if isinstance(data, dict) else body.update({"data": data})
    return jsonify(body), status


def created(data=None, message=None):
    return success(data, message, 201)


def no_content():
    return "", 204


def error(message, status=400):
    return jsonify({"message": message}), status


def bad_request(message="Invalid request."):
    return error(message, 400)


def unauthorized(message="Authentication required."):
    return error(message, 401)


def forbidden(message="You do not have permission to perform this action."):
    return error(message, 403)


def not_found(message="The requested resource was not found."):
    return error(message, 404)


def conflict(message="A conflict occurred. Please try again."):
    return error(message, 409)


def unprocessable(message="The provided data is invalid."):
    return error(message, 422)


def too_many_requests(message="Too many requests. Please wait before trying again."):
    return error(message, 429)


def server_error(message="An unexpected error occurred. Please try again later."):
    return error(message, 500)
