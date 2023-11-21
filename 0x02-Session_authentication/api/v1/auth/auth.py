#!/usr/bin/env python3

"""
  Module for authentication
"""
from typing import List, TypeVar

from flask import request
import os


class Auth():
    """
      Authentication class
    """

    def require_auth(self, path: str,
                     excluded_paths: List[str]) -> bool:
        """
          Method that depends which path requires
          authentication or not
        """
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True

        len_path = len(path)

        if path[len_path - 1] == '/':
            slashed_path = path
        else:
            slashed_path = path + '/'

        for excluded_path in excluded_paths:
            if slashed_path.endswith(excluded_path):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """"
           Method for authorization_header
        """
        if request is None:
            return None
        key = "Authorization"

        key_value = request.headers.get(key)

        if not key_value:
            return None
        return key_value

    def current_user(self, request=None) -> TypeVar('User'):
        """
          Method for current_user
        """
        return None

    def session_cookie(self, request=None):
        """
          Retrieves value of a cookie
        """
        if request is None:
            return None
        _my_session_id = os.getenv("SESSION_NAME")
        value = request.cookies.get(_my_session_id)
        return value
