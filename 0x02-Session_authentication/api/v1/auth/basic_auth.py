#!/usr/bin/env python3

"""
  Module that instantiates an AUth
  class Model
"""

from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """
      BasicAuth class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
           Method that checks the header and
           extract_base64_authorization_header
        """
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if authorization_header[0:6] != "Basic ":
            return None
        if len(authorization_header) < 6:
            return None
        value = authorization_header[6:]
        return value

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
          Method that converts base64 header to a normal
          string
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            decoded_str = base64.b64decode(base64_authorization_header)
        except Exception:
            return None
        decoded_utf = decoded_str.decode('utf-8')
        return decoded_utf

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
          Method that retrieves the user's email and password
          from the decoded string, works only if ':' is included
        """

        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) is not str:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        user_cred = decoded_base64_authorization_header.split(":")
        email = user_cred[0]
        if len(user_cred) <= 2:
            password = user_cred[1]
        elif len(user_cred) > 2:
            password = user_cred[1] + ':' + user_cred[2]

        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
           Method that searches the database if a user with this
           record actually exists!
        """
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None

        users = User.search({"email": user_email})
        if not users:
            return None
        if users:
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
          Method that integrates other and uses BasicAuth on requests
        """
        header = self.authorization_header(request)
        if header is not None:
            encoded_header = self.extract_base64_authorization_header(header)
            if encoded_header is not None:
                decoded_header = self.decode_base64_authorization_header(
                        encoded_header)
                if decoded_header is not None:
                    email, password = self.extract_user_credentials(
                            decoded_header)
                    if email is not None:
                        return self.user_object_from_credentials(
                                email, password)
        return
