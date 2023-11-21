#!/usr/bin/env python3

"""
  Module for session authentication
"""

from api.v1.auth.auth import Auth
from models.user import User
import uuid
import os


class SessionAuth(Auth):
    """
      Class for session auth
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
          Creates a sessionId for a user
        """
        if user_id is None:
            return None
        if type(user_id) is not str:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
          Retrieves a user_id_by_session_id
        """
        if session_id is None:
            return None
        if type(session_id) is not str:
            return None
        user_id = self.user_id_by_session_id.get(session_id)
        return user_id

    def current_user(self, request=None):
        """
          Overloads a user based on their cookie-id
        """
        cookie_value = self.session_cookie(request)
        user_id = self.user_id_for_session_id(cookie_value)
        current_user = User.get(user_id)
        return current_user

    def destroy_session(self, request=None):
        """
          Deletes a session and logout
        """
        if request is None:
            return False
        session_value = self.session_cookie(request)
        if not session_value:
            return False
        user_id = self.user_id_by_session_id(session_value)
        if not user_id:
            return False
        del self.user_id_by_session_id[session_value]
        return True
