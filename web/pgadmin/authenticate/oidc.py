import json
from base64 import b64decode

from flask import current_app
from flask_babelex import gettext
from flask_security import login_user

from pgadmin import User, Server, db
from pgadmin.authenticate.internal import BaseAuthentication
from pgadmin.tools.user_management import create_user

import jwt


class OIDCAuthentication(BaseAuthentication):
    """OIDC Authentication Class"""

    def get_friendly_name(self):
        return gettext('oidc')

    def login(self, form):
        user = getattr(form, 'user', None)

        tkn = jwt.decode(current_app.login_manager.oidc.get_access_token(), verify=False)

        if user is None:
            user = User.query.filter_by(username=tkn['preferred_username']).first()

        if user is None:
            current_app.logger.exception(
                self.messages('USER_DOES_NOT_EXIST'))
            return False, self.messages('USER_DOES_NOT_EXIST')

        Server.query.filter_by(user_id=user.id).delete()
        db.session.commit()

        # Login user through flask_security
        status = login_user(user)
        if not status:
            current_app.logger.exception(self.messages('LOGIN_FAILED'))
            return False, self.messages('LOGIN_FAILED')
        return True, None

    def authenticate(self, form):
        try:
            current_app.login_manager.oidc._process_callback('destination')
        except:
            return False, 'Forbidden'

        tkn = jwt.decode(current_app.login_manager.oidc.get_access_token(), verify=False)
        user = User.query.filter_by(
            username=tkn['preferred_username']).first()
        if user is None:
            return create_user({
                'username': tkn['preferred_username'],
                'email': tkn['email'],
                'role': 2,
                'active': True,
                'auth_source': 'oidc'
            })
        return True, None

    def validate(self, form):
        return True
