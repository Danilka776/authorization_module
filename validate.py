import datetime

from keystone import exception
from keystone.auth import plugins as auth_plugins
from keystone.common import dependency
from keystone.openstack.common import log
from oauthlib.oauth2 import RequestValidator

from oslo.utils import timeutils

METHOD_NAME = 'oauth2_validator'
LOG = log.getLogger(__name__)

@dependency.requires('oauth2_api')
class NewOAuth2Validator(RequestValidator):
    """OAuthlib request validator."""

    def new_validate_client_id(self, client_id, *other_params):
        client_dict = self.oauth2_api.get_consumer(client_id)
        if not client_dict:
            return False
        else:
            return True 

    def new_validate_redirect_uri(self, client_id, redirect_uri, *other_params):
        """A character-by-character string comparison is used"""
        client_dict = self.oauth2_api.get_consumer(client_id)
        registered_uris = client_dict['redirect_uris']

        for uri in registered_uris:
            if redirect_uri == uri:
                return True
        return False

    def new_get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        client_dict = self.oauth2_api.get_consumer(client_id)
        if not client_dict['redirect_uris']:
            headers = request.headers
            return headers['referer']   # take the source URL
        else:
            return client_dict['redirect_uris'][0]
        


    def new_save_authorization_code(self, client_id, code, request, *other_params):
        authorization_code = {
            'code': code['code'], # code is a dict with state and the code
            'consumer_id': client_id,
            'scopes': request.scopes,
            'authorizing_user_id': request.user_id, # populated through the credentials
            'state': request.state,
            'redirect_uri': request.redirect_uri,
            'code_challenge': request.code_challenge,  # pkce
            'code_challenge_method': 'S256'
        }
        token_duration = 28800
        now = timeutils.utcnow()
        future = now + datetime.timedelta(seconds=token_duration)
        expiry_date = timeutils.isotime(future, subsecond=True)
        authorization_code['expires_at'] = expiry_date
        self.oauth2_api.store_authorization_code(authorization_code)


    def new_authenticate_client(self, request, *other_params):
        LOG.debug('OAUTH2: authenticating client')
        authmethod, auth = request.headers['Authorization'].split(' ', 1)
        auth = auth.decode('unicode_escape')
        if authmethod.lower() == 'basic':
            auth = auth.decode('base64')
            client_id, secret = auth.split(':', 1)
            client_dict = self.oauth2_api.get_consumer(client_id)
            if client_dict['code_challenge'] is not None:                # add validate pkce
                request.client = type('obj', (object,), 
                    {'client_id' : client_id,
                     'code_challenge': client_dict['code_challenge'],
                     'code_challenge_method': 'S256'})
                
                LOG.info('OAUTH2: succesfully authenticated client %s',
                    client_dict['name'])
                return True
        return False

        
    def validate_grant_type(self, client_id, grant_type, *other_params):
        if grant_type == 'authorization_code' or grant_type == 'client_credentials' or grant_type == 'refresh_token':
            return True
        else:
            return False
