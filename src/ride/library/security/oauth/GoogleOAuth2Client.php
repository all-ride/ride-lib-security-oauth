<?php

namespace ride\library\security\oauth;

use ride\library\http\client\Client;
use ride\library\security\authenticator\io\AuthenticatorIO;

/**
 * Google implementation of the OAuth2 client
 */
class GoogleOAuth2Client extends OAuth2Client {

    /**
     * Constructs a new Google OAuth2 client
     * @param \ride\library\http\client\Client $httpClient
     * @param \ride\library\security\authenticator\io\AuthenticatorIO $io
     * @return null
     */
    public function __construct(Client $httpClient, AuthenticatorIO $io) {
        parent::__construct($httpClient, $io);

        $this->setAuthorizationUrl('https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=%client.id%&redirect_uri=%redirect.uri%&scope=%scope%&state=%state%');
        $this->setTokenUrl('https://accounts.google.com/o/oauth2/token');
        $this->setUserInfoUrl('https://www.googleapis.com/oauth2/v1/userinfo');
    }

}
