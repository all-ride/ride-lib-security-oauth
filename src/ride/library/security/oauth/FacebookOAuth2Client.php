<?php

namespace ride\library\security\oauth;

use ride\library\http\client\Client;
use ride\library\security\authenticator\io\AuthenticatorIO;

/**
 * Facebook implementation of the OAuth2 client
 */
class FacebookOAuth2Client extends OAuth2Client {

    /**
     * Constructs a new Facebook OAuth2 client
     * @param ride\library\http\client\Client $httpClient
     * @param ride\library\security\authenticator\io\AuthenticatorIO $io
     * @return null
     */
    public function __construct(Client $httpClient, AuthenticatorIO $io) {
        parent::__construct($httpClient, $io);

        $this->setAuthorizationUrl('https://www.facebook.com/dialog/oauth?client_id=%client.id%&redirect_uri=%redirect.uri%&scope=%scope%&state=%state%');
        $this->setTokenUrl('https://graph.facebook.com/oauth/access_token');
        $this->setUserInfoUrl('https://graph.facebook.com/me');
    }

}
