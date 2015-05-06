<?php

namespace ride\library\security\oauth\policy;

use ride\library\security\model\SecurityModel;
use ride\library\security\oauth\OAuth2Client;

/**
 * Policy to connect OAuth users with your system
 * @see ride\library\security\authenticator\OAuth2Authenticator
 */
interface ConnectPolicy {

    /**
     * Connects a user to your security model
     * @param \ride\library\security\oauth\OAuth2Client $client
     * @param \ride\library\security\model\SecurityModel $securityModel
     * Instance of the current security model
     * @return \ride\library\security\model\User|null User if a user is
     * available, null if the user is not allowed
     */
    public function connectUser(OAuth2Client $client, SecurityModel $securityModel);

}
