<?php

namespace ride\library\security\oauth;

use ride\library\security\model\SecurityModel;

/**
 * Policy to connect new OAuth users with your system
 * @see ride\library\security\authenticator\OAuth2Authenticator
 */
interface ConnectPolicy {

    /**
     * Connects a new user to your security model
     * @param \ride\library\security\model\SecurityModel $securityModel
     * Instance of the current security model
     * @param array $userInfo User information provided by the oAuth server in
     * a key-value pair
     * @return \ride\library\security\model\User|null User if a new user has
     * been created, null if the user is not allowed
     */
    public function connectUser(SecurityModel $securityModel, array $userInfo);

}
