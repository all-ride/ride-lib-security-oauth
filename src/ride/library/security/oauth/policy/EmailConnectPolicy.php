<?php

namespace ride\library\security\oauth\policy;

use ride\library\security\model\SecurityModel;
use ride\library\security\oauth\OAuth2Client;
use ride\library\StringHelper;

use \Exception;

/**
 * Connect policy which retrieves the user info from the OAuth service and
 * connects users based on their email address
 */
class EmailConnectPolicy implements ConnectPolicy {

    /**
     * Connects a user to your security model
     * @param \ride\library\security\oauth\OAuth2Client $client
     * @param \ride\library\security\model\SecurityModel $securityModel
     * Instance of the current security model
     * @return \ride\library\security\model\User|null User if a user is
     * available, null if the user is not allowed
     */
    public function connectUser(OAuth2Client $client, SecurityModel $securityModel) {
        // get the user information
        $userInfo = $client->getUserInfo();
        if (!isset($userInfo['email'])) {
            return null;
        }

        // get the user
        $user = $securityModel->getUserByEmail($userInfo['email']);
        if (!$user) {
            $user = $this->createUser($securityModel, $userInfo);
        }

        return $user;
    }

    /**
     * Creates a new user in the security model
     * @param \ride\library\security\model\SecurityModel $securityModel
     * Instance of the current security model
     * @param array $userInfo User information as retrieved from the client
     * @return \ride\library\security\model\User|null User if a user is
     * created, null if the user is not allowed
     */
    protected function createUser(SecurityModel $securityModel, array $userInfo) {
        // check for needed data
        if (!isset($userInfo['name']) || !isset($userInfo['email'])) {
            return null;
        }

        // create the user
        $user = $securityModel->createUser();
        $user->setDisplayName($userInfo['name']);
        $user->setUserName($userInfo['email']);
        $user->setEmail($userInfo['email']);
        $user->setIsEmailConfirmed(true);
        $user->setPassword(StringHelper::generate());
        $user->setIsActive(true);

        // save the user
        try {
            $securityModel->saveUser($user);
        } catch (Exception $exception) {
            return null;
        }

        return $user;
    }

}
