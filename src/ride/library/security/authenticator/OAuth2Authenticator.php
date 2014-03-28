<?php

namespace ride\library\security\authenticator;

use ride\library\http\Request;
use ride\library\security\authenticator\io\AuthenticatorIO;
use ride\library\security\exception\InactiveAuthenticationException;
use ride\library\security\exception\UnauthorizedException;
use ride\library\security\model\User;
use ride\library\security\oauth\ConnectPolicy;
use ride\library\security\oauth\OAuth2Client;

/**
 * Authenticator to integrate OAuth2 authentication
 */
class OAuth2Authenticator extends AbstractAuthenticator {

    /**
     * Name for the state of the oauth
     * @var string
     */
    const VAR_USER = 'oauth.user';

    /**
     * OAuth2 client
     * @var \ride\library\security\OAuth2Client
     */
    protected $client;

    /**
     * AuthenticatorIO to cache the authentication
     * @var \ride\library\security\authenticator\io\AuthenticatorIO
     */
    protected $io;

    /**
     * Connect policy for new users
     * @var ConnectPolicy
     */
    protected $connectPolicy;

    /**
     * Constructs a new authenticator
     * @param \ride\library\security\authenticator\io\AuthenticatorIO $io
     * authenticator to extend with Google authentication support
     * @return null
     */
    public function __construct(OAuth2Client $client) {
        $this->client = $client;
        $this->io = null;
        $this->user = null;
    }

    /**
     * Sets the authenticator IO to cached the authentications. When the io is
     * set, the server will not authenticate the access token for every request
     * @param \ride\library\security\authenticator\io\AuthenticatorIO $io
     * @return null
     */
    public function setAuthenticatorIO(AuthenticatorIO $io) {
        $this->io = $io;
    }

    /**
     * Sets the connect policy for new users
     * @param ConnectPolicy $connectPolicy
     * @return null
     */
    public function setConnectPolicy(ConnectPolicy $connectPolicy) {
        $this->connectPolicy = $connectPolicy;
    }

    /**
     * Gets the connect policy for new users
     * @return ConnectPolicy
     */
    public function getConnectPolicy() {
        return $this->connectPolicy;
    }

    /**
     * Logout the current user
     * @return null
     */
    public function logout() {
        $this->client->clearToken();
        $this->user = null;

        if ($this->io) {
            $this->io->set(self::VAR_USER, null);
        }
    }

    /**
     * Gets the URL to Google for authentication
     * @return string
     */
    public function getAuthorizationUrl() {
        return $this->client->getAuthorizationUrl();
    }

    /**
     * Authenticates a user through the incoming request
     * @param \ride\library\http\Request $request
     * @return \ride\library\security\model\User|null User if the authentication
     * succeeded
     */
    public function authenticate(Request $request) {
        if (!$this->client->authenticate($request)) {
            return null;
        }

        $userInfo = $this->client->getUserInfo();
        if (!isset($userInfo['email'])) {
            return null;
        }

        $securityModel = $this->securityManager->getSecurityModel();

        $user = $securityModel->getUserByEmail($userInfo['email']);

        if (!$user) {
            if ($this->connectPolicy) {
                $user = $this->connectPolicy->connectUser($securityModel, $userInfo);
            }

            if (!$user) {
                throw new UnauthorizedException();
            }
        }

        if (!$user->isActive()) {
            throw new InactiveAuthenticationException();
        }

        return $this->setUser($user);
    }

    /**
     * Gets the current user.
     * @return \ride\library\security\model\User User instance if a user is
     * logged in, null otherwise
     */
    public function getUser() {
        if ($this->io) {
            $username = $this->io->get(self::VAR_USER);
            if ($username) {
                $securityModel = $this->securityManager->getSecurityModel();

                $this->user = $securityModel->getUserByUsername($username);
            }
        }

        return $this->user;
    }

    /**
     * Sets the current authenticated user
     * @param \ride\library\security\model\User $user User to set the
     * authentication for
     * @return \ride\library\security\model\User updated user with the
     * information of the authentification
     */
    public function setUser(User $user) {
        if ($this->io) {
            $this->io->set(self::VAR_USER, $user->getUsername());
        }

        return $this->user = $user;
    }

}
