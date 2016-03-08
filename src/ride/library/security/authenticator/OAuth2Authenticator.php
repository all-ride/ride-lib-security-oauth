<?php

namespace ride\library\security\authenticator;

use ride\library\http\Request;
use ride\library\security\authenticator\io\AuthenticatorIO;
use ride\library\security\exception\InactiveAuthenticationException;
use ride\library\security\exception\UnauthorizedException;
use ride\library\security\model\User;
use ride\library\security\oauth\policy\ConnectPolicy;
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
     * Name for the switched user name
     * @var string
     */
    const VAR_SWITCHED_USER = 'oauth.user.switched';

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
        $this->user = false;
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
     * @param \ride\library\security\oauth\policy\ConnectPolicy $connectPolicy
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
        if ($this->io && $this->io->get(self::VAR_SWITCHED_USER)) {
            $this->io->set(self::VAR_SWITCHED_USER, null);
            $this->user = false;
        } else {
            $this->client->clearToken();
            $this->user = null;

            if ($this->io) {
                $this->io->set(self::VAR_USER, null);
            }
        }
    }

    /**
     * Gets the URL for authentication
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
        $user = null;

        if (!$this->client->authenticate($request)) {
            return $user;
        }

        if ($this->connectPolicy) {
            $user = $this->connectPolicy->connectUser($this->client, $this->securityManager->getSecurityModel());
        }

        if (!$user) {
            throw new UnauthorizedException();
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
        if ($this->user === false && $this->io && $this->client->getToken()) {
            $username = $this->io->get(self::VAR_USER);
            if ($username) {
                $securityModel = $this->securityManager->getSecurityModel();

                $this->user = $securityModel->getUserByUsername($username);

                $username = $this->io->get(self::VAR_SWITCHED_USER);
                if (!$username) {
                    return $this->user;
                }

                $switchedUser = $securityModel->getUserByUsername($username);
                if (!$switchedUser) {
                    return $this->user;
                }

                if (!$this->user->isSuperUser() && !$this->user->isPermissionGranted(SecurityManager::PERMISSION_SWITCH)) {
                    $this->io->set(self::VAR_SWITCHED_USER, null);

                    throw new UnauthorizedException('Could not switch user: not allowed');
                }

                $this->user = $switchedUser;
            }
        }

        return parent::getUser();
    }

    /**
     * Sets the current authenticated user
     * @param \ride\library\security\model\User $user User to set the
     * authentication for
     * @return \ride\library\security\model\User updated user with the
     * information of the authentification
     */
    public function setUser(User $user = null) {
        if ($user !== null && $this->io) {
            $this->io->set(self::VAR_USER, $user->getUsername());
        }

        return parent::setUser($user);
    }

    /**
     * Switch to the provided user to test it's permissions. When logging out,
     * the user before switching will be the current user
     * @param string $username The username of the user to switch to
     * @return null
     * @throws \ride\library\security\exception\UnauthorizedException when not
     * authenticated or not allowed to switch
     * @throws \ride\library\security\exception\UserNotFoundException when the
     * requested user could not be found
     */
    public function switchUser($username) {
        if (!$this->io) {
            return false;
        }

        $this->user = $this->getUserForSwitch($username);
        $this->io->set(self::VAR_SWITCHED_USER, $username);

        return true;
    }

    /**
     * Checks is the current user is a switched user
     * @return boolean
     */
    public function isSwitchedUser() {
        if ($this->getUser() && $this->io && $this->io->get(self::VAR_SWITCHED_USER)) {
            return true;
        }

        return false;
    }

}
