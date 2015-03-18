<?php

namespace ride\library\security\oauth;

use ride\library\security\model\SecurityModel;
use ride\library\String;

use \Exception;

/**
 * Connect policy to allow everybody to connect with your system
 */
class EverybodyConnectPolicy implements ConnectPolicy {

    /**
     * Roles to set to a new user
     * @var array
     */
    private $roles = array();

    /**
     * Adds a role for new users
     * @param string $role Name or id of a role
     * @return null
     */
    public function addRole($role) {
        $this->roles[$role] = $role;
    }

    /**
     * Removes a role for new users
     * @param string $role Name or id of a role
     * @return null
     */
    public function removeRole($role) {
        if (isset($this->roles[$role])) {
            unset($this->roles[$role]);
        }
    }

    /**
     * Gets the roles for new users
     * @return array
     */
    public function getRoles() {
        return array_keys($this->roles);
    }

    /**
     * Connects a new user to your security model
     * @param \ride\library\security\model\SecurityModel $securityModel
     * Instance of the current security model
     * @param array $userInfo User information provided by google in a
     * key-value pair
     * @return \ride\library\security\model\User|null User if a new user has
     * been created, null if the user is not allowed
     */
    public function connectUser(SecurityModel $securityModel, array $userInfo) {
        // check for needed data
        if (!isset($userInfo['name']) || !isset($userInfo['email'])) {
            return false;
        }

        // create the user
        $user = $securityModel->createUser();
        $user->setDisplayName($userInfo['name']);
        $user->setUserName($userInfo['email']);
        $user->setEmail($userInfo['email']);
        $user->setIsEmailConfirmed(true);
        $user->setPassword(String::generate());
        $user->setIsActive(true);

        // save the user
        try {
            $securityModel->saveUser($user);
        } catch (Exception $exception) {
            return false;
        }

        // check for user roles
        if ($this->roles) {
            // retrieve roles from security model
            $roles = array();
            foreach ($this->roles as $role => $null) {
                try {
                    if (is_numeric($role)) {
                        $roles[] = $securityModel->getRoleById($role);
                    } else {
                        $roles[] = $securityModel->getRoleByName($role);
                    }
                } catch (Exception $exception) {

                }
            }

            // set roles to user
            if ($roles) {
                try {
                    $securityModel->setRolesToUser($user, $roles);
                } catch (Exception $exception) {

                }
            }
        }

        // go back
        return $user;
    }

}
