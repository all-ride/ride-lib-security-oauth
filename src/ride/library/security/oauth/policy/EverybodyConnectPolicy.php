<?php

namespace ride\library\security\oauth\policy;

use ride\library\security\model\SecurityModel;

use \Exception;

/**
 * Connect policy to allow everybody to connect with your system
 */
class EverybodyConnectPolicy extends EmailConnectPolicy {

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
    protected function createUser(SecurityModel $securityModel, array $userInfo) {
        $user = parent::createUser($securityModel, $userInfo);
        if (!$user || !$this->roles) {
            return $user;
        }

        // retrieve roles from security model
        $roles = array();
        foreach ($this->roles as $role => $null) {
            if (is_numeric($role)) {
                $r = $securityModel->getRoleById($role);
            } else {
                $r = $securityModel->getRoleByName($role);
                if (!$r) {
                    $r = $securityModel->createRole();
                    $r->setName($role);

                    $securityModel->saveRole($r);
                }
            }

            if ($r) {
                $roles[] = $r;
            }
        }

        // set roles to user
        if ($roles) {
            try {
                $securityModel->setRolesToUser($user, $roles);
            } catch (Exception $exception) {

            }
        }

        // go back
        return $user;
    }

}
