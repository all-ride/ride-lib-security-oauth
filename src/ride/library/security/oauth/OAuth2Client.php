<?php

namespace ride\library\security\oauth;

use ride\library\http\client\AbstractClient;
use ride\library\http\client\Client;
use ride\library\http\client\Request;
use ride\library\http\HeaderContainer;
use ride\library\http\Header;
use ride\library\http\Request as LibraryRequest;
use ride\library\http\Response;
use ride\library\security\authenticator\io\AuthenticatorIO;
use ride\library\security\exception\SecurityException;

/**
 * HTTP client which acts as an OAuth2 client
 */
class OAuth2Client extends AbstractClient {

    /**
     * Source for the log messages
     * @var string
     */
    const LOG_SOURCE = 'oauth';

    /**
     * Name for the state of the oauth
     * @var string
     */
    const VAR_STATE = 'oauth.state';

    /**
     * URL to redirect the browser to so the user can grant access to your
     * application
     *
     * Use the following string as placeholders:
     * <ul>
     * <li>%redirect.uri% URL to redirect when returning from the OAuth server
     * authorization page</li>
     * <li>%client.id% client application identifier registered at the
     * server</li>
     * <li>%scope% scope of the requested permissions to the granted by the
     * OAuth server with the user permissions</li>
     * <li>%state% identifier of the OAuth session state</li>
     * </ul>
     * @var string
     */
    protected $urlAuthorization;

    /**
     * OAuth server URL that will return the access token URL.
     * @var string
     */
    protected $urlToken;

    /**
     * OAuth server URL that will return the user information
     * @var string
     */
    protected $urlUserInfo;

    /**
     * HTTP client
     * @var \ride\library\http\client\Client
     */
    protected $httpClient;

    /**
     * I/O for the authenticator
     * @var \ride\library\security\authenticator\io\AuthenticatorIO
     */
    protected $io;

    /**
     * Authentication token
     * @var string
     */
    protected $token;

    /**
     * Identifier of your application registered with the OAuth server
     * @var string
     */
    protected $clientId;

    /**
     * Secret value assigned to your application when it is registered with the
     * OAuth server.
     * @var string
     */
    protected $clientSecret;

    /**
     * Permissions that your application needs to call the OAuth server APIs
     * @var string
     */
    protected $scope;

    /**
     * Constructs a new OAuth client
     * @param \ride\library\http\client\Client $httpClient
     * @param \ride\library\security\authenticator\io\AuthenticatorIO $io
     * @return null
     */
    public function __construct(Client $httpClient, AuthenticatorIO $io) {
        $this->httpClient = $httpClient;
        $this->io = $io;

        $this->token = null;

        $this->clientId = null;
        $this->clientSecret = null;
        $this->scope = null;

        $this->urlAuthorization = null;
        $this->urlToken = null;
        $this->urlUserInfo = null;
    }

    /**
     * Sets the client id as set in the OAuth server
     * @param string $clientId
     * @return null
     */
    public function setClientId($clientId) {
        $this->clientId = $clientId;
    }

    /**
     * Sets the client secret as set in the OAuth server
     * @param string $clientSecret
     * @return null
     */
    public function setClientSecret($clientSecret) {
        $this->clientSecret = $clientSecret;
    }

    /**
     * Sets the scopes
     * @param string|array $scope Scope URL or array of scope URLs
     * @return null
     */
    public function setScope($scope) {
        if (is_array($scope)) {
            $scope = implode(' ', $scope);
        }

        $this->scope = $scope;
    }

    /**
     * Sets the redirect URI as set in the OAuth server
     * @param string $redirectUri URL to redirect to when the user authorized
     * @return null
     */
    public function setRedirectUri($redirectUri) {
        $this->redirectUri = $redirectUri;
    }

    /**
     * Sets the authorization URL for the user
     * @param string $url URL to redirect the user to. Contains the following
     * placeholders: %redirect.uri%, %client.id%, %scope% and %state%
     * @return null
     */
    public function setAuthorizationUrl($url) {
        $this->urlAuthorization = $url;
    }

    /**
     * Gets the authorization URL for the user
     * @return string
     */
    public function getAuthorizationUrl() {
        if (!$this->urlAuthorization) {
            throw new SecurityException('No dialog URL set');
        }

        if (!$this->redirectUri) {
            throw new SecurityException('No redirect URI set');
        }

        if (!$this->clientId) {
            throw new SecurityException('No client id set');
        }

        if (!$this->clientSecret) {
            throw new SecurityException('No client secret set');
        }

        $url = $this->urlAuthorization;
        $url = str_replace('%redirect.uri%', urlencode($this->redirectUri), $url);
        $url = str_replace('%client.id%', urlencode($this->clientId), $url);
        $url = str_replace('%scope%', urlencode($this->scope), $url);
        $url = str_replace('%state%', urlencode($this->getState()), $url);

        return $url;
    }

    /**
     * Sets the URL to authenticate the token
     * @param string $url
     * @return null
     */
    public function setTokenUrl($url) {
        $this->urlToken = $url;
    }

    /**
     * Sets the URL to retrieve the user info (this is a scope)
     * @param string $url
     * @return null
     */
    public function setUserInfoUrl($url) {
        $this->urlUserInfo = $url;
    }

    /**
     * Clears the token
     * @return null
     */
    public function clearToken() {
        $this->token = null;

        if ($this->urlToken) {
            $this->io->set($this->urlToken, null);
        }
    }

    /**
     * Gets the current token
     * @return string
     * @throws Exception
     */
    public function getToken() {
        if ($this->log) {
            $this->log->logDebug('Checking if OAuth access token was already retrieved from ' . $this->urlToken, null, self::LOG_SOURCE);
        }

        if ($this->token !== null) {
            return $this->token;
        }

        if (!$this->urlToken) {
            throw new SecurityException('No access token URL set');
        }

        $accessToken = $this->io->get($this->urlToken, array());
        if ($this->log) {
            $this->log->logDebug('Access token from storage', var_export($accessToken, true), self::LOG_SOURCE);
        }

        if (!isset($accessToken['value'])) {
            $this->token = false;
        } elseif (isset($accessToken['expires']) && strcmp($accessToken['expires'], gmstrftime('%Y-%m-%d %H:%M:%S')) < 0) {
            if($this->log) {
                $this->log->logDebug('OAuth access token expired on ' . $accessToken['expires'], null, self::LOG_SOURCE);
            }

            // perform refresh?

            $this->token = false;
        } else {
            $this->token = $accessToken['value'];
            if (isset($accessToken['type'])) {
                $this->tokenType = $accessToken['type'];
            }

            if($this->log) {
                $this->log->logDebug('OAuth access token ' . $this->token, $this->tokenType, self::LOG_SOURCE);
            }
        }

        return $this->token;
    }

    /**
     * Authenticates the incoming request
     * @param \ride\library\http\Request $request
     * @return boolean True when the request could be authenticated, false
     * otherwise
     */
    public function authenticate(LibraryRequest $request) {
        $token = $this->getToken();
        if ($token) {
            return $token !== false;
        }

        if ($this->log) {
            $this->log->logDebug('Checking the authentication code', null, self::LOG_SOURCE);
        }

        $code = $request->getQueryParameter('code');
        if (!$code) {
            $error = $request->getQueryParameter('error');
            if (!$error) {
                if ($this->log) {
                    $this->log->logDebug('Authorization failed without error', null, self::LOG_SOURCE);
                }

                return false;
            }

            if ($this->log) {
                $this->log->logDebug('Authorization failed with error', $error, self::LOG_SOURCE);
            }

            if ($error != 'invalid_request' && $error != 'unauthorized_client' && $error != 'access_denied' &&
                $error != 'unsupported_response_type' && $error != 'invalid_scope' && $error != 'server_error' &&
                $error != 'temporarily_unavailable' && $error != 'user_denied') {
                throw new SecurityException('Unknown OAuth error code returned: ' . $error);
            }

            return false;
        }

        $requestState = $request->getQueryParameter('state');
        $state = $this->getState();
        if ($requestState != $state) {
            if ($this->log) {
                $this->log->logDebug('Received state (' . $requestState . ') does not match state (' . $state . ')', null, self::LOG_SOURCE);
            }

            return false;
        }

        if (!$this->urlToken) {
            throw new SecurityException('No access token URL set');
        }

        if (!$this->redirectUri) {
            throw new SecurityException('No redirect URI set');
        }

        if (!$this->clientId) {
            throw new SecurityException('No client id set');
        }

        if (!$this->clientSecret) {
            throw new SecurityException('No client secret set');
        }

        $body = array(
            'code' => $code,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'grant_type' => 'authorization_code',
        );

        $headers = array(
            'Accept' => '*/*',
            'Content-Type' => 'application/x-www-form-urlencoded',
        );

        $response = $this->httpClient->post($this->urlToken, $body, $headers);
        if ($response->getStatusCode() != 200) {
            if ($this->log) {
                $this->log->logDebug('Received status code ' . $response->getStatusCode() . ' for ' . $this->urlToken, null, self::LOG_SOURCE);
            }

            return false;
        }

        $response = $this->parseResponse($response, true);

        if (!isset($response['access_token'])) {
            if (isset($response['error'])) {
                if ($this->log) {
                    $this->log->logDebug('Unable to retrieve the access token, received error: ' . $response['error'], null, self::LOG_SOURCE);
                }

                return false;
            }

            throw new SecurityException('OAuth server did not return the access token nor an error. Is the address ' . $this->urlToken . ' correct?');
        }

        $this->token = $response['access_token'];
        $token = array(
            'value' => $this->token,
            'authorized' => true,
        );

        if (isset($response['expires']) || isset($response['expires_in'])) {
            $expires = (isset($response['expires']) ? $response['expires'] : $response['expires_in']);

            if (strval($expires) !== strval(intval($expires)) || $expires <= 0) {
                throw new SecurityException('OAuth server did not return a supported type of access token expiry time');
            }

            $token['expires'] = gmstrftime('%Y-%m-%d %H:%M:%S', time() + $expires);
        }

        if (isset($response['token_type'])) {
            $token['type'] = $response['token_type'];
        }

        if (isset($response['refresh_token'])) {
            $token['refresh'] = $response['refresh_token'];
        }

        if ($this->log) {
            $this->log->logDebug('OAuth access token', $this->token, self::LOG_SOURCE);
        }

        $this->io->set($this->urlToken, $token);
    }

    /**
     * Gets the state string of this server
     * @return string
     */
    protected function getState() {
        $state = $this->io->get(self::VAR_STATE);
        if (!$state) {
            $state = time() . '-' . substr(md5(rand() . time()), 0, 6);

            $this->io->set(self::VAR_STATE, $state);
        }

        return $state;
    }

    /**
     * Gets the user information from the OAuth server
     * @return array|boolean Array with the user information or false on error
     * @throws Exception when no URL for user info is set
     */
    public function getUserInfo() {
        if (!$this->urlUserInfo) {
            throw new SecurityException('No user info URL set');
        }

        $response = $this->get($this->urlUserInfo);
        if ($response->getStatusCode() != 200) {
            return false;
        }

        return $this->parseResponse($response, true);
    }

    /**
     * Parses the body of a response into a useable variable
     * @param \ride\library\http\Response $response Response to parse
     * @param boolean $convertObjectsToArray Set to true to convert json
     * objects to arrays
     * @return mixed
     */
    public function parseResponse(Response $response, $convertObjectsToArray = false) {
        $body = $response->getBody();
        $contentType = $response->getHeader('Content-Type');

        $posSemiColon = strpos($contentType, ';');
        if ($posSemiColon !== false) {
            $contentType = trim(substr($contentType, 0, $posSemiColon));
        }

        switch($contentType) {
            case 'text/javascript':
            case 'application/json':
                $data = json_decode($body);

                if (gettype($data) == 'object' && $convertObjectsToArray) {
                    $response = array();
                    foreach ($data as $property => $value) {
                        $response[$property] = $value;
                    }
                } else {
                    $response = $data;
                }

                break;
            case 'application/x-www-form-urlencoded':
            case 'text/plain':
            case 'text/html':
                parse_str($body, $response);

                break;
            default:
                $response = $body;

                break;
        }

        return $response;
    }

    /**
     * Performs a request
     * @param \ride\library\http\Request $request Request to send
     * @return \ride\library\http\Response Response of the request
     */
    public function sendRequest(LibraryRequest $request) {
        return $this->httpClient->sendRequest($request);
    }

    /**
     * Creates a HTTP client request
     * @param string $method HTTP method (GET, POST, ...)
     * @param string $url URL for the request
     * @param \ride\library\http\HeaderContainer $headers Headers for the
     * request
     * @param string|array $body URL encoded string or an array of request
     * body arguments
     * @return \ride\library\http\client\Request
     */
    public function createRequest($method, $url, HeaderContainer $headers = null, $body = null) {
        if ($headers === null) {
            $headers = new HeaderContainer();
        }

        $vars = parse_url($url);

        if (isset($vars['path'])) {
            $path = $vars['path'];
        } else {
            $path = '/';
        }

        if (isset($vars['host'])) {
            $headers->setHeader(Header::HEADER_HOST, $vars['host'], true);
        }

        if (isset($vars['query'])) {
            $path .= '?' . $vars['query'];

            if ($this->token) {
                $path .= '&access_token=' . urlencode($this->token);
            }
        } elseif ($this->token) {
            $path .= '?access_token=' . urlencode($this->token);
        }

        $request = new Request($path, $method, 'HTTP/1.1', $headers, $body);

        if (isset($vars['port'])) {
            $request->setPort($vars['port']);
        }

        if (isset($vars['user'])) {
            $request->setUsername($vars['user']);
            $request->setPassword($vars['pass']);
            $request->setAuthenticationMethod($this->getAuthenticationMethod());
        } elseif ($this->username) {
            $request->setUsername($this->username);
            $request->setPassword($this->password);
            $request->setAuthenticationMethod($this->getAuthenticationMethod());
        }

        if (isset($vars['scheme']) && $vars['scheme'] == 'https') {
            $request->setIsSecure(true);
        }

        return $request;
    }

}
