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
     * Flag to see if client calls should use a query parameter or a header
     * @var boolean
     */
    protected $useAuthorizationHeader;

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
        $this->useAuthorizationHeader = false;
    }

    /**
     * Sets whether to use a authorization header or a query parameter to
     * provide the access token to the OAuth server
     * @param boolean $useAuthorizationHeader
     * @return null
     */
    public function setUseAuthorizationHeader($useAuthorizationHeader) {
        $this->useAuthorizationHeader = $useAuthorizationHeader;
    }

    /**
     * Gets whether to use a authorization header or a query parameter to
     * provide the access token to the OAuth server
     * @return boolean
     */
    public function useAuthorizationHeader() {
        return $this->useAuthorizationHeader;
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

        $url = $this->urlAuthorization;
        if (is_string($this->redirectUri)) {
            $url = str_replace('%redirect.uri%', urlencode($this->redirectUri), $url);   
        }
        if (is_string($this->clientId)) {
            $url = str_replace('%client.id%', urlencode($this->clientId), $url);
        }
        if (is_string($this->scope) || is_array($this->scope)) {
            $url = str_replace('%scope%', urlencode($this->scope), $url);
        }
        if (is_string($this->getState())) {
            $url = str_replace('%state%', urlencode($this->getState()), $url);
        }

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
     * Sets the token
     * @param string Access token
     * @return null
     */
    public function setToken($token, $refreshToken = null) {
        if (!$this->urlToken) {
            throw new SecurityException('No access token URL set');
        }

        $accessToken = array(
            'token' => $token,
            'refreshToken' => $refreshToken,
        );
        $this->io->set($this->urlToken, $accessToken);

        $this->token = $token;
    }

    /**
     * Gets the current access token. When it's expired, a refresh is attempted.
     * @return string|boolean Access token if authenticated, false otherwise
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

        if (!isset($accessToken['access_token'])) {
            $this->token = false;
        } elseif (isset($accessToken['expires']) && $accessToken['expires'] < time()) {
            if($this->log) {
                $this->log->logDebug('OAuth access token expired on ' . gmstrftime('%Y-%m-%d %H:%M:%S', $accessToken['expires']), null, self::LOG_SOURCE);
            }

            if (isset($accessToken['refresh'])) {
                $this->refreshToken($accessToken['refresh'], $accessToken);
            } else {
                $this->token = false;
            }
        } else {
            $this->token = $accessToken['access_token'];
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
     * Clears the token
     * @return null
     */
    public function clearToken() {
        $this->token = null;

        $this->io->set(self::VAR_STATE, null);

        if ($this->urlToken) {
            $this->io->set($this->urlToken, null);
        }
    }

    /**
     * Authenticates the incoming request
     * @param \ride\library\http\Request $request
     * @return boolean True when the request could be authenticated, false
     * otherwise
     */
    public function authenticate(LibraryRequest $request) {
        if (is_string($request->getQuery()) && (str_replace($request->getQuery(), '', $request->getUrl()) != $this->redirectUri)) {
            // skip oauth which has not the current URL as redirectUri

            return false;
        }

        $token = $this->getToken();
        if ($token) {
            return $token !== false;
        }

        if ($this->log) {
            $this->log->logDebug('Checking the authentication code', null, self::LOG_SOURCE);
        }

        $authorizationCode = $request->getQueryParameter('code');
        if (!$authorizationCode) {
            $error = $request->getQueryParameter('error');
            if ($error) {
                if ($this->log) {
                    $this->log->logDebug('Authorization failed with error', $error, self::LOG_SOURCE);
                }

                switch ($error) {
                    case 'invalid_request':
                    case 'invalid_request':
                    case 'unauthorized_client':
                    case 'access_denied':
                    case 'unsupported_response_type':
                    case 'invalid_scope':
                    case 'server_error':
                    case 'temporarily_unavailable':
                    case 'user_denied':
                        break;
                    default:
                        throw new SecurityException('Unknown OAuth error code returned: ' . $error);
                }
            } elseif ($this->log) {
                $this->log->logDebug('Authorization failed without error', null, self::LOG_SOURCE);
            }

            return false;
        }

        $requestState = $request->getQueryParameter('state');
        $serverState = $this->getState();
        if ($requestState != $serverState) {
            if ($this->log) {
                $this->log->logDebug('Received state (' . $requestState . ') does not match state (' . $serverState . ')', null, self::LOG_SOURCE);
            }

            return false;
        }

        return $this->retrieveToken($authorizationCode);
    }

    /**
     * Retrieves the access token with the provided authorization code
     * @param string $authorizationCode Authorization code received from the
     * authorization server
     * @return boolean True when successfull, false otherwise
     */
    private function retrieveToken($authorizationCode) {
        if (!$this->urlToken) {
            throw new SecurityException('No access token URL set');
        }

        if (!$this->redirectUri) {
            throw new SecurityException('No redirect URI set');
        }

        if (!$this->clientId) {
            throw new SecurityException('No client id set');
        }

        $body = array(
            'code' => $authorizationCode,
            'redirect_uri' => $this->redirectUri,
            'grant_type' => 'authorization_code',
        );

        $headers = array(
            'Accept' => '*/*',
            'Content-Type' => 'application/x-www-form-urlencoded',
        );

        if ($this->clientSecret) {
            // $body['client_id'] => $this->clientId;
            // $body['client_secret'] = $this->clientSecret;
            $headers['Authorization'] = 'Basic ' . base64_encode(urlencode($this->clientId) . ':' . urlencode($this->clientSecret));
        }

        $response = $this->httpClient->post($this->urlToken, $body, $headers);

        return $this->parseTokenResponse($response);
    }

    /**
     * Refreshes the access token with the provided refresh token
     * @param string $refreshToken Refresh token to send
     * @param array $token Current token data
     * @return boolean True when successfull, false otherwise
     */
    private function refreshToken($refreshToken, array $token) {
        if (!$this->urlToken) {
            throw new SecurityException('No access token URL set');
        }

        if (!$this->clientId) {
            throw new SecurityException('No client id set');
        }

        $body = array(
            'client_id' => $this->clientId,
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token',
        );

        if ($this->clientSecret) {
            $body['client_secret'] = $this->clientSecret;
        }

        $headers = array(
            'Accept' => '*/*',
            'Content-Type' => 'application/x-www-form-urlencoded',
        );

        $response = $this->httpClient->post($this->urlToken, $body, $headers);

        return $this->parseTokenResponse($response, $token);
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
     * Parses the response of a token request
     * @param \ride\library\http\Response $response Response of the token
     * request
     * @param array $token Container for the token variables
     * @return boolean True when granted, false otherwise
     * @throws \ride\library\security\exception\SecurityException when the
     * response has an invalid format
     */
    private function parseTokenResponse(Response $response, array $token = array()) {
        $this->token = false;

        if ($response->getStatusCode() != 200) {
            if ($this->log) {
                $this->log->logDebug('Received status code ' . $response->getStatusCode() . ' for ' . $this->urlToken, null, self::LOG_SOURCE);
            }

            return false;
        }

        $response = $this->parseResponse($response, true);

        if (isset($response['error'])) {
            if ($this->log) {
                $this->log->logDebug('Unable to retrieve the access token, received error: ' . $response['error'], null, self::LOG_SOURCE);
            }

            return false;
        }

        if (!isset($response['access_token'])) {
            throw new SecurityException('OAuth server did not return the access token nor an error. Is the address ' . $this->urlToken . ' correct?');
        }

        if ($this->log) {
            $this->log->logDebug('OAuth answer', var_export($response, true), self::LOG_SOURCE);
        }

        $token['access_token'] = $response['access_token'];
        $token['created'] = time();

        if (isset($response['expires_in'])) {
            $expires = $response['expires_in'];
            if (strval($expires) !== strval(intval($expires)) || $expires <= 0) {
                throw new SecurityException('OAuth server did not return a supported type of access token expiry time');
            }

            $token['expires'] = time() + $expires;
        } elseif (isset($token['expires'])) {
            unset($token['expires']);
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
        $this->token = $token['access_token'];

        return true;
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

        if (isset($vars['query'])) {
            $path .= '?' . $vars['query'];
        }

        if (isset($vars['host'])) {
            $headers->setHeader(Header::HEADER_HOST, $vars['host'], true);
        }

        $token = $this->getToken();
        if ($token) {
            if ($this->useAuthorizationHeader()) {
                $headers->setHeader(Header::HEADER_AUTHORIZATION, 'Bearer ' . $token);
            } elseif (isset($vars['query'])) {
                $path .= '&access_token=' . urlencode($token);
            } else {
                $path .= '?access_token=' . urlencode($token);
            }
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
