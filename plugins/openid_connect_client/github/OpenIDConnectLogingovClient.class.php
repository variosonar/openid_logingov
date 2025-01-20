<?php

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

/**
 * @file
 * LoginGov OAuth2 client.
 */

class OpenIDConnectLogingovClient extends OpenIDConnectClientBase {

  /**
   * A list of data fields available on login.gov.
   *
   * @var array
   */
  protected static $userinfoFields = [
    'all_emails' => 'All emails',
    'given_name' => 'First name',
    'family_name' => 'Last name',
    'address' => 'Address',
    'phone' => 'Phone',
    'birthdate' => 'Date of birth',
    'social_security_number' => 'Social security number',
    'verified_at' => 'Verification timestamp',
    'x509' => 'x509',
    'x509_subject' => 'x509 Subject',
    'x509_presented' => 'x509 Presented',
  ];

  /**
   * A list of fields we always request from the site.
   *
   * @var array
   */
  protected static $alwaysFetchFields = [
    'sub' => 'UUID',
    'email' => 'Email',
    'ial' => 'Identity Assurance Level',
    'aal' => 'Authenticator Assurance Level',
  ];

  /**
   * A mapping of userinfo fields to the scopes required to receive them.
   *
   * @var array
   */
  protected static $fieldToScopeMap = [
    'sub' => 'openid',
    'email' => 'email',
    'all_emails' => 'all_emails',
    'ial' => 'openid',
    'aal' => 'openid',
    'given_name' => 'profile:name',
    'family_name' => 'profile:name',
    'address' => 'address',
    'phone' => 'phone',
    'birthdate' => 'profile:birthdate',
    'social_security_number' => 'social_security_number',
    'verified_at' => 'profile:verified_at',
    'x509' => 'x509',
    'x509_subject' => 'x509:subject',
    'x509_presented' => 'x509:presented',
    'x509_issuer' => 'x509:issuer',
  ];


  /**
   * {@inheritdoc}
   */
  public function settingsForm() {
    $form = parent::settingsForm();

    $form['client_secret'] = [
      '#title' => t('Client secret'),
      '#description' => t(
        'The <a href="@docs" target="_blank">private key</a> to request LoginGov.',
        [
          '@docs' => 'https://developers.login.gov/oidc/getting-started/',
        ]
      ),
      '#default_value' => $this->getSetting('client_secret', NULL),
      '#type' => 'textarea',
    ];

    $form['sandbox_mode'] = [
      '#title' => t('Sandbox Mode'),
      '#type' => 'checkbox',
      '#description' => t('Check here to use the identitysandbox.gov test environment.'),
      '#default_value' =>$this->getSetting('sandbox_mode', TRUE),
    ];

    $form['acr_level'] = [
      '#title' => t('Authentication Assurance Level'),
      '#type' => 'checkboxes',
      '#options' => [
        'ial/1' => t('IAL 1 - Basic'),
        'ial/2' => t('IAL 2 - Verified Identity'),
        'aal/2' => t('AAL 2 - Users must re-authenticate every 12 hours'),
        'aal/3' => t('AAL 3 - Users must authenticate with WebAuthn or PIV/CAC'),
      ],
      '#default_value' => $this->getSetting('acr_level', ['ial/1']),
    ];

    $form['require_piv'] = [
      '#title' => t('Require PIV/CAC with AAL 3'),
      '#type' => 'checkbox',
      '#default_value' => $this->getSetting('require_piv', FALSE),
      '#states' => [
        'visible' => [':input[name="clients[logingov][acr_level][aal/3]"]' => ['checked' => TRUE]],
      ],
    ];

    $form['verified_within'] = [
      '#title' => t('Verified within'),
      '#type' => 'fieldset',
      '#description' => t('Must be no shorter than 30 days.  Set to 0 for unlimited.'),
      '#collapsible' => TRUE,
      '#collapsed' => TRUE,
      '#group' => 'verified_within',
      '#states' => [
        'collapsed' => [':input[name="clients[logingov][acr_level]"]' => ['value' => 'ial/1']],
      ],
    ];
    $form['verified_within']['count'] = [
      '#field_prefix' => '<strong>' . t('Verified within') . '</strong><br>',
      //'#field_suffix' => '<br>' . t('Must be no shorter than 30 days.  Set to 0 for unlimited.'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('verified_within', NULL) ? variable_get('openid_connect_client_logingov')['verified_within']['count'] : 1,
      '#group' => 'verified_within',
    ];
    $form['verified_within']['units'] = [
      '#type' => 'select',
      '#options' => [
        'd' => t('days'),
        'w' => t('weeks'),
        'm' => t('months'),
        'y' => t('years'),
      ],
      '#default_value' => $this->getSetting('verified_within', NULL) ? variable_get('openid_connect_client_logingov')['verified_within']['units'] : 'y',
      '#group' => 'verified_within',
    ];

    $form['userinfo_fields'] = [
      '#title' => t('User fields'),
      '#type' => 'select',
      '#multiple' => TRUE,
      '#options' => static::$userinfoFields,
      '#description' => t(
        'List of fields to fetch, which will translate to the required scopes. Some fields require IAL/2 Authentication Assurance Level. See the  <a href="@docs" target="_blank">Login.gov documentation</a> for more details. The Email and UUID (sub) fields are always fetched.',
        [
          '@docs' => 'https://developers.login.gov/attributes/',
        ]
      ),
      '#default_value' => $this->getSetting('userinfo_fields', []),
    ];

    $form['force_reauth'] = [
      '#title' => t('Force Reauthorization'),
      '#type' => 'checkbox',
      '#default_value' => $this->getSetting('force_reauth', FALSE),
      '#description' => t('Require the user to login again to Login.gov. <em>Requires login.gov administrator approval.</em>'),
    ];
    //watchdog('Debug', '<pre>' . print_r($form,1) . '</pre>');

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function getEndpoints(): array {
    return $this->getSetting('sandbox_mode') ? [
      'authorization' => 'https://idp.int.identitysandbox.gov/openid_connect/authorize',
      'token' => 'https://idp.int.identitysandbox.gov/api/openid_connect/token',
      'userinfo' => 'https://idp.int.identitysandbox.gov/api/openid_connect/userinfo',
      'end_session' => 'https://idp.int.identitysandbox.gov/openid_connect/logout',
      'certs' => 'https://idp.int.identitysandbox.gov/api/openid_connect/certs',
    ] :
    [
      'authorization' => 'https://secure.login.gov/openid_connect/authorize',
      'token' => 'https://secure.login.gov/api/openid_connect/token',
      'userinfo' => 'https://secure.login.gov/api/openid_connect/userinfo',
      'end_session' => 'https://secure.login.gov/openid_connect/logout',
      'certs' => 'https://secure.login.gov/api/openid_connect/certs',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function authorize($scope = 'openid email') {
    $redirect_uri = OPENID_CONNECT_REDIRECT_PATH_BASE . '/' . $this->name;
    $url_options = $this->getUrlOptions($scope, $redirect_uri);
    $endpoints = $this->getEndpoints();
    // Clear $_GET['destination'] because we need to override it.
    unset($_GET['destination']);
    drupal_goto($endpoints['authorization'], $url_options);
  }

  /**
   * Helper function for URL options.
   *
   * @param string $scope
   *   A string of scopes.
   * @param string $redirect_uri
   *   URI to redirect for authorization.
   *
   * @return array
   *   Array with URL options.
   */
  protected function getUrlOptions(string $scope, string $redirect_uri): array {
    $additional_scopes = $this->getSetting('userinfo_fields', NULL);
    $options = [
      'query' => [
        'client_id' => $this->getSetting('client_id'),
        'response_type' => 'code',
        'scope' => $scope . (isset($additional_scopes) ? ' ' . implode(' ', $additional_scopes) : ''),
        'redirect_uri' => url($redirect_uri, array(
          'absolute' => TRUE,
          'language' => LANGUAGE_NONE,
        )),
        'state' => openid_connect_create_state_token(),
      ],
    ];

    $nonce = $this->generateNonce();
    $options['query'] += [
      'acr_values' => $this->generateAcrValue(),
      'nonce' => $nonce,
    ];
    $this->lists_session('login_gov.nonce', $nonce);

    if ($this->settings['acr_level'] == '2' && $this->settings['verified_within']['count']) {
      $options['query']['verified_within'] = $this->settings['verified_within']['count'] . $this->settings['verified_within']['units'];
    }
    $options['query']['prompt'] = $this->settings['force_reauth'] ? 'login' : 'select_account';

    return $options;
  }


  /**
   * {@inheritdoc}
   */
  public function retrieveUserInfo($access_token) {
    $request_options = array(
      'headers' => array(
        'Authorization' => 'Bearer ' . $access_token,
        'Accept' => 'application/json',
      ),
    );
    $endpoints = $this->getEndpoints();
    $response = drupal_http_request($endpoints['userinfo'], $request_options);
    if (!isset($response->error) && $response->code == 200) {
      $data = drupal_json_decode($response->data);
      watchdog('OpenID Connect LoginGov user logged in', '<pre>' . print_r($data, 1) . '</pre>');
      return $data ?: FALSE;
    }
    else {
      openid_connect_log_request_error(__FUNCTION__, $this->name, $response);
      return FALSE;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function decodeIdToken($id_token) {
    return array();
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveTokens($authorization_code) {
    // Exchange `code` for access token and ID token.
    $redirect_uri = OPENID_CONNECT_REDIRECT_PATH_BASE . '/' . $this->name;
    $endpoints = $this->getEndpoints();
    $post_data = $this->getEncryptedRequestOptions($authorization_code, $redirect_uri);

    $post_data['form_params'] += array(
      'code' => $authorization_code,
      'client_id' => $this->getSetting('client_id'),
      'client_secret' => '',
      'redirect_uri' => url($redirect_uri, array('absolute' => TRUE)),
    );

    $request_options = array(
      'method' => 'POST',
      'data' => drupal_http_build_query($post_data['form_params']),
      'timeout' => 15,
      'headers' => array(
        'Content-Type' => 'application/x-www-form-urlencoded',
        'Accept' => 'application/json',
      ),
    );
    
    $response = drupal_http_request($endpoints['token'], $request_options);

    if (!isset($response->error) && $response->code == 200) {
      $tokens = drupal_json_decode($response->data);
      // Verify the nonce is the one we sent earlier.
      if (!empty($tokens['id_token'])) {
        $keys = $this->getPeerPublicKeys();
        $decoded_tokens = JWT::decode($tokens['id_token'], $keys);
        $session_nonce = $this->lists_session('login_gov.nonce');
        if (!empty($session_nonce) && ($decoded_tokens->nonce !== $session_nonce)) {
          return NULL;
        }
      }

      return $tokens;
    }
    else {
      openid_connect_log_request_error(__FUNCTION__, $this->name, $response);
      return FALSE;
    }
  }

  /**
   * {@inheritdoc}
   */
  protected function getEncryptedRequestOptions(string $authorization_code, string $redirect_uri): array {
    $endpoints = $this->getEndpoints();

    // Build the client assertion.
    // See https://developers.login.gov/oidc/#token
    $client_assertion_payload = [
      'iss' => $this->settings['client_id'],
      'sub' => $this->settings['client_id'],
      'aud' => $endpoints['token'],
      'jti' => $this->generateNonce(),
      'exp' => time() + 300,
    ];
    // Add the client assertion to the list of options.
    $options = [
      'client_assertion' => $this->signJwtPayload($client_assertion_payload),
      'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      'code' => $authorization_code,
      'grant_type' => 'authorization_code',
    ];
    return [
      'form_params' => $options,
      'headers' => [
        'Accept' => 'application/json',
      ],
    ];
  }

  /**
   * Sign the JWT.
   *
   * @param array $payload
   *   An array of key-value pairs.
   *
   * @return string
   *   The signed JWT.
   */
  public function signJwtPayload(array $payload): string {
    return JWT::encode($payload, $this->getPrivateKey(), 'RS256');
  }

  /**
   * Return the private key for signing the JWTs.
   *
   * @return string
   *   The private key in PEM format.
   */
  protected function getPrivateKey(): ?string {
    $key = trim($this->settings['client_secret']);
    // Return the key's KeyValue, or fall back to the old configuration if there
    // is no Key.
    return $key ? $key : $this->settings['client_secret'];
  }

  /**
   * Get login.gov's public signing key.
   *
   * @return array|null
   *   A list of public keys.
   */
  protected function getPeerPublicKeys(): ?array {
    $endpoints = $this->getEndpoints();
    $request_options = array(
      'method' => 'GET',
      'data' => '',
      'timeout' => 15,
      'headers' => array(
        'Content-Type' => 'application/x-www-form-urlencoded',
        'Accept' => 'application/json',
      ),
    );
  
    $response = drupal_http_request($endpoints['certs'], $request_options);
    if (!isset($response->error) && $response->code == 200) {
      $keys = drupal_json_decode($response->data);
      return JWK::parseKeySet($keys);
    } else {
      return [];
    }
  }

  /**
   * Generate a one-time use code word, a nonce.
   *
   * @param int $length
   *   The length of the nonce.
   *
   * @return string
   *   The nonce.
   */
  protected function generateNonce(int $length = 26): string {
    return substr(drupal_random_key($length), 0, $length);
  }

  /**
   * Generate the acr_values portion of the URL options.
   *
   * @return string
   *   The Authentication Context Class Reference value.
   */
  protected function generateAcrValue(): string {
    $acrs = [];

    foreach (array_filter($this->settings['acr_level']) as $acr_level) {
      $param = ($acr_level == 'aal/3' && $this->settings['require_piv']) ? '?hspd12=true' : '';
      $acrs[] = 'http://idmanagement.gov/ns/assurance/' . $acr_level . $param;
    }

    return implode(' ', $acrs);
  }

  /**
   * {@inheritdoc}
   */
  protected function getEncryptedUrlOptions($options, string $scope, string $redirect_uri): array {
    $nonce = $this->generateNonce();
    $options['query'] += [
      'acr_values' => $this->generateAcrValue(),
      'nonce' => $nonce,
    ];
    $this->requestStack->getCurrentRequest()->getSession()->set('login_gov.nonce', $nonce);

    if ($this->configuration['acr_level'] == '2' && $this->configuration['verified_within']['count']) {
      $options['query']['verified_within'] = $this->configuration['verified_within']['count'] . $this->configuration['verified_within']['units'];
    }
    $options['query']['prompt'] = $this->configuration['force_reauth'] ? 'login' : 'select_account';

    return $options;
  }

  public function lists_session($key, $value = NULL) {
    static $storage;
    if ($value) {
      $storage[$key] = $value ;
      $_SESSION['lists'][$key] = $value ;   // I use 'lists' in case some other module uses 'type' in $_SESSION
    }
    else if (empty($storage[$key]) && isset($_SESSION['lists'][$key])) {
      $storage[$key] = $_SESSION['lists'][$key];
    }
    return $storage[$key];
  }

}
