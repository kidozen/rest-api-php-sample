<?php require 'vendor/autoload.php';

$kido        = new Kido('https://company.kidocloud.com', 'app', 'company@kidozen.com', 'p4ssw0rd', 'Kidozen');
$object_sets = $kido->getObjectSets();
var_dump($object_sets);

class Kido {

	private $client;
	private $marketplace;
	private $app;
	private $user;
	private $pass;
	private $authentication_provider;
	private $config;
	private $token;

	function __construct($marketplace, $app, $user, $pass, $authentication_provider) {
		$this->client                  = new GuzzleHttp\Client();
		$this->marketplace             = $marketplace;
		$this->app                     = $app;
		$this->user                    = $user;
		$this->pass                    = $pass;
		$this->authentication_provider = $authentication_provider;
		$this->config                  = $this->getAppConfig();
		$this->token                   = $this->getAuthenticationToken();
	}

	public function getObjectSets() {
		$url = $this->config['url'] . 'storage/local';
		return $this->client->get($url, [
				'headers' => [
					'authorization' => $this->token['token']
				]
			])->json();
	}

	private function getAuthenticationToken() {
		$wsTrustToken = function ($client, $user, $pass, $auth_service_scope, $endpoint) {
			$template = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><a:Action s:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action><a:To s:mustUnderstand="1">[To]</a:To><o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:UsernameToken u:Id="uuid-6a13a244-dac6-42c1-84c5-cbb345b0c4c4-1"><o:Username>[Username]</o:Username><o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">[Password]</o:Password></o:UsernameToken></o:Security></s:Header><s:Body><trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><a:EndpointReference><a:Address>[ApplyTo]</a:Address></a:EndpointReference></wsp:AppliesTo><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType><trust:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</trust:TokenType></trust:RequestSecurityToken></s:Body></s:Envelope>';
			$template = str_replace('[To]', $endpoint, $template);
			$template = str_replace('[Username]', $user, $template);
			$template = str_replace('[Password]', $pass, $template);
			$template = str_replace('[ApplyTo]', $auth_service_scope, $template);

			return (string) $client->post($endpoint, [
					'headers' => [
						'Content-Type' => 'application/soap+xml; charset=utf-8'
					],
					'body' => $template
				])->getBody();
		};

		$wrapToken = function ($client, $user, $pass, $auth_service_scope, $endpoint) {
			return (string) $client->post($endpoint, [
					'body' => [
						'wrap_name'     => $user,
						'wrap_password' => $pass,
						'wrap_scope'    => $auth_service_scope,
					]
				])->getBody();
		};

		$auth_config = $this->config['authConfig'];
		$ip          = $auth_config['identityProviders'][$this->authentication_provider];

		if (strtolower($ip['protocol']) == 'wrapv0.9') {
			$getToken = $wrapToken;
		} else if (strtolower($ip['protocol']) == 'ws-trust') {
			$getToken = $wsTrustToken;
		} else {
			throw new Exception('Authorization protocol not supported');
		}

		$body = $getToken($this->client, $this->user, $this->pass, $auth_config['authServiceScope'], $ip['endpoint']);

		if (!preg_match('/<Assertion(.*)<\/Assertion>/', $body, $assertion)) {
			throw new Exception('Unable to get a token from IDP');
		}

		$token = $this->client->post($auth_config['authServiceEndpoint'], [
				'body' => [
					'wrap_assertion'        => $assertion[0],
					'wrap_scope'            => $auth_config['applicationScope'],
					'wrap_assertion_format' => 'SAML',
				]
			])->json();

		if (!$token || (!isset($token['access_token']) && !isset($token['rawToken']))) {
			throw new Exception('Unable to retrieve KidoZen token');
		}

		$access_token    = isset($token['access_token']) ? $token['access_token'] : $token['rawToken'];
		$token['token']  = 'WRAP access_token="' . $access_token . '"';
		$token_data      = urldecode($access_token);
		$claims          = explode('&', $token_data);
		$token['claims'] = $claims;
		foreach ($claims as $key => $value) {
			if (strpos($value, 'ExpiresOn')) {
				$token['expiresOn'] = intval(explode('=', $value)[1]) * 1000 - 20 * 1000;
				break;
			}
		}

		return $token;
	}

	private function getAppConfig() {
		return $this->client->get($this->marketplace . '/publicapi/apps?name=' . $this->app)->json()[0];
	}

}