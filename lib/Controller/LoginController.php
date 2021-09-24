<?php

/** @noinspection AdditionOperationOnArraysInspection */

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2020, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\UserOIDC\Controller;

use OCA\UserOIDC\Event\AttributeMappedEvent;
use OCA\UserOIDC\Event\TokenObtainedEvent;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\OIDCService;
use OCA\UserOIDC\Service\UserService;
use OCA\UserOIDC\Service\InvalidTokenException;
use OCA\UserOIDC\Vendor\Firebase\JWT\JWT;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Http\Client\IClientService;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Security\ISecureRandom;

class LoginController extends Controller {
	private const STATE = 'oidc.state';
	private const NONCE = 'oidc.nonce';
	private const PROVIDERID = 'oidc.providerid';
	private const REDIRECT_AFTER_LOGIN = 'oidc.redirect';

	/** @var ISecureRandom */
	private $random;

	/** @var ISession */
	private $session;

	/** @var IClientService */
	private $clientService;

	/** @var IURLGenerator */
	private $urlGenerator;

	/** @var UserMapper */
	private $userMapper;

	/** @var IUserSession */
	private $userSession;

	/** @var IUserManager */
	private $userManager;

	/** @var ProviderMapper */
	private $providerMapper;

	/** @var ILogger */
	private $logger;

	/** @var ProviderService */
	private $providerService;

	/** @var UserService */
	private $userService;

	/** @var DiscoveryService */
	private $discoveryService;

	/** @var OIDCService */
	private $userInfoService;
	
	public function __construct(
		IRequest $request,
		ProviderMapper $providerMapper,
		ProviderService $providerService,
		UserService $userService,
		DiscoveryService $discoveryService,
		OIDCService $oidcService,
		ISecureRandom $random,
		ISession $session,
		IClientService $clientService,
		IURLGenerator $urlGenerator,
		UserMapper $userMapper,
		IUserSession $userSession,
		IUserManager $userManager,
		IEventDispatcher $eventDispatcher,
		ILogger $logger
	) {
		parent::__construct(Application::APP_ID, $request);

		$this->random = $random;
		$this->session = $session;
		$this->clientService = $clientService;
		$this->userService = $userService;
		$this->discoveryService = $discoveryService;
		$this->oidcService =$oidcService;
		$this->urlGenerator = $urlGenerator;
		$this->userMapper = $userMapper;
		$this->userSession = $userSession;
		$this->userManager = $userManager;
		$this->providerMapper = $providerMapper;
		$this->providerService = $providerService;
		$this->eventDispatcher = $eventDispatcher;
		$this->logger = $logger;
	}

	/**
	 * @PublicPage
	 * @NoCSRFRequired
	 * @UseSession
	 */
	public function login(int $providerId, string $redirectUrl = null) {
		$this->logger->debug('Initiating login for provider with id: ' . $providerId);

		//TODO: handle exceptions
		$provider = $this->providerMapper->getProvider($providerId);

		$state = $this->random->generate(32, ISecureRandom::CHAR_DIGITS . ISecureRandom::CHAR_UPPER);
		$this->session->set(self::STATE, $state);
		$this->session->set(self::REDIRECT_AFTER_LOGIN, $redirectUrl);

		$nonce = $this->random->generate(32, ISecureRandom::CHAR_DIGITS . ISecureRandom::CHAR_UPPER);
		$this->session->set(self::NONCE, $nonce);

		$this->session->set(self::PROVIDERID, $providerId);
		$this->session->close();

		$data = [
			'client_id' => $provider->getClientId(),
			'response_type' => 'code',
			'scope' => $provider->getScope(),
			'redirect_uri' => $this->urlGenerator->linkToRouteAbsolute(Application::APP_ID . '.login.code'),
			// 'claims' => json_encode([
			// 	// more details about requesting claims:
			// 	// https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
			// 	'id_token' => [
			// 		// ['essential' => true] means it's mandatory but it won't trigger an error if it's not there
			// 		$uidAttribute => ['essential' => true],
			// 		// null means we want it
			// 		$emailAttribute => null,
			// 		$displaynameAttribute => null,
			// 		$quotaAttribute => null,
			// 	],
			// 	'userinfo' => [
			// 		$uidAttribute => ['essential' => true],
			// 		$emailAttribute => null,
			// 		$displaynameAttribute => null,
			// 		$quotaAttribute => null,
			// 	],
			// ]),
			'claims' => json_encode([
				'id_token' => [
					'urn:telekom.com:all' => null
				],
				'userinfo' => [
					'urn:telekom.com:all' => null
				],
			]),
			'state' => $state,
			'nonce' => $nonce,
		];

		// pass discovery query parameters also on to the authentication
		// $discoveryUrl = parse_url($provider->getDiscoveryEndpoint());
		// if (isset($discoveryUrl["query"])) {
		// 	$this->logger->debug('Add custom discovery query: ' . $discoveryUrl["query"]);
		// 	$discoveryQuery = [];
		// 	parse_str($discoveryUrl["query"], $discoveryQuery);
		// 	$data += $discoveryQuery;
		// }

		try {
			$discovery = $this->discoveryService->obtainDiscovery($provider);
		} catch (\Exception $e) {
			$this->logger->error('Could not reach provider at URL ' . $provider->getDiscoveryEndpoint());
			$response = new Http\TemplateResponse('', 'error', [
				'errors' => [
					['error' => 'Could not the reach OpenID Connect provider.']
				]
			], Http\TemplateResponse::RENDER_AS_ERROR);
			$response->setStatus(404);
			return $response;
		}

		//TODO verify discovery

		$url = $discovery['authorization_endpoint'] . '?' . http_build_query($data);
		$this->logger->debug('Redirecting user to: ' . $url);

		return new RedirectResponse($url);
	}

	/**
	 * @PublicPage
	 * @NoCSRFRequired
	 * @UseSession
	 */
	public function code($state = '', $code = '', $scope = '') {
		$this->logger->debug('Code login with core: ' . $code . ' and state: ' . $state);

		if ($this->session->get(self::STATE) !== $state) {
			$this->logger->debug('state does not match');

			// TODO show page with forbidden
			return new JSONResponse([
				'got' => $state,
				'expected' => $this->session->get(self::STATE),
			], Http::STATUS_FORBIDDEN);
		}

		$providerId = (int)$this->session->get(self::PROVIDERID);
		$provider = $this->providerMapper->getProvider($providerId);

		$discovery = $this->discoveryService->obtainDiscovery($provider);
		$this->logger->debug('Obtainting data from: ' . $discovery['token_endpoint']);

		$client = $this->clientService->newClient();
		$result = $client->post(
			$discovery['token_endpoint'],
			[
				'body' => [
					'code' => $code,
					'client_id' => $provider->getClientId(),
					'client_secret' => $provider->getClientSecret(),
					'redirect_uri' => $this->urlGenerator->linkToRouteAbsolute(Application::APP_ID . '.login.code'),
					'grant_type' => 'authorization_code',
				],
			]
		);

		$data = json_decode($result->getBody(), true);
		$this->logger->debug('Received code response: ' . json_encode($data, JSON_THROW_ON_ERROR));
		$this->eventDispatcher->dispatchTyped(new TokenObtainedEvent($data, $provider, $discovery));

		// TODO: proper error handling
		$jwks = $this->discoveryService->obtainJWK($provider);
		JWT::$leeway = 60;
		$payload = JWT::decode($data['id_token'], $jwks, array_keys(JWT::$supported_algs));
		$this->logger->debug('Parsed the JWT payload: ' . json_encode($payload, JSON_THROW_ON_ERROR));

		// the nonce is used to associate the token to the previous redirect
		if (isset($payload->nonce) && $payload->nonce !== $this->session->get(self::NONCE)) {
			$this->logger->debug('Nonce does not match');
			// TODO: error properly
			return new JSONResponse(['invalid nonce'], Http::STATUS_UNAUTHORIZED);
		}

		try {
			$this->oidcService->verifyToken($provider, $payload); 
		} catch (InvalidTokenException $eInvalid) {
			return new JSONResponse($eInvalid->getMessage(), Http::STATUS_UNAUTHORIZED);
		}

		// NextMagentaCloud: at the moment not a good idea for SAM3
		// if something is missing from the token, get user info from /userinfo endpoint
		// FIXME: only when attribute mapping is set or optional
		// if (is_null($userId) || is_null($userName) || is_null($email) || is_null($quota)) {
		// 	$options = [
		// 		'headers' => [
		// 			'Authorization' => 'Bearer ' . $data['access_token'],
		// 		],
		// 	];
		// 	$userInfoResult = json_decode($client->get($discovery['userinfo_endpoint'], $options)->getBody(), true);
		// 	$userId = $userId ?? $userInfoResult[$uidAttribute] ?? null;
		// 	$userName = $userName ?? $userInfoResult[$displaynameAttribute] ?? null;
		// 	$email = $email ?? $userInfoResult[$emailAttribute] ?? null;
		// 	$quota = $quota ?? $userInfoResult[$quotaAttribute] ?? null;
		// }

		try {
			$user = $this->userService->userFromToken($providerId, $payload);
		} catch (AttributeValueException $eAttribute) {
			return new JSONResponse($eAttribute->getMessage(), Http::STATUS_NOT_ACCEPTABLE);
		}

		$this->logger->debug('Complete user login, make session');	
		$this->userSession->setUser($user);
		$this->userSession->completeLogin($user, ['loginName' => $user->getUID(), 'password' => '']);
		$this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());

		$this->logger->debug('Redirecting user');
		$redirectUrl = $this->session->get(self::REDIRECT_AFTER_LOGIN);
		if ($redirectUrl) {
			return new RedirectResponse($redirectUrl);
		}

		return new RedirectResponse(\OC_Util::getDefaultPageUrl());
	}
}
