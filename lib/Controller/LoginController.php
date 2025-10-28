<?php

/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** @noinspection AdditionOperationOnArraysInspection */

declare(strict_types=1);

namespace OCA\UserOIDC\Controller;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ServerException;
use OC\Authentication\Token\IProvider;
use OC\User\Session as OC_UserSession;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\SessionMapper;
use OCA\UserOIDC\Event\TokenObtainedEvent;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\LdapService;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\ProvisioningService;
use OCA\UserOIDC\Service\TokenService;
use OCA\UserOIDC\User\Backend;
use OCA\UserOIDC\Vendor\Firebase\JWT\JWT;
use OCA\UserOIDC\Vendor\Firebase\JWT\Key;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\MultipleObjectsReturnedException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataDisplayResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\DB\Exception;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Http\Client\IClientService;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Security\ICrypto;
use OCP\Security\ISecureRandom;
use OCP\Session\Exceptions\SessionNotAvailableException;
use OCP\User\Events\BeforeUserLoggedInEvent;
use OCP\User\Events\UserLoggedInEvent;
use Psr\Log\LoggerInterface;

class LoginController extends BaseOidcController {
	private const STATE = 'oidc.state';
	private const NONCE = 'oidc.nonce';
	public const PROVIDERID = 'oidc.providerid';
	private const REDIRECT_AFTER_LOGIN = 'oidc.redirect';
	private const ID_TOKEN = 'oidc.id_token';
	private const CODE_VERIFIER = 'oidc.code_verifier';

	public function __construct(
		IRequest $request,
		private ProviderMapper $providerMapper,
		private ProviderService $providerService,
		private DiscoveryService $discoveryService,
		private LdapService $ldapService,
		private ISecureRandom $random,
		private ISession $session,
		private IClientService $clientService,
		private IURLGenerator $urlGenerator,
		private IUserSession $userSession,
		private IUserManager $userManager,
		private ITimeFactory $timeFactory,
		private IEventDispatcher $eventDispatcher,
		private IConfig $config,
		private IProvider $authTokenProvider,
		private SessionMapper $sessionMapper,
		private ProvisioningService $provisioningService,
		private IL10N $l10n,
		private LoggerInterface $logger,
		private ICrypto $crypto,
		private TokenService $tokenService,
	) {
		// Psalm-Fix: BaseOidcController erwartet $l10n im Konstruktor
		parent::__construct($request, $config, $this->l10n);
	}

	private function isSecure(): bool {
		// no restriction in debug mode
		return $this->isDebugModeEnabled() || $this->request->getServerProtocol() === 'https';
	}

	private function buildProtocolErrorResponse(?bool $throttle = null): TemplateResponse {
		// Psalm-Fix: buildFailureTemplateResponse entfernte/abweichende Signatur vermeiden
		// Nutze buildErrorTemplateResponse(message, status, metadata, throttleFlag)
		$message = $this->l10n->t('You must access Nextcloud with HTTPS to use OpenID Connect.');
		return $this->buildErrorTemplateResponse(
			$message,
			Http::STATUS_NOT_FOUND,
			['reason' => 'insecure connection'],
			$throttle ?? false
		);
	}

	private function getRedirectResponse(?string $redirectUrl = null): RedirectResponse {
		if ($redirectUrl === null || $redirectUrl === '') {
			return new RedirectResponse($this->urlGenerator->getBaseUrl());
		}

		if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $redirectUrl) === 1 || str_starts_with($redirectUrl, '//')) {
			return new RedirectResponse($this->urlGenerator->getBaseUrl());
		}

		$redirectUrl = preg_replace('/[\r\n\\\\]/', '', $redirectUrl);

		$path = parse_url($redirectUrl, PHP_URL_PATH) ?? '/';
		$query = parse_url($redirectUrl, PHP_URL_QUERY);
		$safe = rtrim($this->urlGenerator->getBaseUrl(), '/') . '/' . ltrim($path, '/')
			. ($query ? '?' . $query : '');

		return new RedirectResponse($safe);
	}

	/**
	 * @PublicPage
	 * @NoCSRFRequired
	 * @UseSession
	 * @BruteForceProtection(action=userOidcLogin)
	 *
	 * @param int $providerId
	 * @param string|null $redirectUrl
	 * @return DataDisplayResponse|RedirectResponse|TemplateResponse
	 */
	public function login(int $providerId, ?string $redirectUrl = null): DataDisplayResponse|RedirectResponse|TemplateResponse {
		if ($this->userSession->isLoggedIn()) {
			return $this->getRedirectResponse($redirectUrl);
		}
		if (!$this->isSecure()) {
			return $this->buildProtocolErrorResponse();
		}
		$this->logger->debug('Initiating OIDC login', ['providerId' => $providerId]);

		try {
			$provider = $this->providerMapper->getProvider($providerId);
		} catch (DoesNotExistException|MultipleObjectsReturnedException $e) {
			$message = $this->l10n->t('There is not such OpenID Connect provider.');
			return $this->buildErrorTemplateResponse($message, Http::STATUS_NOT_FOUND, ['provider_not_found' => $providerId]);
		}

		$data = [];
		$discoveryUrl = parse_url($provider->getDiscoveryEndpoint());
		if (isset($discoveryUrl['query'])) {
			$this->logger->debug('Add custom discovery query', ['query' => $discoveryUrl['query']]);
			$discoveryQuery = [];
			parse_str($discoveryUrl['query'], $discoveryQuery);
			$data += $discoveryQuery;
		}

		try {
			$discovery = $this->discoveryService->obtainDiscovery($provider);
		} catch (\Exception $e) {
			$this->logger->error('Could not reach the provider', [
				'discovery' => $provider->getDiscoveryEndpoint(),
				'exception' => $e,
			]);
			$message = $this->l10n->t('Could not reach the OpenID Connect provider.');
			return $this->buildErrorTemplateResponse($message, Http::STATUS_NOT_FOUND, ['reason' => 'provider unreachable']);
		}

		$state = $this->random->generate(32, ISecureRandom::CHAR_DIGITS . ISecureRandom::CHAR_UPPER);
		$nonce = $this->random->generate(32, ISecureRandom::CHAR_DIGITS . ISecureRandom::CHAR_UPPER);
		$this->session->set(self::STATE, $state);
		$this->session->set(self::NONCE, $nonce);
		$this->session->set(self::PROVIDERID, $providerId);
		$this->session->set(self::REDIRECT_AFTER_LOGIN, $redirectUrl);

		$oidcSystemConfig = $this->config->getSystemValue('user_oidc', []);
		$isPkceSupported = in_array('S256', $discovery['code_challenge_methods_supported'] ?? [], true);
		$isPkceEnabled = $isPkceSupported && ($oidcSystemConfig['use_pkce'] ?? true);

		if ($isPkceEnabled) {
			$code_verifier = $this->random->generate(128, ISecureRandom::CHAR_DIGITS . ISecureRandom::CHAR_UPPER . ISecureRandom::CHAR_LOWER);
			$this->session->set(self::CODE_VERIFIER, $code_verifier);
		}

		$this->session->close();

		$uidAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_UID, 'sub');

		$claims = [
			'id_token' => [],
			'userinfo' => [],
		];

		$isDefaultClaimsEnabled = !isset($oidcSystemConfig['enable_default_claims']) || $oidcSystemConfig['enable_default_claims'] !== false;
		if ($isDefaultClaimsEnabled) {
			$emailAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_EMAIL, 'email');
			$displaynameAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_DISPLAYNAME, 'name');
			$quotaAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_QUOTA, 'quota');
			$groupsAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_GROUPS, 'groups');
			foreach ([$emailAttribute, $displaynameAttribute, $quotaAttribute, $groupsAttribute] as $claim) {
				$claims['id_token'][$claim] = null;
				$claims['userinfo'][$claim] = null;
			}
		} else {
			$emailAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_EMAIL);
			$displaynameAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_DISPLAYNAME);
			$quotaAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_QUOTA);
			$groupsAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_GROUPS);
			foreach ([$emailAttribute, $displaynameAttribute, $quotaAttribute, $groupsAttribute] as $claim) {
				if ($claim !== '') {
					$claims['id_token'][$claim] = null;
					$claims['userinfo'][$claim] = null;
				}
			}
		}

		if ($uidAttribute !== 'sub') {
			$claims['id_token'][$uidAttribute] = ['essential' => true];
			$claims['userinfo'][$uidAttribute] = ['essential' => true];
		}

		$extraClaimsString = $this->providerService->getSetting($providerId, ProviderService::SETTING_EXTRA_CLAIMS, '');
		if ($extraClaimsString) {
			$extraClaims = explode(' ', $extraClaimsString);
			foreach ($extraClaims as $extraClaim) {
				$claims['id_token'][$extraClaim] = null;
				$claims['userinfo'][$extraClaim] = null;
			}
		}

		$data += [
			'client_id' => $provider->getClientId(),
			'response_type' => 'code',
			'scope' => trim($provider->getScope()),
			'redirect_uri' => $this->urlGenerator->linkToRouteAbsolute(Application::APP_ID . '.login.code'),
			'claims' => json_encode($claims),
			'state' => $state,
			'nonce' => $nonce,
		];
		if ($isPkceEnabled) {
			$data['code_challenge'] = $this->toCodeChallenge($this->session->get(self::CODE_VERIFIER));
			$data['code_challenge_method'] = 'S256';
		}
		$authorizationUrl = $this->discoveryService->buildAuthorizationUrl($discovery['authorization_endpoint'], $data);

		$this->logger->debug('Redirecting user to OP authorization endpoint');

		if ($this->request->isUserAgent(['/Safari/']) && !$this->request->isUserAgent(['/Chrome/'])) {
			return new DataDisplayResponse('<meta http-equiv="refresh" content="0; url=' . htmlspecialchars($authorizationUrl, ENT_QUOTES, 'UTF-8') . '" />');
		}

		return new RedirectResponse($authorizationUrl);
	}

	/**
	 * @PublicPage
	 * @NoCSRFRequired
	 * @UseSession
	 * @BruteForceProtection(action=userOidcCode)
	 *
	 * @param string $state
	 * @param string $code
	 * @param string $scope
	 * @param string $error
	 * @param string $error_description
	 * @return JSONResponse|RedirectResponse|TemplateResponse
	 * @throws DoesNotExistException
	 * @throws MultipleObjectsReturnedException
	 * @throws SessionNotAvailableException
	 * @throws \JsonException
	 */
	public function code(string $state = '', string $code = '', string $scope = '', string $error = '', string $error_description = ''): JSONResponse|RedirectResponse|TemplateResponse {
		if (!$this->isSecure()) {
			return $this->buildProtocolErrorResponse();
		}
		$this->logger->debug('OIDC code flow callback received');

		if ($error !== '') {
			return new JSONResponse([
				'error' => $error,
				'error_description' => $error_description,
			], Http::STATUS_FORBIDDEN);
		}

		if ($this->session->get(self::STATE) !== $state) {
			$this->logger->debug('State does not match');
			$message = $this->l10n->t('The received state does not match the expected value.');
			if ($this->isDebugModeEnabled()) {
				$responseData = [
					'error' => 'invalid_state',
					'error_description' => $message,
					'got' => $state,
					'expected' => $this->session->get(self::STATE),
				];
				return new JSONResponse($responseData, Http::STATUS_FORBIDDEN);
			}
			return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, ['reason' => 'state does not match'], true);
		}

		$providerId = (int)$this->session->get(self::PROVIDERID);
		$provider = $this->providerMapper->getProvider($providerId);
		try {
			$providerClientSecret = $this->crypto->decrypt($provider->getClientSecret());
		} catch (\Exception $e) {
			$this->logger->error('Failed to decrypt the client secret', ['exception' => $e]);
			$message = $this->l10n->t('Failed to decrypt the OIDC provider client secret');
			return $this->buildErrorTemplateResponse($message, Http::STATUS_BAD_REQUEST, [], false);
		}

		$discovery = $this->discoveryService->obtainDiscovery($provider);

		$this->logger->debug('Requesting tokens at OP token endpoint');

		$oidcSystemConfig = $this->config->getSystemValue('user_oidc', []);
		$isPkceSupported = in_array('S256', $discovery['code_challenge_methods_supported'] ?? [], true);
		$isPkceEnabled = $isPkceSupported && ($oidcSystemConfig['use_pkce'] ?? true);

		$client = $this->clientService->newClient();
		try {
			$requestBody = [
				'code' => $code,
				'redirect_uri' => $this->urlGenerator->linkToRouteAbsolute(Application::APP_ID . '.login.code'),
				'grant_type' => 'authorization_code',
			];
			if ($isPkceEnabled) {
				$requestBody['code_verifier'] = $this->session->get(self::CODE_VERIFIER);
			}

			$headers = [];
			$tokenEndpointAuthMethod = 'client_secret_post';
			$supported = $discovery['token_endpoint_auth_methods_supported'] ?? null;

			if (is_array($supported)) {
				if (in_array('client_secret_basic', $supported, true) && !in_array('client_secret_post', $supported, true)) {
					$tokenEndpointAuthMethod = 'client_secret_basic';
				}
			}

			if ($tokenEndpointAuthMethod === 'client_secret_basic') {
				$headers = [
					'Authorization' => 'Basic ' . base64_encode($provider->getClientId() . ':' . $providerClientSecret),
					'Content-Type' => 'application/x-www-form-urlencoded',
				];
			} else {
				$requestBody['client_id'] = $provider->getClientId();
				$requestBody['client_secret'] = $providerClientSecret;
			}

			$result = $client->post(
				$discovery['token_endpoint'],
				[
					'body' => $requestBody,
					'headers' => $headers,
				]
			);
		} catch (ClientException|ServerException $e) {
			$response = $e->getResponse();
			$body = (string)$response->getBody();
			$responseBodyArray = json_decode($body, true);
			if ($responseBodyArray !== null && isset($responseBodyArray['error'], $responseBodyArray['error_description'])) {
				$this->logger->debug('OP token endpoint error', [
					'exception' => $e,
					'error' => $responseBodyArray['error'],
					'error_description' => $responseBodyArray['error_description'],
				]);
				$message = $this->l10n->t('Failed to contact the OIDC provider token endpoint') . ': ' . $responseBodyArray['error_description'];
			} else {
				$this->logger->debug('OP token endpoint error', ['exception' => $e]);
				$message = $this->l10n->t('Failed to contact the OIDC provider token endpoint');
			}
			return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, [], false);
		} catch (\Exception $e) {
			$this->logger->debug('OP token endpoint error (generic)', ['exception' => $e]);
			$message = $this->l10n->t('Failed to contact the OIDC provider token endpoint');
			return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, [], false);
		}

		$data = json_decode($result->getBody(), true);
		$this->logger->debug('Token response received (redacted)');

		$this->eventDispatcher->dispatchTyped(new TokenObtainedEvent($data, $provider, $discovery));

		$idTokenRaw = $data['id_token'] ?? null;
		if (!$idTokenRaw) {
			$message = $this->l10n->t('No ID token received from the provider.');
			return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, ['reason' => 'missing id_token']);
		}

		$jwks = $this->discoveryService->obtainJWK($provider, $idTokenRaw);
		JWT::$leeway = 60;
		$idTokenPayload = JWT::decode($idTokenRaw, $jwks);

		$this->logger->debug('ID token parsed (claims redacted)');

		$now = $this->timeFactory->getTime();

		if (isset($idTokenPayload->exp) && (int)$idTokenPayload->exp < $now) {
			$this->logger->debug('Token expired');
			$message = $this->l10n->t('The received token is expired.');
			return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, ['reason' => 'token expired']);
		}

		if (!isset($discovery['issuer']) || $idTokenPayload->iss !== $discovery['issuer']) {
			$this->logger->debug('Invalid issuer');
			$message = $this->l10n->t('The issuer does not match the one from the discovery endpoint');
			return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, ['invalid_issuer' => $idTokenPayload->iss ?? null]);
		}

		$checkAudience = !isset($oidcSystemConfig['login_validation_audience_check'])
			|| !in_array($oidcSystemConfig['login_validation_audience_check'], [false, 'false', 0, '0'], true);
		if ($checkAudience) {
			$tokenAudience = $idTokenPayload->aud ?? null;
			$providerClientId = $provider->getClientId();
			if (
				(is_string($tokenAudience) && $tokenAudience !== $providerClientId)
				|| (is_array($tokenAudience) && !in_array($providerClientId, $tokenAudience, true))
			) {
				$this->logger->debug('Invalid audience');
				$message = $this->l10n->t('The audience does not match ours');
				return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, ['invalid_audience' => $idTokenPayload->aud ?? null]);
			}
		}

		$checkAzp = !isset($oidcSystemConfig['login_validation_azp_check'])
			|| !in_array($oidcSystemConfig['login_validation_azp_check'], [false, 'false', 0, '0'], true);
		if ($checkAzp) {
			if (isset($idTokenPayload->azp) && $idTokenPayload->azp !== $provider->getClientId()) {
				$this->logger->debug('Invalid azp');
				$message = $this->l10n->t('The authorized party does not match ours');
				return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, ['invalid_azp' => $idTokenPayload->azp]);
			}
		}

		if (isset($idTokenPayload->nonce) && $idTokenPayload->nonce !== $this->session->get(self::NONCE)) {
			$this->logger->debug('Invalid nonce');
			$message = $this->l10n->t('The nonce does not match');
			return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, ['reason' => 'invalid nonce']);
		}

		$uidAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_UID, 'sub');
		$userId = $idTokenPayload->{$uidAttribute} ?? null;
		if ($userId === null) {
			$message = $this->l10n->t('Failed to provision the user');
			return $this->build403TemplateResponse($message, Http::STATUS_BAD_REQUEST, ['reason' => 'failed to provision user']);
		}

		$restrictLoginToGroups = $this->providerService->getSetting($providerId, ProviderService::SETTING_RESTRICT_LOGIN_TO_GROUPS, '0');
		if ($restrictLoginToGroups === '1') {
			$syncGroups = $this->provisioningService->getSyncGroupsOfToken($providerId, $idTokenPayload);

			if ($syncGroups === null || count($syncGroups) === 0) {
				$this->logger->debug('User not in any whitelisted group');
				$message = $this->l10n->t('You do not have permission to log in to this instance. If you think this is an error, please contact an administrator.');
				return $this->build403TemplateResponse($message, Http::STATUS_FORBIDDEN, ['reason' => 'user not in any whitelisted group']);
			}
		}

		$autoProvisionAllowed = (!isset($oidcSystemConfig['auto_provision']) || $oidcSystemConfig['auto_provision']);
		$softAutoProvisionAllowed = (!isset($oidcSystemConfig['soft_auto_provision']) || $oidcSystemConfig['soft_auto_provision']);

		$shouldDoUserLookup = !$autoProvisionAllowed || ($softAutoProvisionAllowed && !$this->provisioningService->hasOidcUserProvisitioned($userId));
		if ($shouldDoUserLookup && $this->ldapService->isLDAPEnabled()) {
			$this->userManager->search($userId, 1, 0);
			$this->ldapService->syncUser($userId);
		}

		$userFromOtherBackend = $this->userManager->get($userId);
		if ($userFromOtherBackend !== null && $this->ldapService->isLdapDeletedUser($userFromOtherBackend)) {
			$userFromOtherBackend = null;
		}

		if ($autoProvisionAllowed) {
			if (!$softAutoProvisionAllowed && $userFromOtherBackend !== null) {
				$message = $this->l10n->t('User conflict');
				return $this->build403TemplateResponse($message, Http::STATUS_BAD_REQUEST, ['reason' => 'non-soft auto provision, user conflict'], false);
			}
			$user = $this->provisioningService->provisionUser($userId, $providerId, $idTokenPayload, $userFromOtherBackend);
		} else {
			$user = $userFromOtherBackend;
		}

		if ($user === null) {
			$message = $this->l10n->t('Failed to provision the user');
			return $this->build403TemplateResponse($message, Http::STATUS_BAD_REQUEST, ['reason' => 'failed to provision user']);
		}

		try {
			$this->session->set(self::ID_TOKEN, $this->crypto->encrypt($idTokenRaw));
		} catch (\Exception $e) {
			$this->logger->debug('Failed to encrypt ID token for session storage', ['exception' => $e]);
		}

		$this->logger->debug('Logging user in');

		$this->userSession->setUser($user);
		if ($this->userSession instanceof OC_UserSession) {
			$this->userSession->completeLogin($user, ['loginName' => $user->getUID(), 'password' => '']);
			$this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());
			$this->userSession->createRememberMeToken($user);
			$this->eventDispatcher->dispatchTyped(new BeforeUserLoggedInEvent($user->getUID(), null, \OC::$server->get(Backend::class)));
			$this->eventDispatcher->dispatchTyped(new UserLoggedInEvent($user, $user->getUID(), null, false));
		}

		$this->session->remove(self::STATE);
		$this->session->remove(self::NONCE);
		$this->session->remove(self::CODE_VERIFIER);

		$this->session->set('last-password-confirm', $this->timeFactory->getTime() + (60 * 60 * 24 * 365 * 4));

		// createSession nur aufrufen, wenn vorhanden
		try {
			$authToken = $this->authTokenProvider->getToken($this->session->getId());

			$sidForStorage = $idTokenPayload->sid
				?? $idTokenPayload->{'urn:telekom.com:session_token'}
				?? 'fallback-sid';

			if (method_exists($this->sessionMapper, 'createSession')) {
				$this->sessionMapper->createSession(
					$sidForStorage,
					$idTokenPayload->sub ?? 'fallback-sub',
					$idTokenPayload->iss ?? 'fallback-iss',
					$authToken->getId(),
					$this->session->getId()
				);
			} else {
				$this->logger->debug('SessionMapper::createSession not available; skipping backchannel mapping persist.');
			}
		} catch (\Throwable $e) {
			// InvalidTokenException oder andere — nicht kritisch für Login
			$this->logger->debug('Auth token not found or persistence failed after login', ['exception' => $e]);
		}

		if ($user->canChangeAvatar()) {
			$this->logger->debug('User can change avatar (post-login sync may occur)');
		}

		$this->logger->debug('Redirecting user after login');

		$redirectUrl = $this->session->get(self::REDIRECT_AFTER_LOGIN);
		if ($redirectUrl) {
			return $this->getRedirectResponse($redirectUrl);
		}

		return new RedirectResponse(\OC_Util::getDefaultPageUrl());
	}

	/**
	 * Endpoint called by NC to logout in the IdP before killing the current session
	 *
	 * @PublicPage
	 * @NoAdminRequired
	 * @NoCSRFRequired
	 * @UseSession
	 * @BruteForceProtection(action=userOidcSingleLogout)
	 *
	 * @return RedirectResponse|TemplateResponse
	 * @throws Exception
	 * @throws SessionNotAvailableException
	 * @throws \JsonException
	 */
	public function singleLogoutService(): RedirectResponse|TemplateResponse {
		$oidcSystemConfig = $this->config->getSystemValue('user_oidc', []);
		$targetUrl = $this->urlGenerator->getAbsoluteURL('/');
		if (!isset($oidcSystemConfig['single_logout']) || $oidcSystemConfig['single_logout']) {
			$isFromGS = ($this->config->getSystemValueBool('gs.enabled', false)
				&& $this->config->getSystemValueString('gss.mode', '') === 'master');
			if ($isFromGS) {
				$jwt = $this->request->getParam('jwt', '');

				try {
					$key = $this->config->getSystemValueString('gss.jwt.key', '');
					$decoded = (array)JWT::decode($jwt, new Key($key, 'HS256'));

					$providerId = $decoded['oidcProviderId'] ?? null;
				} catch (\Exception $e) {
					$this->logger->debug('Failed to get the logout provider ID from GSS', ['exception' => $e]);
				}
			} else {
				$providerId = $this->session->get(self::PROVIDERID);
			}
			if ($providerId) {
				try {
					$provider = $this->providerMapper->getProvider((int)$providerId);
				} catch (DoesNotExistException|MultipleObjectsReturnedException $e) {
					$message = $this->l10n->t('There is not such OpenID Connect provider.');
					return $this->buildErrorTemplateResponse($message, Http::STATUS_NOT_FOUND, ['provider_id' => $providerId]);
				}

				$discoveryData = $this->discoveryService->obtainDiscovery($provider);
				$defaultEndSessionEndpoint = $discoveryData['end_session_endpoint'] ?? null;
				$customEndSessionEndpoint = $provider->getEndSessionEndpoint();
				$endSessionEndpoint = $customEndSessionEndpoint ?: $defaultEndSessionEndpoint;

				if ($endSessionEndpoint) {
					$endSessionEndpoint .= '?post_logout_redirect_uri=' . $targetUrl;
					$endSessionEndpoint .= '&client_id=' . $provider->getClientId();
					$shouldSendIdToken = $this->providerService->getSetting(
						$provider->getId(),
						ProviderService::SETTING_SEND_ID_TOKEN_HINT, '0'
					) === '1';
					$idTokenHint = null;
					$idTokenEncrypted = $this->session->get(self::ID_TOKEN);
					if ($shouldSendIdToken && $idTokenEncrypted) {
						try {
							$idTokenHint = $this->crypto->decrypt($idTokenEncrypted);
						} catch (\Exception $e) {
							$this->logger->debug('Failed to decrypt ID token for logout hint', ['exception' => $e]);
						}
					}
					if ($shouldSendIdToken && $idTokenHint) {
						$endSessionEndpoint .= '&id_token_hint=' . $idTokenHint;
					}
					$targetUrl = $endSessionEndpoint;
				}
			}
		}

		$this->userSession->logout();
		$this->session->clear();
		return new RedirectResponse($targetUrl);
	}

	/**
	 * Endpoint called by the IdP (OP) when end_session_endpoint is called by another client
	 * Implemented according to https://openid.net/specs/openid-connect-backchannel-1_0.html
	 *
	 * @PublicPage
	 * @NoCSRFRequired
	 *
	 * @param string $providerIdentifier
	 * @param string $logout_token
	 * @return JSONResponse
	 * @throws Exception
	 * @throws \JsonException
	 */
	public function backChannelLogout(string $providerIdentifier, string $logout_token = ''): JSONResponse {
		$provider = $this->providerService->getProviderByIdentifier($providerIdentifier);
		if ($provider === null) {
			return $this->getBackchannelLogoutErrorResponse(
				'provider not found',
				'The provider was not found in Nextcloud',
				['provider_not_found' => $providerIdentifier]
			);
		}

		$jwks = $this->discoveryService->obtainJWK($provider, $logout_token);
		JWT::$leeway = 60;
		$logoutTokenPayload = JWT::decode($logout_token, $jwks);

		$this->logger->debug('Backchannel logout token parsed (claims redacted)');

		$aud = $logoutTokenPayload->aud ?? null;
		$clientId = $provider->getClientId();
		$audOk = is_string($aud) ? $aud === $clientId : (is_array($aud) && in_array($clientId, $aud, true));
		if (!$audOk) {
			return $this->getBackchannelLogoutErrorResponse(
				'invalid audience',
				'The audience of the logout token does not match the provider',
				['invalid_audience' => $aud]
			);
		}

		if (!isset($logoutTokenPayload->events->{'http://schemas.openid.net/event/backchannel-logout'})) {
			return $this->getBackchannelLogoutErrorResponse(
				'invalid event',
				'The backchannel-logout event was not found in the logout token',
				['invalid_event' => true]
			);
		}

		if (isset($logoutTokenPayload->nonce)) {
			return $this->getBackchannelLogoutErrorResponse(
				'invalid nonce',
				'The logout token should not contain a nonce attribute',
				['nonce_should_not_be_set' => true]
			);
		}

		$now = $this->timeFactory->getTime();
		if (!isset($logoutTokenPayload->iat) || abs($now - (int)$logoutTokenPayload->iat) > 300) {
			return $this->getBackchannelLogoutErrorResponse(
				'stale token',
				'Logout token is too old or missing iat',
				['iat' => $logoutTokenPayload->iat ?? null]
			);
		}

		if (!isset($logoutTokenPayload->sid) && !isset($logoutTokenPayload->sub)) {
			return $this->getBackchannelLogoutErrorResponse(
				'missing sid/sub',
				'The logout token must contain at least sid or sub',
				[]
			);
		}

		$sid = $logoutTokenPayload->sid ?? null;

		try {
			if ($sid === null) {
				return $this->getBackchannelLogoutErrorResponse(
					'invalid SID',
					'The sid of the logout token was not found',
					['session_sid_not_found' => null]
				);
			}

			$oidcSession = $this->sessionMapper->findSessionBySid($sid);
		} catch (DoesNotExistException $e) {
			return $this->getBackchannelLogoutErrorResponse(
				'invalid SID',
				'The sid of the logout token was not found',
				['session_sid_not_found' => $sid]
			);
		} catch (MultipleObjectsReturnedException $e) {
			return $this->getBackchannelLogoutErrorResponse(
				'invalid SID',
				'The sid of the logout token was found multiple times',
				['multiple_logout_tokens_found' => $sid]
			);
		}

		$sub = $logoutTokenPayload->sub ?? null;
		if (isset($sub) && ($oidcSession->getSub() !== $sub)) {
			return $this->getBackchannelLogoutErrorResponse(
				'invalid SUB',
				'The sub does not match the one from the login ID token',
				['invalid_sub' => $sub]
			);
		}

		$iss = $logoutTokenPayload->iss ?? null;
		if ($oidcSession->getIss() !== $iss) {
			return $this->getBackchannelLogoutErrorResponse(
				'invalid ISS',
				'The iss does not match the one from the login ID token',
				['invalid_iss' => $iss]
			);
		}

		$authTokenId = (int)$oidcSession->getAuthtokenId();
		try {
			$authToken = $this->authTokenProvider->getTokenById($authTokenId);
			$userId = $authToken->getUID();
			$this->authTokenProvider->invalidateTokenById($userId, $authToken->getId());
		} catch (\Throwable $e) {
			// bereits ungültig → ok
		}

		$this->sessionMapper->delete($oidcSession);

		return new JSONResponse();
	}

	/**
	 * Backward compatible function for MagentaCLOUD to smoothly transition to new config
	 *
	 * @PublicPage
	 * @NoCSRFRequired
	 * @BruteForceProtection(action=userOidcBackchannelLogout)
	 *
	 * @param string $logout_token
	 * @return JSONResponse
	 * @throws Exception
	 * @throws \JsonException
	 */
	public function telekomBackChannelLogout(string $logout_token = ''): JSONResponse {
		return $this->backChannelLogout('Telekom', $logout_token);
	}

	/**
	 * Generate a backchannel logout response.
	 * Log the error but always return HTTP 200 OK for IDM compliance.
	 *
	 * @param string $error
	 * @param string $description
	 * @param array $throttleMetadata
	 * @return JSONResponse
	 */
	private function getBackchannelLogoutErrorResponse(
		string $error,
		string $description,
		array $throttleMetadata = []
	): JSONResponse {
		$this->logger->debug('Backchannel logout error', ['error' => $error, 'description' => $description] + $throttleMetadata);
		return new JSONResponse(
			[
				'error' => $error,
				'error_description' => $description,
			],
			Http::STATUS_OK,
		);
	}

	private function toCodeChallenge(string $data): string {
		return rtrim(strtr(base64_encode(hash('sha256', $data, true)), '+/', '-_'), '=');	
	}
}
