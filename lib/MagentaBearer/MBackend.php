<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\UserOIDC\MagentaBearer;

use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\ProvisioningDeniedException;
use OCA\UserOIDC\Service\ProvisioningEventService;
use OCA\UserOIDC\User\AbstractOidcBackend;
use OCP\Authentication\IApacheBackend;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\Security\ICrypto;
use Psr\Log\LoggerInterface;

class MBackend extends AbstractOidcBackend implements IApacheBackend {

	public function __construct(
		IConfig $config,
		UserMapper $userMapper,
		LoggerInterface $logger,
		IRequest $request,
		ISession $session,
		IURLGenerator $urlGenerator,
		IEventDispatcher $eventDispatcher,
		DiscoveryService $discoveryService,
		ProviderMapper $providerMapper,
		ProviderService $providerService,
		IUserManager $userManager,
		protected ICrypto $crypto,
		protected TokenService $mtokenService,
		protected ProvisioningEventService $provisioningService,
	) {
		parent::__construct(
			$config,
			$userMapper,
			$logger,
			$request,
			$session,
			$urlGenerator,
			$eventDispatcher,
			$discoveryService,
			$providerMapper,
			$providerService,
			$userManager,
		);
	}

	public function getBackendName(): string {
		return Application::APP_ID . '\\MagentaBearer';
	}

	/**
	 * Backend is activated if a bearer token header is detected.
	 */
	public function isSessionActive(): bool {
		$headerToken = $this->request->getHeader(Application::OIDC_API_REQ_HEADER);

		return preg_match('/^\s*bearer\s+/i', $headerToken) === 1;
	}

	public function getCurrentUserId(): string {
		$headerToken = $this->request->getHeader(Application::OIDC_API_REQ_HEADER);

		if (preg_match('/^\s*bearer\s+/i', $headerToken) !== 1) {
			$this->logger->debug('No Bearer token');
			return '';
		}

		$headerToken = preg_replace('/^\s*bearer\s+/i', '', $headerToken);
		if (!is_string($headerToken) || $headerToken === '') {
			$this->logger->debug('No Bearer token');
			return '';
		}

		$providers = $this->providerMapper->getProviders();
		if (count($providers) === 0) {
			$this->logger->debug('No OIDC providers');
			return '';
		}

		foreach ($providers as $provider) {
			if ($this->providerService->getSetting($provider->getId(), ProviderService::SETTING_CHECK_BEARER, '0') !== '1') {
				continue;
			}

			try {
				$sharedSecret = $this->crypto->decrypt($provider->getBearerSecret());
				$bearerToken = $this->mtokenService->decryptToken($headerToken, $sharedSecret);
				$this->mtokenService->verifySignature($bearerToken, $sharedSecret);

				$payload = $this->mtokenService->decode($bearerToken);
				$this->mtokenService->verifyClaims($payload, ['http://auth.magentacloud.de']);
			} catch (InvalidTokenException $e) {
				$this->logger->debug('Invalid token: ' . $e->getMessage() . '. Trying another provider.');
				continue;
			} catch (SignatureException $e) {
				$this->logger->debug($e->getMessage() . '. Trying another provider.');
				continue;
			} catch (\Throwable $e) {
				$this->logger->debug('General non-matching provider problem: ' . $e->getMessage());
				continue;
			}

			$uidAttribute = $this->providerService->getSetting($provider->getId(), ProviderService::SETTING_MAPPING_UID, 'sub');
			$userId = is_object($payload) ? ($payload->{$uidAttribute} ?? null) : null;

			if (!$this->isAcceptableUserId($userId)) {
				$this->logger->debug('No extractable user id, check mapping!');
				return '';
			}

			try {
				$provisioningResult = $this->provisioningService->provisionUser($userId, $provider->getId(), $payload);
				$provisionedUser = $provisioningResult['user'] ?? null;

				if ($provisionedUser instanceof IUser) {
					$userId = $provisionedUser->getUID();
				}

				$this->checkFirstLogin($userId);

				return $userId;
			} catch (ProvisioningDeniedException $e) {
				$this->logger->error('Bearer token access denied: ' . $e->getMessage());
				return '';
			}
		}

		$this->logger->debug('Could not find provider for token');

		return '';
	}
}
