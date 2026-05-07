<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\UserOIDC\Service;

use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Event\AttributeMappedEvent;
use OCA\UserOIDC\Event\UserAccountChangeEvent;
use OCA\UserOIDC\Event\UserAccountChangeResult;
use OCP\Accounts\IAccountManager;
use OCP\DB\Exception;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Http\Client\IClientService;
use OCP\IAvatarManager;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Security\ICrypto;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\Log\LoggerInterface;

class ProvisioningEventService extends ProvisioningService {
	public function __construct(
		LocalIdService $idService,
		private ProviderService $providerService,
		UserMapper $userMapper,
		private IUserManager $userManager,
		IGroupManager $groupManager,
		private IEventDispatcher $eventDispatcher,
		private LoggerInterface $logger,
		IAccountManager $accountManager,
		IClientService $clientService,
		IAvatarManager $avatarManager,
		IConfig $config,
		ISession $session,
		private IFactory $l10nFactory,
		private ProviderMapper $providerMapper,
		private ICrypto $crypto,
	) {
		parent::__construct(
			$idService,
			$providerService,
			$userMapper,
			$userManager,
			$groupManager,
			$eventDispatcher,
			$logger,
			$accountManager,
			$clientService,
			$avatarManager,
			$config,
			$session,
			$l10nFactory,
			$providerMapper,
			$crypto,
		);
	}

	protected function mapDispatchUID(int $providerId, object $payload, string $tokenUserId): string {
		$uidAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_UID, 'sub');
		$mappedUserId = $payload->{$uidAttribute} ?? $tokenUserId;

		if (!is_string($mappedUserId) || trim($mappedUserId) === '') {
			throw new AttributeValueException('Mapped uid is empty or invalid');
		}

		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_UID, $payload, $mappedUserId);
		$this->eventDispatcher->dispatchTyped($event);

		$value = $event->getValue();
		if (!is_string($value) || trim($value) === '') {
			throw new AttributeValueException('Mapped uid is empty or invalid');
		}

		return $value;
	}

	protected function mapDispatchDisplayname(int $providerId, object $payload): ?string {
		$displaynameAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_DISPLAYNAME, 'displayname');
		$mappedDisplayName = $payload->{$displaynameAttribute} ?? null;

		if (is_string($mappedDisplayName) && $mappedDisplayName !== '') {
			$mappedDisplayName = mb_substr($mappedDisplayName, 0, 255);
		} elseif ($mappedDisplayName !== null) {
			$mappedDisplayName = (string)$mappedDisplayName;
		}

		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_DISPLAYNAME, $payload, $mappedDisplayName);
		$this->eventDispatcher->dispatchTyped($event);

		$value = $event->getValue();

		return $value === null ? null : (string)$value;
	}

	protected function mapDispatchEmail(int $providerId, object $payload): ?string {
		$emailAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_EMAIL, 'email');
		$mappedEmail = $payload->{$emailAttribute} ?? null;

		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_EMAIL, $payload, $mappedEmail);
		$this->eventDispatcher->dispatchTyped($event);

		$value = $event->getValue();

		return $value === null ? null : (string)$value;
	}

	protected function mapDispatchQuota(int $providerId, object $payload): ?string {
		$quotaAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_QUOTA, 'quota');
		$mappedQuota = $payload->{$quotaAttribute} ?? null;

		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_QUOTA, $payload, $mappedQuota);
		$this->eventDispatcher->dispatchTyped($event);

		$value = $event->getValue();

		return $value === null ? null : (string)$value;
	}

	protected function dispatchUserAccountUpdate(
		string $uid,
		?string $displayName,
		?string $email,
		?string $quota,
		object $payload,
	): UserAccountChangeResult {
		$event = new UserAccountChangeEvent($uid, $displayName, $email, $quota, $payload);
		$this->eventDispatcher->dispatchTyped($event);

		$result = $event->getResult();

		if ($result->hasDecision() && !$result->isAccessAllowed()) {
			throw new ProvisioningDeniedException(
				$result->getReason(),
				$result->getRedirectUrl(),
			);
		}

		return $result;
	}

	/**
	 * Trigger provisioning via event system.
	 *
	 * @return array{user: ?IUser, userData: array}
	 * @throws Exception
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 * @throws ProvisioningDeniedException
	 */
	public function provisionUser(
		string $tokenUserId,
		int $providerId,
		object $idTokenPayload,
		?IUser $existingLocalUser = null,
	): array {
		try {
			$uid = $this->mapDispatchUID($providerId, $idTokenPayload, $tokenUserId);
			$displayName = $this->mapDispatchDisplayname($providerId, $idTokenPayload);
			$email = $this->mapDispatchEmail($providerId, $idTokenPayload);
			$quota = $this->mapDispatchQuota($providerId, $idTokenPayload);
		} catch (AttributeValueException $e) {
			$this->logger->info($tokenUserId . ': user rejected by OpenID web authorization, reason: ' . $e->getMessage());
			throw new ProvisioningDeniedException($e->getMessage());
		}

		$userReaction = $this->dispatchUserAccountUpdate($uid, $displayName, $email, $quota, $idTokenPayload);

		if ($userReaction->hasDecision()) {
			if ($userReaction->isAccessAllowed()) {
				$this->logger->info($uid . ': account accepted, reason: ' . $userReaction->getReason());

				return [
					'user' => $existingLocalUser ?? $this->userManager->get($uid),
					'userData' => get_object_vars($idTokenPayload),
				];
			}

			$this->logger->info($uid . ': account rejected, reason: ' . $userReaction->getReason());

			throw new ProvisioningDeniedException(
				$userReaction->getReason(),
				$userReaction->getRedirectUrl(),
			);
		}

		return parent::provisionUser($tokenUserId, $providerId, $idTokenPayload, $existingLocalUser);
	}
}
