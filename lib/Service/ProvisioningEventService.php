<?php
/*
 * @copyright Copyright (c) 2021 Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.com>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

declare(strict_types=1);

namespace OCA\UserOIDC\Service;

use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Event\AttributeMappedEvent;
use OCA\UserOIDC\Event\UserAccountChangeEvent;
use OCP\DB\Exception;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IGroupManager;
use OCP\ILogger;
use OCP\IUser;
use OCP\IUserManager;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

// FIXME there should be an interface for both variations
class ProvisioningEventService extends ProvisioningService {

	/** @var IEventDispatcher */
	private $eventDispatcher;

	/** @var ILogger */
	private $logger;

	/** @var IUserManager */
	private $userManager;

	/** @var ProviderService */
	private $providerService;

	public function __construct(
		LocalIdService   $idService,
		ProviderService  $providerService,
		UserMapper       $userMapper,
		IUserManager     $userManager,
		IGroupManager    $groupManager,
		IEventDispatcher $eventDispatcher,
		ILogger          $logger
	) {
		parent::__construct($idService,
							$providerService,
							$userMapper,
							$userManager,
							$groupManager,
							$eventDispatcher,
							$logger);
		$this->eventDispatcher = $eventDispatcher;
		$this->logger = $logger;
		$this->userManager = $userManager;
		$this->providerService = $providerService;
	}

	protected function mapDispatchUID(int $providerid, object $payload, string $tokenUserId) {
		$uidAttribute = $this->providerService->getSetting($providerid, ProviderService::SETTING_MAPPING_UID, 'sub');
		$mappedUserId = $payload->{$uidAttribute} ?? $tokenUserId;
		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_UID, $payload, $mappedUserId);
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getValue();
	}

	protected function mapDispatchDisplayname(int $providerid, object $payload) {
		$displaynameAttribute = $this->providerService->getSetting($providerid, ProviderService::SETTING_MAPPING_DISPLAYNAME, 'displayname');
		$mappedDisplayName = $payload->{$displaynameAttribute} ?? null;

		if (isset($mappedDisplayName)) {
			$limitedDisplayName = mb_substr($mappedDisplayName, 0, 255);
			$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_DISPLAYNAME, $payload, $limitedDisplayName);
		} else {
			$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_DISPLAYNAME, $payload);
		}
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getValue();
	}

	protected function mapDispatchEmail(int $providerid, object $payload) {
		$emailAttribute = $this->providerService->getSetting($providerid, ProviderService::SETTING_MAPPING_EMAIL, 'email');
		$mappedEmail = $payload->{$emailAttribute} ?? null;
		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_EMAIL, $payload, $mappedEmail);
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getValue();
	}

	protected function mapDispatchQuota(int $providerid, object $payload) {
		$quotaAttribute = $this->providerService->getSetting($providerid, ProviderService::SETTING_MAPPING_QUOTA, 'quota');
		$mappedQuota = $payload->{$quotaAttribute} ?? null;
		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_QUOTA, $payload, $mappedQuota);
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getValue();
	}

	protected function dispatchUserAccountUpdate(string $uid, ?string $displayName, ?string $email, ?string $quota, object $payload) {
		$event = new UserAccountChangeEvent($uid, $displayName, $email, $quota, $payload);
		$this->eventDispatcher->dispatchTyped($event);
		return $event->getResult();
	}

	/**
	 * Trigger a provisioning via event system.
	 * This allows to flexibly implement complex provisioning strategies -
	 * even in a separate app.
	 *
	 * On error, the provisioning logic can deliver failure reasons and
	 * even a redirect to a different endpoint.
	 *
	 * @param string $tokenUserId
	 * @param int $providerId
	 * @param object $idTokenPayload
	 * @return IUser|null
	 * @throws Exception
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 * @throws ProvisioningDeniedException
	 */
	public function provisionUser(string $tokenUserId, int $providerId, object $idTokenPayload): ?IUser {
		try {
			// for multiple reasons, it is better to take the uid directly from a token field
			//$uid = $this->mapDispatchUID($providerId, $idTokenPayload, $tokenUserId);
			$uid = $tokenUserId;
			$displayname = $this->mapDispatchDisplayname($providerId, $idTokenPayload);
			$email = $this->mapDispatchEmail($providerId, $idTokenPayload);
			$quota = $this->mapDispatchQuota($providerId, $idTokenPayload);
		} catch (AttributeValueException $eAttribute) {
			$this->logger->info("{$uid}: user rejected by OpenId web authorization, reason: " . $eAttribute->getMessage());
			throw new ProvisioningDeniedException($eAttribute->getMessage());
		}

		$userReaction = $this->dispatchUserAccountUpdate($uid, $displayname, $email, $quota, $idTokenPayload);
		if ($userReaction->isAccessAllowed()) {
			$this->logger->info("{$uid}: account accepted, reason: " . $userReaction->getReason());
			$user = $this->userManager->get($uid);
			return $user;
		} else {
			$this->logger->info("{$uid}: account rejected, reason: " . $userReaction->getReason());
			throw new ProvisioningDeniedException($userReaction->getReason(), $userReaction->getRedirectUrl());
		}
	}
}
