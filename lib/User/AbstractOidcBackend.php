<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\UserOIDC\User;

use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\ProviderService;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\DB\Exception;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\IRootFolder;
use OCP\Files\ISetupManager;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\Server;
use OCP\User\Backend\ABackend;
use OCP\User\Backend\ICustomLogout;
use OCP\User\Backend\IGetDisplayNameBackend;
use OCP\User\Backend\ILimitAwareCountUsersBackend;
use OCP\User\Backend\IPasswordConfirmationBackend;
use OCP\User\Events\UserFirstTimeLoggedInEvent;
use Psr\Log\LoggerInterface;

abstract class AbstractOidcBackend extends ABackend implements IPasswordConfirmationBackend, IGetDisplayNameBackend, ICustomLogout, ILimitAwareCountUsersBackend {

	public function __construct(
		protected IConfig $config,
		protected UserMapper $userMapper,
		protected LoggerInterface $logger,
		protected IRequest $request,
		protected ISession $session,
		protected IURLGenerator $urlGenerator,
		protected IEventDispatcher $eventDispatcher,
		protected DiscoveryService $discoveryService,
		protected ProviderMapper $providerMapper,
		protected ProviderService $providerService,
		protected IUserManager $userManager,
	) {
	}

	public function countUsers(int $limit = 0): int|false {
		try {
			$count = $this->userMapper->countUsers();

			if ($limit > 0 && $count > $limit) {
				return $limit;
			}

			return $count;
		} catch (\Throwable $e) {
			$this->logger->error('Failed to count OIDC users', [
				'exception' => $e,
			]);

			return false;
		}
	}

	public function deleteUser($uid): bool {
		if (!is_string($uid) || $uid === '') {
			return false;
		}

		try {
			$user = $this->userMapper->getUser($uid);
			$this->userMapper->delete($user);
			return true;
		} catch (DoesNotExistException $e) {
			$this->logger->info('Tried to delete non-existent user', [
				'uid' => $uid,
				'exception' => $e,
			]);
			return false;
		} catch (Exception $e) {
			$this->logger->error('Failed to delete user', [
				'uid' => $uid,
				'exception' => $e,
			]);
			return false;
		}
	}

	public function getUsers($search = '', $limit = null, $offset = null): array {
		if (!is_string($search)
			|| ($limit !== null && !is_int($limit))
			|| ($offset !== null && !is_int($offset))
		) {
			return [];
		}

		return array_map(
			static fn ($user) => $user->getUserId(),
			$this->userMapper->find($search, $limit, $offset)
		);
	}

	public function userExists($uid): bool {
		return is_string($uid) && $uid !== '' && $this->userMapper->userExists($uid);
	}

	public function getDisplayName($uid): string {
		if (!is_string($uid) || $uid === '') {
			return (string)$uid;
		}

		try {
			$user = $this->userMapper->getUser($uid);
			return $user->getDisplayName();
		} catch (DoesNotExistException) {
			return $uid;
		}
	}

	public function getDisplayNames($search = '', $limit = null, $offset = null): array {
		if (!is_string($search)
			|| ($limit !== null && !is_int($limit))
			|| ($offset !== null && !is_int($offset))
		) {
			return [];
		}

		return $this->userMapper->findDisplayNames($search, $limit, $offset);
	}

	public function hasUserListings(): bool {
		return true;
	}

	public function canConfirmPassword(string $uid): bool {
		return false;
	}

	public function injectSession(ISession $session): void {
		$this->session = $session;
	}

	public function getLogoutUrl(): string {
		return $this->urlGenerator->linkToRouteAbsolute('user_oidc.login.singleLogoutService');
	}

	protected function isAcceptableUserId(mixed $userId): bool {
		return is_string($userId) && trim($userId) !== '';
	}

	protected function checkFirstLogin(string $userId): bool {
		$user = $this->userManager->get($userId);
		if ($user === null) {
			return false;
		}

		$firstLogin = $user->getLastLogin() === 0;

		if ($firstLogin) {
			try {
				if (version_compare($this->config->getSystemValueString('version', '0.0.0'), '34.0.0', '>=')
					&& interface_exists(ISetupManager::class)
				) {
					Server::get(ISetupManager::class)->setupForUser($user);
				} else {
					\OC_Util::setupFS($userId);
				}

				$userFolder = Server::get(IRootFolder::class)->getUserFolder($userId);
				\OC_Util::copySkeleton($userId, $userFolder);
			} catch (\Throwable $e) {
				$this->logger->warning('Could not fully set up user filesystem on first login', [
					'userId' => $userId,
					'exception' => $e,
				]);
			}

			if (class_exists(UserFirstTimeLoggedInEvent::class)) {
				$this->eventDispatcher->dispatchTyped(new UserFirstTimeLoggedInEvent($user));
			}
		}

		$user->updateLastLoginTimestamp();

		return $firstLogin;
	}
}
