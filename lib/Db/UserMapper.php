<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\UserOIDC\Db;

use OCA\UserOIDC\Service\LocalIdService;
use OCP\AppFramework\Db\IMapperException;
use OCP\AppFramework\Db\QBMapper;
use OCP\Cache\CappedMemoryCache;
use OCP\IDBConnection;
use Psr\Log\LoggerInterface;

/**
 * @extends QBMapper<User>
 */
class UserMapper extends QBMapper {

	private CappedMemoryCache $userCache;
	private LoggerInterface $logger;

	public function __construct(
		IDBConnection $db,
		LoggerInterface $logger,
		private LocalIdService $idService,
	) {
		parent::__construct($db, 'user_oidc', User::class);
		$this->userCache = new CappedMemoryCache();
		$this->logger = $logger;
	}

	/**
	 * @param string $uid
	 * @return User
	 * @throws \OCP\AppFramework\Db\DoesNotExistException
	 * @throws \OCP\AppFramework\Db\MultipleObjectsReturnedException
	 */
	public function getUser(string $uid): User {
		$cachedUser = $this->userCache->get($uid);
		if ($cachedUser !== null) {
			return $cachedUser;
		}

		$qb = $this->db->getQueryBuilder();
		$qb->select('*')
			->from($this->getTableName())
			->where(
				$qb->expr()->eq('user_id', $qb->createNamedParameter($uid))
			);

		/** @var User $user */
		$user = $this->findEntity($qb);
		$this->userCache->set($uid, $user);
		return $user;
	}

	public function find(string $search, $limit = null, $offset = null): array {
		$qb = $this->db->getQueryBuilder();

		$backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
		$stack = [];

		foreach ($backtrace as $index => $trace) {
			$class = $trace['class'] ?? '';
			$type = $trace['type'] ?? '';
			$function = $trace['function'] ?? '';
			$file = $trace['file'] ?? 'unknown file';
			$line = $trace['line'] ?? 'unknown line';

			$stack[] = sprintf(
				"#%d %s%s%s() called at [%s:%s]",
				$index,
				$class,
				$type,
				$function,
				$file,
				$line
			);
		}

		$this->logger->debug("Find user by string: " . $search . " -- Call Stack:\n" . implode("\n", $stack));

		$qb->select('user_id', 'display_name')
			->from($this->getTableName(), 'u')
			->leftJoin('u', 'preferences', 'p', $qb->expr()->andX(
				$qb->expr()->eq('userid', 'user_id'),
				$qb->expr()->eq('appid', $qb->expr()->literal('settings')),
				$qb->expr()->eq('configkey', $qb->expr()->literal('email')))
			)
			->where($qb->expr()->iLike('user_id', $qb->createPositionalParameter('%' . $this->db->escapeLikeParameter($search) . '%')))
			->orWhere($qb->expr()->iLike('display_name', $qb->createPositionalParameter('%' . $this->db->escapeLikeParameter($search) . '%')))
			->orWhere($qb->expr()->iLike('configvalue', $qb->createPositionalParameter('%' . $this->db->escapeLikeParameter($search) . '%')))
			->orderBy($qb->func()->lower('user_id'), 'ASC')
			->setMaxResults($limit)
			->setFirstResult($offset);

		return $this->findEntities($qb);
	}

	public function findDisplayNames(string $search, $limit = null, $offset = null): array {
		$qb = $this->db->getQueryBuilder();

		$backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
		$stack = [];

		foreach ($backtrace as $index => $trace) {
			$class = $trace['class'] ?? '';
			$type = $trace['type'] ?? '';
			$function = $trace['function'] ?? '';
			$file = $trace['file'] ?? 'unknown file';
			$line = $trace['line'] ?? 'unknown line';

			$stack[] = sprintf(
				"#%d %s%s%s() called at [%s:%s]",
				$index,
				$class,
				$type,
				$function,
				$file,
				$line
			);
		}

		$this->logger->debug("Find user display names by string: " . $search . " -- Call Stack:\n" . implode("\n", $stack));

		$qb->select('user_id', 'display_name')
			->from($this->getTableName(), 'u')
			->leftJoin('u', 'preferences', 'p', $qb->expr()->andX(
				$qb->expr()->eq('userid', 'user_id'),
				$qb->expr()->eq('appid', $qb->expr()->literal('settings')),
				$qb->expr()->eq('configkey', $qb->expr()->literal('email')))
			)
			->where($qb->expr()->iLike('user_id', $qb->createPositionalParameter('%' . $this->db->escapeLikeParameter($search) . '%')))
			->orWhere($qb->expr()->iLike('display_name', $qb->createPositionalParameter('%' . $this->db->escapeLikeParameter($search) . '%')))
			->orWhere($qb->expr()->iLike('configvalue', $qb->createPositionalParameter('%' . $this->db->escapeLikeParameter($search) . '%')))
			->orderBy($qb->func()->lower('user_id'), 'ASC')
			->setMaxResults($limit)
			->setFirstResult($offset);

		$result = $qb->execute();
		$displayNames = [];
		while ($row = $result->fetch()) {
			$displayNames[(string)$row['user_id']] = (string)$row['display_name'];
		}

		return $displayNames;
	}

	public function userExists(string $uid): bool {
		try {
			$this->getUser($uid);
			return true;
		} catch (IMapperException $e) {
			return false;
		}
	}

	public function getOrCreate(int $providerId, string $sub, bool $id4me = false): User {
		$userId = $this->idService->getId($providerId, $sub, $id4me);

		if (strlen($userId) > 64) {
			$userId = hash('sha256', $userId);
		}

		try {
			return $this->getUser($userId);
		} catch (IMapperException $e) {
			// just ignore and continue
		}

		$user = new User();
		$user->setUserId($userId);
		return $this->insert($user);
	}
}
