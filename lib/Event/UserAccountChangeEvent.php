<?php
/*
 * @copyright Copyright (c) 2023 T-Systems International
 *
 * @author B. Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 */

declare(strict_types=1);

namespace OCA\UserOIDC\Event;

use OCP\EventDispatcher\Event;

/**
 * Event to provide custom mapping logic based on the OIDC token data
 * In order to avoid further processing the event propagation should be stopped
 * in the listener after processing as the value might get overwritten afterwards
 * by other listeners through $event->stopPropagation();
 */
class UserAccountChangeEvent extends Event {

	/** @var string */
	private $uid;

	/** @var string|null */
	private $displayname;

	/** @var string|null */
	private $mainEmail;

	/** @var string|null */
	private $quota;

	/** @var object */
	private $claims;

	/** @var UserAccountChangeResult */
	private $result;

	public function __construct(
		string $uid,
		?string $displayname,
		?string $mainEmail,
		?string $quota,
		object $claims,
		bool $accessAllowed = false
	) {
		parent::__construct();
		$this->uid = $uid;
		$this->displayname = $displayname;
		$this->mainEmail = $mainEmail;
		$this->quota = $quota;
		$this->claims = $claims;
		$this->result = new UserAccountChangeResult($accessAllowed, 'default');
	}

	/**
	 * Get the user ID (UID) associated with the event.
	 *
	 * @return string
	 */
	public function getUid(): string {
		return $this->uid;
	}

	/**
	 * Get the display name for the account.
	 *
	 * @return string|null
	 */
	public function getDisplayName(): ?string {
		return $this->displayname;
	}

	/**
	 * Get the primary email address.
	 *
	 * @return string|null
	 */
	public function getMainEmail(): ?string {
		return $this->mainEmail;
	}

	/**
	 * Get the quota assigned to the account.
	 *
	 * @return string|null
	 */
	public function getQuota(): ?string {
		return $this->quota;
	}

	/**
	 * Get the OIDC claims associated with the event.
	 *
	 * @return object
	 */
	public function getClaims(): object {
		return $this->claims;
	}

	/**
	 * Get the current result object.
	 *
	 * @return UserAccountChangeResult
	 */
	public function getResult(): UserAccountChangeResult {
		return $this->result;
	}

	/**
	 * Replace the result object with a new one.
	 *
	 * @param bool $accessAllowed Whether access should be allowed
	 * @param string $reason Optional reason for the decision
	 * @param string|null $redirectUrl Optional redirect URL
	 * @return void
	 */
	public function setResult(bool $accessAllowed, string $reason = '', ?string $redirectUrl = null): void {
		$this->result = new UserAccountChangeResult($accessAllowed, $reason, $redirectUrl);
	}
}
