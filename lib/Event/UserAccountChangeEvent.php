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
	private $uid;
	private $displayname;
	private $mainEmail;
	private $quota;
	private $claims;
	private $result;


	public function __construct(string $uid, ?string $displayname, ?string $mainEmail, ?string $quota, object $claims, bool $accessAllowed = false) {
		parent::__construct();
		$this->uid = $uid;
		$this->displayname = $displayname;
		$this->mainEmail = $mainEmail;
		$this->quota = $quota;
		$this->claims = $claims;
		$this->result = new UserAccountChangeResult($accessAllowed, 'default');
	}

	/**
	 * @return get event username (uid)
	 */
	public function getUid(): string {
		return $this->uid;
	}

	/**
	 * @return get event displayname
	 */
	public function getDisplayName(): ?string {
		return $this->displayname;
	}

	/**
	 * @return get event main email
	 */
	public function getMainEmail(): ?string {
		return $this->mainEmail;
	}

	/**
	 * @return get event quota
	 */
	public function getQuota(): ?string {
		return $this->quota;
	}

	/**
	 * @return array the array of claim values associated with the event
	 */
	public function getClaims(): object {
		return $this->claims;
	}

	/**
	 * @return value for the logged in user attribute
	 */
	public function getResult(): UserAccountChangeResult {
		return $this->result;
	}

	public function setResult(bool $accessAllowed, string $reason = '', ?string $redirectUrl = null) : void {
		$this->result = new UserAccountChangeResult($accessAllowed, $reason, $redirectUrl);
	}
}
