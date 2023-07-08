<?php
/*
 * @copyright Copyright (c) 2021 Julius Härtl <jus@bitgrid.net>
 *
 * @author Julius Härtl <jus@bitgrid.net>
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

namespace OCA\UserOIDC\Event;

use OCP\EventDispatcher\Event;

use OCA\UserOIDC\Event\UserAccountChangeResult;

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
