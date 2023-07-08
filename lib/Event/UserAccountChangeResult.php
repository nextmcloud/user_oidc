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

/**
 * Event to provide custom mapping logic based on the OIDC token data
 * In order to avoid further processing the event propagation should be stopped
 * in the listener after processing as the value might get overwritten afterwards
 * by other listeners through $event->stopPropagation();
 */
class UserAccountChangeResult {

    /** @var bool */
    private $accessAllowed;
    /** @var string */
    private $reason;
    /** @var string */
    private $redirectUrl;

	public function __construct(bool $accessAllowed, string $reason = '', ?string $redirectUrl = null) {
		$this->accessAllowed = $accessAllowed;
        $this->redirectUrl = $redirectUrl;
        $this->reason = $reason;
	}

	/**
	 * @return value for the logged in user attribute
	 */
	public function isAccessAllowed(): bool {
		return $this->accessAllowed;
	}

	public function setAccessAllowed(bool $accessAllowed): void {
		$this->accessAllowed = $accessAllowed;
	}

	/**
	 * @return get optional alternate redirect address
	 */
	public function getRedirectUrl(): ?string {
		return $this->redirectUrl;
	}

	/**
	 * @return set optional alternate redirect address
	 */
	public function setRedirectUrl(?string $redirectUrl): void {
		$this->redirectUrl = $redirectUrl;
	}

	/**
	 * @return get decision reason
	 */
	public function getReason(): string {
		return $this->reason;
	}

	/**
	 * @return set decision reason
	 */
	public function setReason(string $reason): void {
		$this->reason = $reason;
    }
}
