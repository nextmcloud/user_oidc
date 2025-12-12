<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2023, T-Systems International
 *
 * @author B. Rederlechner <bernd.rederlechner@t-Systems.com>
 *
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program. If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\UserOIDC\Service;

/**
 * Exception if the precondition of the config update method isn't met
 * @since 1.4.0
 */
class ProvisioningDeniedException extends \Exception {
	private $redirectUrl;

	/**
	 * Exception constructor including an option redirect url.
	 *
	 * @param string $message The error message. It will be not revealed to the
	 *                        the user (unless the hint is empty) and thus
	 *                        should be not translated.
	 * @param string $hint A useful message that is presented to the end
	 *                     user. It should be translated, but must not
	 *                     contain sensitive data.
	 * @param int $code Set default to 403 (Forbidden)
	 * @param \Exception|null $previous
	 */
	public function __construct(string $message, ?string $redirectUrl = null, int $code = 403, ?\Exception $previous = null) {
		parent::__construct($message, $code, $previous);
		$this->redirectUrl = $redirectUrl;
	}

	/**
	 * Read optional failure redirect if available
	 * @return string|null
	 */
	public function getRedirectUrl(): ?string {
		return $this->redirectUrl;
	}

	/**
	 * Include redirect in string serialisation.
	 *
	 * @return string
	 */
	public function __toString(): string {
		$redirect = $this->redirectUrl ?? '<no redirect>';
		return __CLASS__ . ": [{$this->code}]: {$this->message} ({$redirect})\n";
	}
}
