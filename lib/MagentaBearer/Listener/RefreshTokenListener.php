<?php
/**
 * @copyright Copyright (c) 2023 T-Systems International
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Store the refresh token in session to use it for
 * bearer self test.
 */

declare(strict_types=1);

namespace OCA\UserOIDC\MagentaBearer\Listener;

use OCA\UserOIDC\Event\TokenObtainedEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;

use OCP\ISession;

class RefreshTokenListener implements IEventListener {
	public const TBEARER_SESSION_ID = "telekom.refresh_token";

	public function __construct(ISession $session) {
		$this->session = $session;
	}

	/**
	 * Store the Telekom refresh token in session
	 * for use in self test
	 */
	public function handle(Event $event): void {
		if (!$event instanceof TokenObtainedEvent) {
			return;
		}

		$token = $event->getToken();
		$refreshToken = $token['refresh_token'] ?? null;
		if ($refreshToken !== null) {
			$this->session->set(self::TBEARER_SESSION_ID, $refreshToken);
		}
	}
}
