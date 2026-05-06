<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\UserOIDC\Event;

use OCP\EventDispatcher\Event;

/**
 * Event to allow custom account provisioning decisions based on OIDC token data.
 */
class UserAccountChangeEvent extends Event {
	private UserAccountChangeResult $result;

	public function __construct(
		private string $uid,
		private ?string $displayName,
		private ?string $mainEmail,
		private ?string $quota,
		private object $claims,
		bool $accessAllowed = false,
	) {
		parent::__construct();

		$this->result = new UserAccountChangeResult($accessAllowed, 'default');
	}

	public function getUid(): string {
		return $this->uid;
	}

	public function getDisplayName(): ?string {
		return $this->displayName;
	}

	public function getMainEmail(): ?string {
		return $this->mainEmail;
	}

	public function getQuota(): ?string {
		return $this->quota;
	}

	public function getClaims(): object {
		return $this->claims;
	}

	public function getResult(): UserAccountChangeResult {
		return $this->result;
	}

	public function setResult(bool $accessAllowed, string $reason = '', ?string $redirectUrl = null): void {
		$this->result = new UserAccountChangeResult($accessAllowed, $reason, $redirectUrl);
	}
}
