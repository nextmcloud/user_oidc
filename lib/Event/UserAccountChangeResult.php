<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\UserOIDC\Event;

/**
 * Represents the result of an account change event decision.
 */
class UserAccountChangeResult {
	public function __construct(
		private bool $accessAllowed,
		private string $reason = '',
		private ?string $redirectUrl = null,
	) {
	}

	public function isAccessAllowed(): bool {
		return $this->accessAllowed;
	}

	public function setAccessAllowed(bool $accessAllowed): void {
		$this->accessAllowed = $accessAllowed;
	}

	public function getReason(): string {
		return $this->reason;
	}

	public function setReason(string $reason): void {
		$this->reason = $reason;
	}

	public function getRedirectUrl(): ?string {
		return $this->redirectUrl;
	}

	public function setRedirectUrl(?string $redirectUrl): void {
		$this->redirectUrl = $redirectUrl;
	}
}
