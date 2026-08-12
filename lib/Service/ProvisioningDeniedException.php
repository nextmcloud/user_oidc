<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\UserOIDC\Service;

class ProvisioningDeniedException extends \Exception {
	public function __construct(
		string $message,
		private ?string $redirectUrl = null,
		int $code = 403,
		?\Throwable $previous = null,
	) {
		parent::__construct($message, $code, $previous);
	}

	public function getRedirectUrl(): ?string {
		return $this->redirectUrl;
	}

	public function __toString(): string {
		$redirect = $this->redirectUrl ?? '<no redirect>';

		return self::class . ": [{$this->code}]: {$this->message} ({$redirect})\n";
	}
}
