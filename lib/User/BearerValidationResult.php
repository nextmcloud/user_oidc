<?php

declare(strict_types=1);

namespace OCA\UserOIDC\User;

final class BearerValidationResult {
	public function __construct(
		public readonly string $userId,
		public readonly object|array $payload,
	) {
	}
}