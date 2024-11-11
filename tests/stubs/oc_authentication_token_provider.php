<?php

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\Authentication\Token {
	interface IToken extends \JsonSerializable {
		public function getId(): int;

		public function getUid(): string;
	}

	interface IProvider {
		public function getToken(string $tokenId): IToken;

		public function invalidateTokenById(string $uid, int $id);

		public function getTokenById(int $tokenId): IToken;
	}
}
