<?php

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

declare(strict_types=1);

use OCA\UserOIDC\BaseTest\BearerTokenTestCase;
use OCA\UserOIDC\MagentaBearer\InvalidTokenException;
use OCA\UserOIDC\MagentaBearer\SignatureException;

class SamBearerTokenTest extends BearerTokenTestCase {

	public function testValidSignature(): void {
		$this->expectNotToPerformAssertions();

		$testtoken = $this->setupSignedToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$bearerToken = $this->tokenService->decryptToken($testtoken, $this->getTestBearerSecret());

		$this->tokenService->verifySignature($bearerToken, $this->getTestBearerSecret());
		$claims = $this->tokenService->decode($bearerToken);
		$this->tokenService->verifyClaims($claims, ['http://auth.magentacloud.de']);
	}

	public function testInvalidSignature(): void {
		$this->expectException(SignatureException::class);

		$bearerToken = $this->signToken(
			$this->getRealExampleClaims(),
			$this->getTestBearerSecret(),
			true,
		);

		$this->tokenService->verifySignature($bearerToken, $this->getTestBearerSecret());
	}

	public function testEncryptedValidSignature(): void {
		$this->expectNotToPerformAssertions();

		$testtoken = $this->setupSignEncryptToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$bearerToken = $this->tokenService->decryptToken($testtoken, $this->getTestBearerSecret());

		$this->tokenService->verifySignature($bearerToken, $this->getTestBearerSecret());
		$claims = $this->tokenService->decode($bearerToken);
		$this->tokenService->verifyClaims($claims, ['http://auth.magentacloud.de']);
	}

	public function testEncryptedInvalidEncryption(): void {
		$this->expectException(InvalidTokenException::class);

		$testtoken = $this->setupSignEncryptToken($this->getRealExampleClaims(), $this->getTestBearerSecret());
		$invalidEncryption = mb_substr($testtoken, 0, -1);

		$bearerToken = $this->tokenService->decryptToken($invalidEncryption, $this->getTestBearerSecret());
		$this->tokenService->verifySignature($bearerToken, $this->getTestBearerSecret());
		$claims = $this->tokenService->decode($bearerToken);
		$this->tokenService->verifyClaims($claims, ['http://auth.magentacloud.de']);
	}
}
