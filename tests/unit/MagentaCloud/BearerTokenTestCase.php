<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\UserOIDC\BaseTest;

use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\MagentaBearer\TokenService;
use OCA\UserOIDC\Vendor\Jose\Component\Core\AlgorithmManager;
use OCA\UserOIDC\Vendor\Jose\Component\Core\JWK;
use OCA\UserOIDC\Vendor\Jose\Component\Core\Util\Base64UrlSafe;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Compression\CompressionMethodManager;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Compression\Deflate;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\JWEBuilder;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\Algorithm\HS256;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\JWS;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\JWSBuilder;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use OCP\AppFramework\App;
use PHPUnit\Framework\TestCase;

class BearerTokenTestCase extends TestCase {
	protected App $app;
	protected TokenService $tokenService;

	/** @var array<string, mixed> */
	private array $realExampleClaims = [];

	/** @return array<string, mixed> */
	public function getRealExampleClaims(): array {
		return $this->realExampleClaims;
	}

	public function getTestBearerSecret(): string {
		return Base64UrlSafe::encodeUnpadded('JQ17C99A-DAF8-4E27-FBW4-GV23B043C993');
	}

	public function setUp(): void {
		parent::setUp();

		$this->app = new App(Application::APP_ID);
		$this->tokenService = $this->app->getContainer()->get(TokenService::class);

		$now = time();

		$this->realExampleClaims = [
			'iss' => 'sts00.idm.ver.sul.t-online.de',
			'urn:telekom.com:idm:at:subjectType' => [
				'format' => 'urn:com:telekom:idm:1.0:nameid-format:anid',
				'realm' => 'ver.sul.t-online.de',
			],
			'acr' => 'urn:telekom:names:idm:THO:1.0:ac:classes:pwd',
			'sub' => '1200490100000000100XXXXX',
			'iat' => $now,
			'nbf' => $now,
			'exp' => $now + 7200,
			'urn:telekom.com:idm:at:authNStatements' => [
				'urn:telekom:names:idm:THO:1.0:ac:classes:pwd' => [
					'authenticatingAuthority' => null,
					'authNInstant' => $now,
				],
			],
			'aud' => ['http://auth.magentacloud.de'],
			'jti' => 'STS-1e22a06f-790c-40fb-ad1d-6de2ddcf2431',
			'urn:telekom.com:idm:at:attributes' => [
				[ 'name' => 'client_id',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '10TVL0SAM30000004901NEXTMAGENTACLOUDTEST'],
				[ 'name' => 'displayname',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => 'nmc01@ver.sul.t-online.de'],
				[ 'name' => 'email',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => 'nmc01@ver.sul.t-online.de'],
				[ 'name' => 'anid',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1200490100000000100XXXXX'],
				[ 'name' => 'd556',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'domt',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => 'ver.sul.t-online.de'],
				[ 'name' => 'f048',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1'],
				[ 'name' => 'f049',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1'],
				[ 'name' => 'f051',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'f460',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'f467',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'f468',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'f469',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'f471',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'f556',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1'],
				[ 'name' => 'f734',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'mainEmail',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => 'nmc01@ver.sul.t-online.de'],
				[ 'name' => 's556',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '0'],
				[ 'name' => 'usta',
					'nameFormat' => 'urn:com:telekom:idm:1.0:attrname-format:field',
					'value' => '1']
			],
			'urn:telekom.com:idm:at:version' => '1.0',
		];
	}

	protected function signToken(array $claims, string $signKey, bool $invalidate = false): JWS {
		$algorithmManager = new AlgorithmManager([
			new HS256(),
		]);

		$jwk = new JWK([
			'kty' => 'oct',
			'k' => $invalidate
				? Base64UrlSafe::encodeUnpadded('JQ17C99A-DAF8-4E27-FBW4-GV23B043C994')
				: $signKey,
		]);

		return (new JWSBuilder($algorithmManager))
			->create()
			->withPayload((string)json_encode($claims))
			->addSignature($jwk, ['alg' => 'HS256'])
			->build();
	}

	protected function setupSignedToken(array $claims, string $signKey): string {
		return (new JWSCompactSerializer())->serialize($this->signToken($claims, $signKey), 0);
	}

	protected function setupEncryptedToken(JWS $token, string $decryptKey): string {
		$keyEncryptionAlgorithmManager = new AlgorithmManager([
			new PBES2HS512A256KW(),
			new RSAOAEP256(),
			new ECDHESA256KW(),
		]);

		$contentEncryptionAlgorithmManager = new AlgorithmManager([
			new A256CBCHS512(),
		]);

		$compressionMethodManager = new CompressionMethodManager([
			new Deflate(),
		]);

		$jwk = new JWK([
			'kty' => 'oct',
			'k' => $decryptKey,
		]);

		$jwe = (new JWEBuilder(
			$keyEncryptionAlgorithmManager,
			$contentEncryptionAlgorithmManager,
			$compressionMethodManager,
		))
			->create()
			->withPayload((new JWSCompactSerializer())->serialize($token, 0))
			->withSharedProtectedHeader([
				'alg' => 'PBES2-HS512+A256KW',
				'enc' => 'A256CBC-HS512',
				'zip' => 'DEF',
			])
			->addRecipient($jwk)
			->build();

		return (new JWECompactSerializer())->serialize($jwe, 0);
	}

	protected function setupSignEncryptToken(array $claims, string $secret, bool $invalidate = false): string {
		return $this->setupEncryptedToken($this->signToken($claims, $secret, $invalidate), $secret);
	}
}
