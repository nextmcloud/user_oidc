<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace OCA\UserOIDC\MagentaBearer;

use OCA\UserOIDC\Vendor\Jose\Component\Core\AlgorithmManager;
use OCA\UserOIDC\Vendor\Jose\Component\Core\JWK;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Compression\CompressionMethodManager;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Compression\Deflate;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\JWEDecrypter;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use OCA\UserOIDC\Vendor\Jose\Component\Encryption\Serializer\JWESerializerManager;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\Algorithm\HS256;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\Algorithm\HS384;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\Algorithm\HS512;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\JWS;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\JWSVerifier;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use OCA\UserOIDC\Vendor\Jose\Component\Signature\Serializer\JWSSerializerManager;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;

class TokenService {
	private JWEDecrypter $jweDecrypter;
	private JWESerializerManager $encryptionSerializerManager;
	private JWSVerifier $jwsVerifier;
	private JWSSerializerManager $serializerManager;

	public function __construct(
		private LoggerInterface $logger,
		private ITimeFactory $timeFactory,
	) {
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

		$signatureAlgorithmManager = new AlgorithmManager([
			new HS256(),
			new HS384(),
			new HS512(),
		]);

		$this->jweDecrypter = new JWEDecrypter(
			$keyEncryptionAlgorithmManager,
			$contentEncryptionAlgorithmManager,
			$compressionMethodManager,
		);

		$this->encryptionSerializerManager = new JWESerializerManager([
			new JWECompactSerializer(),
		]);

		$this->jwsVerifier = new JWSVerifier($signatureAlgorithmManager);

		$this->serializerManager = new JWSSerializerManager([
			new JWSCompactSerializer(),
		]);
	}

	public function decryptToken(string $rawToken, string $decryptKey): JWS {
		$numSegments = substr_count($rawToken, '.') + 1;
		$this->logger->debug('Bearer access token received', [
			'segments' => $numSegments,
		]);

		$key = new JWK([
			'kty' => 'oct',
			'k' => $decryptKey,
		]);

		if ($numSegments > 3) {
			try {
				$jwe = $this->encryptionSerializerManager->unserialize($rawToken);
			} catch (\InvalidArgumentException $e) {
				throw new InvalidTokenException('Invalid encrypted bearer token', 0, $e);
			}

			if (!$this->jweDecrypter->decryptUsingKey($jwe, $key, 0)) {
				throw new InvalidTokenException('Unknown bearer encryption format');
			}

			$payload = $jwe->getPayload();
			if ($payload === null || $payload === '') {
				throw new InvalidTokenException('Empty decrypted bearer token payload');
			}

			return $this->serializerManager->unserialize($payload);
		}

		try {
			return $this->serializerManager->unserialize($rawToken);
		} catch (\InvalidArgumentException $e) {
			throw new InvalidTokenException('Invalid bearer token', 0, $e);
		}
	}

	public function decode(JWS $decodedToken): object {
		$payload = $decodedToken->getPayload();
		if ($payload === null || $payload === '') {
			throw new InvalidTokenException('Empty bearer token payload');
		}

		$samContent = json_decode($payload, false);
		if (!is_object($samContent)) {
			throw new InvalidTokenException('Invalid bearer token JSON payload');
		}

		$attributeName = 'urn:telekom.com:idm:at:attributes';
		if (isset($samContent->{$attributeName}) && is_iterable($samContent->{$attributeName})) {
			foreach ($samContent->{$attributeName} as $claimKeyValue) {
				if (isset($claimKeyValue->name, $claimKeyValue->value)) {
					$samContent->{'urn:telekom.com:' . $claimKeyValue->name} = $claimKeyValue->value;
				}
			}

			unset($samContent->{$attributeName});
		}

		$this->logger->debug('Adapted OpenID-like Telekom SAM3 access token');

		return $samContent;
	}

	public function verifySignature(JWS $decodedToken, string $signKey): void {
		$key = new JWK([
			'kty' => 'oct',
			'k' => $signKey,
		]);

		if (!$this->jwsVerifier->verifyWithKey($decodedToken, $key, 0)) {
			throw new SignatureException('Invalid signature');
		}
	}

	public function verifyClaims(object $claims, array $audiences = [], int $leeway = 60): void {
		$timestamp = $this->timeFactory->getTime();

		if (isset($claims->nbf) && is_numeric($claims->nbf) && (int)$claims->nbf > ($timestamp + $leeway)) {
			throw new InvalidTokenException(
				'Cannot handle token prior to ' . date(\DateTimeInterface::ATOM, (int)$claims->nbf)
			);
		}

		if (isset($claims->iat) && is_numeric($claims->iat) && (int)$claims->iat > ($timestamp + $leeway)) {
			throw new InvalidTokenException(
				'Cannot handle token prior to ' . date(\DateTimeInterface::ATOM, (int)$claims->iat)
			);
		}

		if (isset($claims->exp) && is_numeric($claims->exp) && ($timestamp - $leeway) >= (int)$claims->exp) {
			throw new InvalidTokenException('Expired token');
		}

		if ($audiences !== []) {
			$tokenAudiences = $claims->aud ?? [];
			if (is_string($tokenAudiences)) {
				$tokenAudiences = [$tokenAudiences];
			}

			if (!is_array($tokenAudiences) || array_intersect($tokenAudiences, $audiences) === []) {
				throw new InvalidTokenException('No acceptable audience in token.');
			}
		}
	}
}
