<?php
/*
 * @copyright Copyright (c) 2021 Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @license GNU AGPL version 3 or any later version
 */
declare(strict_types=1);

namespace OCA\UserOIDC\MagentaBearer;

use DateTime;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;

class TokenService {

	private LoggerInterface $logger;
	private ITimeFactory $timeFactory;

	// ✅ FIX: vorher dynamisch gesetzt
	private JWEDecrypter $jweDecrypter;
	private JWESerializerManager $encryptionSerializerManager;
	private JWSVerifier $jwsVerifier;
	private JWSSerializerManager $serializerManager;

	public function __construct(LoggerInterface $logger, ITimeFactory $timeFactory) {
		$this->logger = $logger;
		$this->timeFactory = $timeFactory;

		// Key encryption algorithms
		$keyEncryptionAlgorithmManager = new AlgorithmManager([
			new PBES2HS512A256KW(),
			new RSAOAEP256(),
			new ECDHESA256KW(),
		]);

		// Content encryption algorithms
		$contentEncryptionAlgorithmManager = new AlgorithmManager([
			new A256CBCHS512(),
		]);

		// Compression methods
		$compressionMethodManager = new CompressionMethodManager([
			new Deflate(),
		]);

		// Signature algorithms
		$signatureAlgorithmManager = new AlgorithmManager([
			new HS256(),
			new HS384(),
			new HS512(),
		]);

		$this->jweDecrypter = new JWEDecrypter(
			$keyEncryptionAlgorithmManager,
			$contentEncryptionAlgorithmManager,
			$compressionMethodManager
		);

		$this->encryptionSerializerManager = new JWESerializerManager([
			new JWECompactSerializer(),
		]);

		$this->jwsVerifier = new JWSVerifier($signatureAlgorithmManager);

		$this->serializerManager = new JWSSerializerManager([
			new JWSCompactSerializer(),
		]);
	}

	/**
	 * Implement JOSE decryption for SAM3 tokens
	 */
	public function decryptToken(string $rawToken, string $decryptKey): JWS {
		// web-token library does not like underscores in headers, so replace them with - (which is valid in JWT)
		$numSegments = substr_count($rawToken, '.') + 1;
		$this->logger->debug('Bearer access token(segments=' . $numSegments . ')=' . $rawToken);

		if ($numSegments > 3) {
			// trusted authenticator and myself share the client secret,
			// so use it for encrypted web tokens
			$clientSecret = new JWK([
				'kty' => 'oct',
				'k' => $decryptKey,
			]);

			$jwe = $this->encryptionSerializerManager->unserialize($rawToken);

			// We decrypt the token. This method does NOT check the header.
			if ($this->jweDecrypter->decryptUsingKey($jwe, $clientSecret, 0)) {
				return $this->serializerManager->unserialize($jwe->getPayload());
			}

			throw new InvalidTokenException('Unknown bearer encryption format');
		}

		return $this->serializerManager->unserialize($rawToken);
	}

	/**
	 * Get claims (even before verification to access e.g. aud standard field ...)
	 * Transform them in a format compatible with id_token representation.
	 */
	public function decode(JWS $decodedToken): object {
		$this->logger->debug('Telekom SAM3 access token: ' . $decodedToken->getPayload());
		$samContent = json_decode($decodedToken->getPayload(), false);

		$claimArray = $samContent->{'urn:telekom.com:idm:at:attributes'} ?? null;
		if (is_iterable($claimArray)) {
			foreach ($claimArray as $claimKeyValue) {
				if (isset($claimKeyValue->name, $claimKeyValue->value)) {
					$samContent->{'urn:telekom.com:' . $claimKeyValue->name} = $claimKeyValue->value;
				}
			}
		}
		unset($samContent->{'urn:telekom.com:idm:at:attributes'});

		$this->logger->debug('Adapted OpenID-like token; ' . json_encode($samContent));
		return $samContent;
	}

	public function verifySignature(JWS $decodedToken, string $signKey): void {
		$accessSecret = new JWK([
			'kty' => 'oct',
			'k' => $signKey,
		]);

		if (!$this->jwsVerifier->verifyWithKey($decodedToken, $accessSecret, 0)) {
			throw new SignatureException('Invalid Signature');
		}
	}

	/**
	 * @param object $claims decoded token payload
	 * @param string[] $audiences acceptable audiences
	 */
	public function verifyClaims(object $claims, array $audiences = [], int $leeway = 60): void {
		$timestamp = $this->timeFactory->getTime();

		if (isset($claims->nbf) && $claims->nbf > ($timestamp + $leeway)) {
			throw new InvalidTokenException(
				'Cannot handle token prior to ' . date(DateTime::ISO8601, (int)$claims->nbf)
			);
		}

		if (isset($claims->iat) && $claims->iat > ($timestamp + $leeway)) {
			throw new InvalidTokenException(
				'Cannot handle token prior to ' . date(DateTime::ISO8601, (int)$claims->iat)
			);
		}

		if (isset($claims->exp) && ($timestamp - $leeway) >= $claims->exp) {
			throw new InvalidTokenException('Expired token');
		}

		// aud kann String ODER Array sein -> normalisieren
		$tokenAud = [];
		if (isset($claims->aud)) {
			if (is_array($claims->aud)) {
				$tokenAud = $claims->aud;
			} elseif (is_string($claims->aud)) {
				$tokenAud = [$claims->aud];
			}
		}

		if (!empty($audiences) && empty(array_intersect($tokenAud, $audiences))) {
			throw new InvalidTokenException('No acceptable audience in token.');
		}
	}
}
