<?php
/*
 * @copyright Copyright (c) 2021 Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */
declare(strict_types=1);

namespace OCA\UserOIDC\MagentaBearer;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;

/**
 * Token service for handling Magenta/SAM3 bearer tokens (decrypt/verify/claims).
 */
class TokenService {

    /** @var LoggerInterface */
    private $logger;

    /** @var ITimeFactory */
    private $timeFactory;

    /** @var DiscoveryService|null */
    private $discoveryService;

    /** @var JWEDecrypter */
    private $jweDecrypter;

    /** @var JWESerializerManager */
    private $encryptionSerializerManager;

    /** @var JWSVerifier */
    private $jwsVerifier;

    /** @var JWSSerializerManager */
    private $serializerManager;

    public function __construct(LoggerInterface $logger, ITimeFactory $timeFactory, ?DiscoveryService $discoveryService = null) {
        $this->logger = $logger;
        $this->timeFactory = $timeFactory;
        $this->discoveryService = $discoveryService;

        // Key encryption algorithms manager
        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new PBES2HS512A256KW(),
            new RSAOAEP256(),
            new ECDHESA256KW(),
        ]);

        // Content encryption algorithm manager
        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A256CBCHS512(),
        ]);

        // Compression manager
        $compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);

        // Signature algorithms manager
        $signatureAlgorithmManager = new AlgorithmManager([
            new HS256(),
            new HS384(),
            new HS512(),
        ]);

        // JWE decrypter
        $this->jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        // JWESerializerManager
        $this->encryptionSerializerManager = new JWESerializerManager([
            new JWECompactSerializer(),
        ]);

        // JWS verifier
        $this->jwsVerifier = new JWSVerifier($signatureAlgorithmManager);

        // JWSSerializerManager
        $this->serializerManager = new JWSSerializerManager([
            new JWSCompactSerializer(),
        ]);
    }

    /**
     * Implement JOSE decryption for SAM3 tokens
     *
     * @param string $rawToken
     * @param string $decryptKey
     * @return JWS
     * @throws InvalidTokenException
     */
    public function decryptToken(string $rawToken, string $decryptKey) : JWS {
        $numSegments = substr_count($rawToken, '.') + 1;
        $this->logger->debug('Bearer access token(segments=' . $numSegments . ')=' . $rawToken);

        if ($numSegments > 3) {
            $clientSecret = new JWK([
                'kty' => 'oct',
                'k' => $decryptKey,
            ]);

            $jwe = $this->encryptionSerializerManager->unserialize($rawToken);

            if ($this->jweDecrypter->decryptUsingKey($jwe, $clientSecret, 0)) {
                return $this->serializerManager->unserialize($jwe->getPayload());
            }

            throw new InvalidTokenException('Unknown bearer encryption format');
        }

        return $this->serializerManager->unserialize($rawToken);
    }

    /**
     * Decode the token payload into an object and remap claims
     *
     * @param JWS $decodedToken
     * @return object
     */
    public function decode(JWS $decodedToken) : object {
        $this->logger->debug('Telekom SAM3 access token: ' . $decodedToken->getPayload());
        $samContent = json_decode($decodedToken->getPayload(), false);

        $claimArray = $samContent->{'urn:telekom.com:idm:at:attributes'} ?? null;
        if (is_array($claimArray)) {
            foreach ($claimArray as $claimKeyValue) {
                if (isset($claimKeyValue->name)) {
                    $samContent->{'urn:telekom.com:' . $claimKeyValue->name} = $claimKeyValue->value ?? null;
                }
            }
            unset($samContent->{'urn:telekom.com:idm:at:attributes'});
        }

        $this->logger->debug('Adapted OpenID-like token; ' . json_encode($samContent));
        return $samContent;
    }

    /**
     * Verify the JWS signature using the given symmetric key
     *
     * @param JWS $decodedToken
     * @param string $signKey
     * @return void
     * @throws SignatureException
     */
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
     * Verify standard claims (nbf/iat/exp/aud)
     *
     * @param object $claims
     * @param array<int,string> $audiences
     * @param int $leeway
     * @return void
     * @throws InvalidTokenException
     */
    public function verifyClaims(object $claims, array $audiences = [], int $leeway = 60): void {
        $timestamp = $this->timeFactory->getTime();

        if (isset($claims->nbf) && $claims->nbf > ($timestamp + $leeway)) {
            throw new InvalidTokenException(
                'Cannot handle token prior to ' . \date(\DATE_ATOM, (int)$claims->nbf)
            );
        }

        if (isset($claims->iat) && $claims->iat > ($timestamp + $leeway)) {
            throw new InvalidTokenException(
                'Cannot handle token prior to ' . \date(\DATE_ATOM, (int)$claims->iat)
            );
        }

        if (isset($claims->exp) && ($timestamp - $leeway) >= $claims->exp) {
            throw new InvalidTokenException('Expired token');
        }

        if (empty(array_intersect((array)($claims->aud ?? []), $audiences))) {
            throw new InvalidTokenException('No acceptable audience in token.');
        }
    }
}
