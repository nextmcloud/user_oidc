<?php
namespace OCA\UserOIDC\Vendor\Id4me\RP\Model\JWK;

use OCA\UserOIDC\Vendor\phpseclib\Crypt\RSA;
use OCA\UserOIDC\Vendor\phpseclib\Math\BigInteger;
use OCA\UserOIDC\Vendor\Id4me\RP\Helper\Base64UrlHelper;

/**
 * Class representing a RSA security public key, decoded from JWK representation
 *
 * @package OCA\UserOIDC\Vendor\Id4me\RP\Model\JWK
 */
class JWKRSA extends JWK
{
    /**
     * @var object
     */
    private $publickey;

    /**
     * Creates new RSA key representation from jwk
     *
     * @param array $jwk
     */
    public function __construct(array $jwk)
    {
        if (! isset($jwk['n']) || ! isset($jwk['e'])) {
            return false;
        }

        $crypt = new RSA();

        $n = new BigInteger(Base64UrlHelper::base64urlDecode($jwk['n']), 256);
        $e = new BigInteger(Base64UrlHelper::base64urlDecode($jwk['e']), 256);

        $crypt->loadKey(['e' => $e, 'n' => $n]);
        $pem_string = $crypt->getPublicKey();

        $this->publickey = openssl_pkey_get_public($pem_string);
    }

    /**
     * {@inheritDoc}
     * @see \OCA\UserOIDC\Vendor\Id4me\RP\Model\JWK\JWK::getKey()
     */
    public function getHandle()
    {
        return $this->publickey;
    }
}
