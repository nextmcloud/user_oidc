<?php

declare(strict_types=1);

namespace OCA\UserOIDC\BaseTest;

use OCP\AppFramework\App;

use PHPUnit\Framework\TestCase;

use OCA\UserOIDC\AppInfo\Application;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;

use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * This test must be run with --stderr, e.g.
 * phpunit --stderr --bootstrap tests/bootstrap.php tests/unit/SlupReceiverTest.php
 */
class OpenidTokenTestCase extends TestCase {

	/** @var App */
	protected $app;

	/**
	 * Real world example claims content
	 */
	private $realExampleClaims;

	public function getProviderId() : int {
		return 4711;
	}


	public function getRealOidClaims() : array {
		return $this->realOidClaims;
	}

	public function getOidClientId() {
		return "USER_NC_OPENID_TEST";
	}

	public function getOidNonce() {
		return "CVMI8I3JZPALSL5DIM6I1PDP8SDSEN4K";
	}

	public function getOidClientSecret() {
		return \Base64Url\Base64Url::encode('JQ17C99A-DAF8-4E27-FBW4-GV23B043C993');
	}

	public function getOidServerKey() {
		return \Base64Url\Base64Url::encode('JQ17DAF8-C99A-4E27-FBW4-GV23B043C993');
	}

	public function getOidPrivateServerKey() {
		return [
			"p" => "9US9kD6Q8nicR1se1U_iRI9x1iK0__HF7E9yhqrza9DHldC2h7PLuR7y9bITAUtcBmVvqEQlVUXRZPMrNUpLFI9hTdZXAACRqYBYGHg7Mvyzq-2JXhEE5CFDy9wSCPunc8bRq4TsY0ocSXugXKGjx-t1uO3fkF1UgNgNMjdzSPM",
			"kty" => "RSA",
			"q" => "85auJF6W3c91EebGpjMX-g_U0fLBMgO2oxBsldus9x2diRd3wVvUnrTg5fQctODdr4if8dBCPDdLxBUKul4MXULC_nCkGkDjORdESb7j8amGnOvxnaVcQT6C5yHivAawa4R8NchR7n23VrQWO8fHhQBYUHTTy01G3A8D6dznCC8",
			"d" => "tP-lT4FJBKrhhBUk7J1fR0638jVjn46yIfSaB5l_JlqNItmRJtbz3QWopy4oDfvrY_ccZIYG9tLvJH-3LHtuEddwxFsL-9MSUx5qxWB4sKpKA6EpxWNR5EFnFKxR_B2P2yFYiRDdbBh8h9pNaOuNjZU5iitAGvSOfW4X5hyJyu9t9zsEX9O6stEtP3yK5sx-bt7osGDMIguFBMcPVHbYw_Pl7-aNPuQ4ioxVXa3JlO6tTcDrcyMy7d3CWuGACj3juEnO-1n8E_OSR9sMp1k_L7i-qQ3OnLCOx07HeTWklCvNxz7U9qLcQXGcfpdWmhWZt6MO3SIXV4f6Md0U836v0Q",
			"e" => "AQAB",
			"use" => "sig",
			"kid" => "0123456789",
			"qi" => "T3-NLCpVoITdS6PB9XYCsXsfhQSiE_4eTQnZf_Zya5hSd0xZDrrwNiXL8Dzy3YLjsZAFC0U6wAeC2wTBJ8c-6VxdP34J0sGj2I_TNhFFArksLy9ZaRbskCxKAPLipEFi8b1H2-aaRFRLs6BQJbfesQ5mcX2kB5AItAX3R6tcc0A",
			"dp" => "ExUtFor3phXiOt8JEBmuBh2PAtUidgNuncs0ouusEshkrvBVM0u23wlcZ-dZ-TDO0SSVQmdC7FaJSyxsQTItk0TwkijKDhL9Qk3dDNJV8MqehBLwLCRw1_sKllLiCFbkGWrvp0OpTLRYbRM0T-C3qHdWanP_f_DzAS9OH4kW7Cc",
			"alg" => "RS256",
			"dq" => "xr3XAWeHkhw0uVFgHLQtSOJn0pBM3qC2_95jqfVc7xZjtTnHhKSHGqIbqKL-VPnvBcvkK-iuUfEPyUEdyqb3UZQqAm0nByCQA8Ge_shXtJGLejbroKMNXVJCfZBhLOYMRP0IVt1FM9-wmXY_ebDrcfGxHJvlPcekG-HIYKPSgBM",
			"n" => "6WCdDo8KuksEFaFlzvmsaoYhfOoMt5XgnX98dx-F1OUz53SG0lQlFt-xkwra5B4GZ-13lki0qCa2CjA1aLa9kEvDdYhz_0Uc5qOy5haDj8Jn547s6gFyaLzJ0RN5i5eKeDMHcjeEC0_NjiB2UNUFJJ61b2nXIlUvp_vBfKCv4A-8C3mLSbCKJQhX84QRDgt_Abz0MXj_ga72Ka2cwVLo4OFQAK5m57Qfu9ZvseMcgoinyhIQ18b98SkWinn3DM0W1KXLkWLk0S3XEMxLV1M7-9RLo4fgEGOpX1xmmM6KbsC5SxXvRUO7tjU-o35fcewDwXYHnRbxqhRkEFfWb7b8nQ"
		];
	}


	public function getOidPublicServerKey() {
		return \OCA\UserOIDC\Vendor\Firebase\JWT\JWK::parseKeySet([ "keys" => [[
			"kty" => "RSA",
			"e" => "AQAB",
			"use" => "sig",
			"kid" => "0123456789",
			"alg" => "RS256",
			"n" => "6WCdDo8KuksEFaFlzvmsaoYhfOoMt5XgnX98dx-F1OUz53SG0lQlFt-xkwra5B4GZ-13lki0qCa2CjA1aLa9kEvDdYhz_0Uc5qOy5haDj8Jn547s6gFyaLzJ0RN5i5eKeDMHcjeEC0_NjiB2UNUFJJ61b2nXIlUvp_vBfKCv4A-8C3mLSbCKJQhX84QRDgt_Abz0MXj_ga72Ka2cwVLo4OFQAK5m57Qfu9ZvseMcgoinyhIQ18b98SkWinn3DM0W1KXLkWLk0S3XEMxLV1M7-9RLo4fgEGOpX1xmmM6KbsC5SxXvRUO7tjU-o35fcewDwXYHnRbxqhRkEFfWb7b8nQ"
		]]]);
	}

	public function getOidTestCode() {
		return "66844608";
	}

	public function getOidTestState() {
		return "4VSL5T274MJEMLZI1810HUFDA07CEPXZ";
	}

	public function setUp(): void {
		parent::setUp();

		$this->app = new App(Application::APP_ID);
		$this->realOidClaims = array(
			"sub" => "jgyros",
			"urn:custom.com:displayname" => "Jonny G",
			"urn:custom.com:email" => "jonny.gyros@x.y",
			"urn:custom.com:mainEmail" => "jonny.gyuris@x.y.de",
			"iss" => "https:\/\/accounts.login00.custom.de",
			"urn:custom.com:feat1" => "0",
			"urn:custom.com:uid" => "081500000001234",
			"urn:custom.com:feat2" => "1",
			"urn:custom.com:ext2" => "0",
			"urn:custom.com:feat3" => "1",
			"acr" => "urn:custom:names:idm:THO:1.0:ac:classes:passid:00",
			"urn:custom.com:feat4" => "0",
			"urn:custom.com:ext4" => "0",
			"auth_time" => time(),
			"exp" => time() + 7200,
			'iat' => time(),
			"urn:custom.com:session_token" => "ad0fff71-e013-11ec-9e17-39677d2c891c",
			"nonce" => "CVMI8I3JZPALSL5DIM6I1PDP8SDSEN4K",
			"aud" => array("USER_NC_OPENID_TEST") );
	}
		
	protected function createSignToken(array $claims) : string {
		// The algorithm manager with the HS256 algorithm.
		$algorithmManager = new AlgorithmManager([
			new RS256(),
		]);

		// use a different key for an invalid signature
		$jwk = new JWK($this->getOidPrivateServerKey());
		$jwsBuilder = new JWSBuilder($algorithmManager);
		$jws = $jwsBuilder->create()                               // We want to create a new JWS
							->withPayload(json_encode($claims))                   // We set the payload
							->addSignature($jwk, ['alg' => 'RS256', "kid" => "0123456789"]) // We add a signature with a simple protected header
							->build();

		$serializer = new CompactSerializer();
		return $serializer->serialize($jws, 0);
	}
}
