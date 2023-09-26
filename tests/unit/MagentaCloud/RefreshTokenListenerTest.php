<?php
/**
 * @copyright Copyright (c) 2023 T-Systems International
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Test the bearer token self-test:
 * catching the refresh token, getting a bearer with it,
 * calling the bearer checkToken endpoint and display token details
 */


declare(strict_types=1);

use OCP\IRequest;
use OCP\IConfig;
use OCP\ISession;

use OCA\UserOIDC\AppInfo\Application;

use OCA\UserOIDC\MagentaBearer\Listener\RefreshTokenListener;
use OCA\UserOIDC\Db\Provider;
use OCA\UserOIDC\Service\ProviderService;

use OCA\UserOIDC\Event\TokenObtainedEvent;

use PHPUnit\Framework\TestCase;

class RefreshTokenListenerTest extends TestCase {
	private ProviderService $providerService;
	private IConfig $config;
	private ISession $session;

	public function setUp(): void {
		parent::setUp();
		$this->app = new \OCP\AppFramework\App(Application::APP_ID);
		$this->requestMock = $this->createMock(IRequest::class);

		$this->config = $this->createMock(IConfig::class);
		
		// usually, we need to pass the isSecure test be setting debug
		$this->config->expects($this->any())
					->method('getSystemValueBool')
					->with(self::equalTo('debug'), self::equalTo(false))
					->willReturn(true);

		$this->session = $this->createMock(ISession::class);
	}

	/**
	 * Test save existing token in session
	 */
	public function testTokenReceived(): void {
		$token = 'RT2:01234567890';
		$event = new TokenObtainedEvent(
			[ 'refresh_token' => $token],
			$this->createMock(Provider::class), null);
		$this->session->expects($this->once())
						->method('set')
						->with(RefreshTokenListener::TBEARER_SESSION_ID, $token);
		
		$listener = new RefreshTokenListener($this->session);
		$listener->handle($event);
	}

	/**
	 * Test lacking token
	 */
	public function testNoRefreshToken(): void {
		$event = new TokenObtainedEvent(
			[ 'other_token' => 'RT2:01234567890'],
		$this->createMock(Provider::class), null);
		$this->session->expects($this->never())
			->method('set');

		$listener = new RefreshTokenListener($this->session);
		$listener->handle($event);
	}
}
