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
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\Http\Client\IClientService;

use OCA\UserOIDC\Db\ProviderMapper;


use OCA\UserOIDC\Controller\BearerSelfTestController;


use PHPUnit\Framework\TestCase;

class BearerSelfTestTest extends TestCase {

	/**
	 * @var ProviderService
	 */
	private $providerService;

	/**
	 * @var IConfig;
	 */
	private $config;

	public function setUp(): void {
		parent::setUp();
		$this->app = new \OCP\AppFramework\App(Application::APP_ID);
		$this->request = $this->createMock(IRequest::class);

		$this->config = $this->createMock(IConfig::class);
		$this->session = $this->createMock(ISession::class);
		$this->httpclient = $this->createMock(IClientService::class);
		$this->providerMapper = $this->createMock(ProviderMapper::class);

		$this->controller = new BearerSelfTestController(
			$this->httpclient,
			$this->config,
			$this->providerMapper,
			$this->session,
			$this->request
		);
	}

	public function testTokenFromSessionInsecure() {
		$this->config->expects($this->any())
					->method('getSystemValueBool')
					->with(self::equalTo('debug'), self::equalTo(false))
					->willReturn(false);
		$this->request->expects($this->any())
					->method('getServerProtocol')
					->willReturn('http');
		$this->session->expects($this->never())
					->method('get');
		$this->providerMapper->expects($this->never())
					->method('findProviderByIdentifier');
		$this->httpclient->expects($this->never())
					->method('newClient');

		$response = $this->controller->tokenFromSession();
		$this->assertInstanceOf(TemplateResponse::class, $response);
		$this->assertEquals(strval(Http::STATUS_BAD_REQUEST), $response->getTemplateName());
	}
}
