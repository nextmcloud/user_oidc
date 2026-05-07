<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

use OC\AppFramework\Bootstrap\Coordinator;
use OC\Authentication\Token\IProvider;
use OC\Security\Crypto;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\BaseTest\OpenidTokenTestCase;
use OCA\UserOIDC\Controller\LoginController;
use OCA\UserOIDC\Db\Provider;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\SessionMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Event\AttributeMappedEvent;
use OCA\UserOIDC\Event\UserAccountChangeEvent;
use OCA\UserOIDC\Helper\HttpClientHelper;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\LdapService;
use OCA\UserOIDC\Service\LocalIdService;
use OCA\UserOIDC\Service\OIDCService;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\ProvisioningEventService;
use OCA\UserOIDC\Service\SettingsService;
use OCA\UserOIDC\Service\TokenService;
use OCP\Accounts\IAccountManager;
use OCP\AppFramework\App;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Http\Client\IClientService;
use OCP\IAppConfig;
use OCP\IAvatarManager;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Security\ICrypto;
use OCP\Security\ISecureRandom;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

class ProvisioningEventServiceTest extends OpenidTokenTestCase {
	protected App $app;
	private IConfig&MockObject $config;
	private IAppConfig&MockObject $appConfig;
	private Crypto&MockObject $crypto;
	private IRequest&MockObject $request;
	private ProviderMapper&MockObject $providerMapper;
	private ProviderService&MockObject $providerService;
	private Provider $provider;
	private LocalIdService&MockObject $localIdService;
	private UserMapper&MockObject $userMapper;
	private DiscoveryService&MockObject $discoveryService;
	private ISession&MockObject $session;
	private SessionMapper&MockObject $sessionMapper;
	private HttpClientHelper&MockObject $httpClientHelper;
	private IUserSession&MockObject $usersession;
	private IUserManager&MockObject $usermanager;
	private IGroupManager&MockObject $groupmanager;
	private IEventDispatcher $dispatcher;
	private ProvisioningEventService $provisioningService;
	private LoginController $loginController;
	private IUser&MockObject $user;
	private IFactory $l10nFactory;
	private SettingsService&MockObject $settingsService;
	private TokenService $tokenService;
	private OIDCService $oidcService;
	private ITimeFactory&MockObject $timeFactory;
	private mixed $registrationContext;
	private mixed $attributeListener = null;
	private mixed $accountListener = null;
	private array $token;

	protected function getConfigSetup(): MockObject {
		$config = $this->createMock(IConfig::class);

		$config->expects($this->any())
			->method('getSystemValue')
			->with($this->logicalOr($this->equalTo('user_oidc'), $this->equalTo('secret')))
			->willReturnCallback(static function (string $key, mixed $default = null): mixed {
				if ($key === 'user_oidc') {
					return [
						'auto_provisioning' => true,
						'auto_provision' => true,
						'soft_auto_provision' => true,
						'login_validation_audience_check' => false,
						'login_validation_azp_check' => false,
					];
				}

				if ($key === 'secret') {
					return 'Streng_geheim';
				}

				return $default;
			});

		$config->expects($this->any())
			->method('getSystemValueString')
			->willReturnCallback(static function (string $key, string $default = ''): string {
				if ($key === 'version') {
					return '32.0.0';
				}

				return $default;
			});

		$config->expects($this->any())
			->method('setUserValue');

		return $config;
	}

	protected function getOidSessionSetup(): MockObject {
		$session = $this->createMock(ISession::class);

		$session->expects($this->any())
			->method('get')
			->willReturnCallback(function (string $key): mixed {
				$state = $this->getOidTestState();
				$suffix = '-' . $state;

				$values = [
					'oidc.state' . $suffix => $state,
					'oidc.login.providerid' . $suffix => $this->getProviderId(),
					'oidc.providerid' . $suffix => $this->getProviderId(),
					'oidc.nonce' . $suffix => $this->getOidNonce(),
					'oidc.redirect' . $suffix => 'https://welcome.to.magenta',
					'oidc.timestamp' . $suffix => time(),
					'oidc.code_verifier' . $suffix => 'test-code-verifier',
				];

				return $values[$key] ?? null;
			});

		$session->expects($this->any())
			->method('exists')
			->willReturnCallback(function (string $key): bool {
				$state = $this->getOidTestState();
				$suffix = '-' . $state;

				return in_array($key, [
					'oidc.state' . $suffix,
					'oidc.login.providerid' . $suffix,
					'oidc.providerid' . $suffix,
					'oidc.nonce' . $suffix,
					'oidc.redirect' . $suffix,
					'oidc.timestamp' . $suffix,
					'oidc.code_verifier' . $suffix,
				], true);
			});

		$session->expects($this->any())
			->method('set');

		$session->expects($this->any())
			->method('remove');

		$session->expects($this->any())
			->method('getId')
			->willReturn('test-session-id');

		return $session;
	}

	protected function getProviderSetup(): Provider {
		$provider = new Provider();
		$provider->setId($this->getProviderId());
		$provider->setIdentifier('telekom');
		$provider->setClientId($this->getOidClientId());
		$provider->setClientSecret($this->crypto->encrypt($this->getOidClientSecret()));
		$provider->setScope('openid');
		$provider->setDiscoveryEndpoint('https://accounts.login00.custom.de/.well-known/openid-configuration');

		$this->providerMapper->expects($this->any())
			->method('getProvider')
			->with($this->equalTo($this->getProviderId()))
			->willReturn($provider);

		return $provider;
	}

	protected function getProviderServiceSetup(): MockObject {
		$providerService = $this->getMockBuilder(ProviderService::class)
			->setConstructorArgs([$this->appConfig, $this->providerMapper])
			->getMock();

		$providerService->expects($this->any())
			->method('getSetting')
			->willReturnCallback(static function (int $providerId, string $key, string $default = ''): string {
				$values = [
					ProviderService::SETTING_MAPPING_UID => 'sub',
					ProviderService::SETTING_MAPPING_DISPLAYNAME => 'urn:custom.com:displayname',
					ProviderService::SETTING_MAPPING_QUOTA => 'urn:custom.com:f556',
					ProviderService::SETTING_MAPPING_EMAIL => 'urn:custom.com:mainEmail',
					ProviderService::SETTING_MAPPING_GROUPS => '',
					ProviderService::SETTING_RESTRICT_LOGIN_TO_GROUPS => '0',
					ProviderService::SETTING_RESOLVE_NESTED_AND_FALLBACK_CLAIMS_MAPPING => '0',
					ProviderService::SETTING_EXTRA_CLAIMS => '',
				];

				return $values[$key] ?? $default;
			});

		return $providerService;
	}

	protected function getUserManagerSetup(): MockObject {
		$userManager = $this->getMockForAbstractClass(IUserManager::class);

		$this->user = $this->getMockForAbstractClass(IUser::class);
		$this->user->expects($this->any())
			->method('canChangeAvatar')
			->willReturn(false);
		$this->user->expects($this->any())
			->method('getUID')
			->willReturn('jgyros');

		return $userManager;
	}

	public function setUp(): void {
		parent::setUp();

		$this->app = new App(Application::APP_ID);
		$this->config = $this->getConfigSetup();
		$this->appConfig = $this->createMock(IAppConfig::class);

		$this->appConfig->expects($this->any())
			->method('getValueString')
			->willReturn('0');

		$this->appConfig->expects($this->any())
			->method('getValueBool')
			->willReturn(false);

		$this->crypto = $this->getMockBuilder(Crypto::class)
			->setConstructorArgs([$this->config])
			->getMock();

		$this->request = $this->getMockForAbstractClass(IRequest::class);
		$this->request->expects($this->any())
			->method('getServerProtocol')
			->willReturn('https');

		$this->providerMapper = $this->getMockBuilder(ProviderMapper::class)
			->setConstructorArgs([$this->getMockForAbstractClass(IDBConnection::class)])
			->getMock();

		$this->provider = $this->getProviderSetup();
		$this->providerService = $this->getProviderServiceSetup();

		$this->localIdService = $this->getMockBuilder(LocalIdService::class)
			->setConstructorArgs([
				$this->providerService,
				$this->providerMapper,
			])
			->getMock();

		$this->userMapper = $this->getMockBuilder(UserMapper::class)
			->setConstructorArgs([
				$this->getMockForAbstractClass(IDBConnection::class),
				$this->localIdService,
				$this->config,
			])
			->getMock();

		$this->token = [
			'id_token' => $this->createSignToken($this->getRealOidClaims()),
		];

		$this->httpClientHelper = $this->getMockBuilder(HttpClientHelper::class)
			->disableOriginalConstructor()
			->getMock();

		$this->httpClientHelper->expects($this->any())
			->method('post')
			->willReturn(json_encode($this->token, JSON_THROW_ON_ERROR));

		$this->discoveryService = $this->getMockBuilder(DiscoveryService::class)
			->setConstructorArgs([
				$this->app->getContainer()->get(LoggerInterface::class),
				$this->httpClientHelper,
				$this->providerService,
				$this->app->getContainer()->get(IConfig::class),
				$this->app->getContainer()->get(ITimeFactory::class),
				$this->app->getContainer()->get(ICacheFactory::class),
			])
			->getMock();

		$this->discoveryService->expects($this->any())
			->method('obtainDiscovery')
			->willReturn([
				'token_endpoint' => 'https://whatever.to.discover/token',
				'authorization_endpoint' => 'https://whatever.to.discover/auth',
				'issuer' => 'https://accounts.login00.custom.de',
			]);

		$this->discoveryService->expects($this->any())
			->method('obtainJWK')
			->willReturn($this->getOidPublicServerKey());

		$this->session = $this->getOidSessionSetup();

		$this->sessionMapper = $this->getMockBuilder(SessionMapper::class)
			->setConstructorArgs([
				$this->createMock(IDBConnection::class),
				$this->app->getContainer()->get(ICrypto::class),
			])
			->getMock();

		$this->sessionMapper->expects($this->any())
			->method('createOrUpdateSession');

		$this->usersession = $this->getMockBuilder(IUserSession::class)
			->disableOriginalConstructor()
			->onlyMethods([
				'setUser',
				'login',
				'logout',
				'getUser',
				'isLoggedIn',
				'getImpersonatingUserID',
				'setImpersonatingUserID',
				'setVolatileActiveUser',
			])
			->addMethods([
				'completeLogin',
				'createSessionToken',
				'createRememberMeToken',
			])
			->getMock();

		$this->usersession->expects($this->any())
			->method('isLoggedIn')
			->willReturn(false);

		$this->usermanager = $this->getUserManagerSetup();
		$this->groupmanager = $this->getMockForAbstractClass(IGroupManager::class);
		$this->dispatcher = $this->app->getContainer()->get(IEventDispatcher::class);
		$this->l10nFactory = $this->app->getContainer()->get(IFactory::class);

		$this->provisioningService = new ProvisioningEventService(
			$this->app->getContainer()->get(LocalIdService::class),
			$this->providerService,
			$this->userMapper,
			$this->usermanager,
			$this->groupmanager,
			$this->dispatcher,
			$this->app->getContainer()->get(LoggerInterface::class),
			$this->app->getContainer()->get(IAccountManager::class),
			$this->app->getContainer()->get(IClientService::class),
			$this->app->getContainer()->get(IAvatarManager::class),
			$this->config,
			$this->session,
			$this->l10nFactory,
			$this->providerMapper,
			$this->crypto,
		);

		$this->registrationContext = $this->app->getContainer()
			->get(Coordinator::class)
			->getRegistrationContext();

		$this->settingsService = $this->getMockBuilder(SettingsService::class)
			->disableOriginalConstructor()
			->getMock();

		$this->settingsService->expects($this->any())
			->method('getAllowMultipleUserBackEnds')
			->willReturn(true);

		$this->tokenService = $this->app->getContainer()->get(TokenService::class);
		$this->oidcService = $this->app->getContainer()->get(OIDCService::class);

		$this->timeFactory = $this->createMock(ITimeFactory::class);
		$this->timeFactory->expects($this->any())
			->method('getTime')
			->willReturn(time());

		$this->loginController = new LoginController(
			$this->request,
			$this->providerMapper,
			$this->providerService,
			$this->discoveryService,
			$this->app->getContainer()->get(LdapService::class),
			$this->settingsService,
			$this->app->getContainer()->get(ISecureRandom::class),
			$this->session,
			$this->httpClientHelper,
			$this->app->getContainer()->get(IURLGenerator::class),
			$this->usersession,
			$this->usermanager,
			$this->timeFactory,
			$this->dispatcher,
			$this->config,
			$this->appConfig,
			$this->app->getContainer()->get(IProvider::class),
			$this->sessionMapper,
			$this->provisioningService,
			$this->app->getContainer()->get(IL10N::class),
			$this->app->getContainer()->get(LoggerInterface::class),
			$this->crypto,
			$this->tokenService,
			$this->oidcService,
		);

		$this->attributeListener = null;
		$this->accountListener = null;
	}

	public function tearDown(): void {
		if ($this->accountListener !== null) {
			$this->dispatcher->removeListener(UserAccountChangeEvent::class, $this->accountListener);
		}

		if ($this->attributeListener !== null) {
			$this->dispatcher->removeListener(AttributeMappedEvent::class, $this->attributeListener);
		}

		parent::tearDown();
	}

	protected function mockAssertLoginSuccess(): void {
		$this->usermanager->expects($this->once())
			->method('get')
			->willReturn($this->user);

		$this->usersession->expects($this->once())
			->method('setUser')
			->with($this->equalTo($this->user));

		$this->usersession->expects($this->any())
			->method('completeLogin')
			->with($this->anything(), $this->anything());

		$this->usersession->expects($this->any())
			->method('createSessionToken');

		$this->usersession->expects($this->any())
			->method('createRememberMeToken');
	}

	protected function assertLoginRedirect(mixed $result): void {
		if ($result instanceof TemplateResponse) {
			$this->fail(
				'Expected RedirectResponse, got TemplateResponse. Template: '
				. $result->getTemplateName()
				. ' Params: '
				. json_encode($result->getParams(), JSON_THROW_ON_ERROR)
			);
		}

		$this->assertInstanceOf(RedirectResponse::class, $result);
	}

	protected function assertLogin403(mixed $result): void {
		$this->assertInstanceOf(
			TemplateResponse::class,
			$result,
			'LoginController->code() did not end with 403 Forbidden'
		);
	}

	public function testNoMap_AccessOk(): void {
		$this->mockAssertLoginSuccess();

		$this->accountListener = function (Event $event): void {
			$this->assertInstanceOf(UserAccountChangeEvent::class, $event);
			$this->assertEquals('jgyros', $event->getUid());
			$this->assertEquals('Jonny G', $event->getDisplayName());
			$this->assertEquals('jonny.gyuris@x.y.de', $event->getMainEmail());
			$this->assertNull($event->getQuota());

			$event->setResult(true, 'ok', null);
		};

		$this->dispatcher->addListener(UserAccountChangeEvent::class, $this->accountListener);

		$result = $this->loginController->code($this->getOidTestState(), $this->getOidTestCode(), '');

		$this->assertLoginRedirect($result);
		$this->assertNotEmpty($result->getRedirectURL());
	}

	public function testUidNoMapEvent_AccessOk(): void {
		$this->mockAssertLoginSuccess();

		$this->accountListener = function (Event $event): void {
			$this->assertInstanceOf(UserAccountChangeEvent::class, $event);
			$this->assertEquals('jgyros', $event->getUid());
			$this->assertEquals('Jonny G', $event->getDisplayName());
			$this->assertEquals('jonny.gyuris@x.y.de', $event->getMainEmail());
			$this->assertNull($event->getQuota());

			$event->setResult(true, 'ok', 'https://welcome.to.darkside');
		};

		$this->dispatcher->addListener(UserAccountChangeEvent::class, $this->accountListener);

		$result = $this->loginController->code($this->getOidTestState(), $this->getOidTestCode(), '');

		$this->assertLoginRedirect($result);
		$this->assertEquals('http://localhost', $result->getRedirectURL());
	}

	public function testDisplaynameMapEvent_NOk_NoRedirect(): void {
		$this->attributeListener = function (Event $event): void {
			if ($event instanceof AttributeMappedEvent
				&& $event->getAttribute() === ProviderService::SETTING_MAPPING_DISPLAYNAME
			) {
				$event->setValue('Lisa, Mona');
			}
		};

		$this->accountListener = function (Event $event): void {
			$this->assertInstanceOf(UserAccountChangeEvent::class, $event);
			$this->assertEquals('jgyros', $event->getUid());
			$this->assertEquals('Lisa, Mona', $event->getDisplayName());
			$this->assertEquals('jonny.gyuris@x.y.de', $event->getMainEmail());
			$this->assertNull($event->getQuota());

			$event->setResult(false, 'not an original', null);
		};

		$this->dispatcher->addListener(AttributeMappedEvent::class, $this->attributeListener);
		$this->dispatcher->addListener(UserAccountChangeEvent::class, $this->accountListener);

		$result = $this->loginController->code($this->getOidTestState(), $this->getOidTestCode(), '');

		$this->assertLogin403($result);
	}

	public function testMainEmailMap_Nok_Redirect(): void {
		$this->attributeListener = function (Event $event): void {
			if ($event instanceof AttributeMappedEvent
				&& $event->getAttribute() === ProviderService::SETTING_MAPPING_EMAIL
			) {
				$event->setValue('mona.lisa@louvre.fr');
			}
		};

		$this->accountListener = function (Event $event): void {
			$this->assertInstanceOf(UserAccountChangeEvent::class, $event);
			$this->assertEquals('jgyros', $event->getUid());
			$this->assertEquals('Jonny G', $event->getDisplayName());
			$this->assertEquals('mona.lisa@louvre.fr', $event->getMainEmail());
			$this->assertNull($event->getQuota());

			$event->setResult(false, 'under restoration', 'https://welcome.to.louvre');
		};

		$this->dispatcher->addListener(AttributeMappedEvent::class, $this->attributeListener);
		$this->dispatcher->addListener(UserAccountChangeEvent::class, $this->accountListener);

		$result = $this->loginController->code($this->getOidTestState(), $this->getOidTestCode(), '');

		$this->assertLoginRedirect($result);
		$this->assertEquals('https://welcome.to.louvre', $result->getRedirectURL());
	}

	public function testDisplaynameUidQuotaMapped_AccessOK(): void {
		$this->mockAssertLoginSuccess();

		$this->attributeListener = function (Event $event): void {
			if (!$event instanceof AttributeMappedEvent) {
				return;
			}

			if ($event->getAttribute() === ProviderService::SETTING_MAPPING_DISPLAYNAME) {
				$event->setValue('Lisa, Mona');
			}

			if ($event->getAttribute() === ProviderService::SETTING_MAPPING_QUOTA) {
				$event->setValue('5 TB');
			}
		};

		$this->accountListener = function (Event $event): void {
			$this->assertInstanceOf(UserAccountChangeEvent::class, $event);
			$this->assertEquals('jgyros', $event->getUid());
			$this->assertEquals('Lisa, Mona', $event->getDisplayName());
			$this->assertEquals('jonny.gyuris@x.y.de', $event->getMainEmail());
			$this->assertEquals('5 TB', $event->getQuota());

			$event->setResult(true, 'ok', 'https://welcome.to.louvre');
		};

		$this->dispatcher->addListener(AttributeMappedEvent::class, $this->attributeListener);
		$this->dispatcher->addListener(UserAccountChangeEvent::class, $this->accountListener);

		$result = $this->loginController->code($this->getOidTestState(), $this->getOidTestCode(), '');

		$this->assertLoginRedirect($result);
		$this->assertEquals('http://localhost', $result->getRedirectURL());
	}
}
