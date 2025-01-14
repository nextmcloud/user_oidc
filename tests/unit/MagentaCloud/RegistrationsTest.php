<?php
/*
 * @copyright Copyright (c) 2021 T-Systems International
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 */

declare(strict_types=1);

use OC\AppFramework\Bootstrap\Coordinator;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Service\ProvisioningEventService;
use OCA\UserOIDC\Service\ProvisioningService;

use PHPUnit\Framework\TestCase;

class RegistrationsTest extends TestCase {
	public function setUp() :void {
		parent::setUp();

		$this->app = new Application();
		$coordinator = \OC::$server->get(Coordinator::class);
		$this->app->register($coordinator->getRegistrationContext()->for('user_oidc'));
	}

	public function testRegistration() :void {
		$provisioningService = $this->app->getContainer()->get(ProvisioningService::class);
		$this->assertInstanceOf(ProvisioningEventService::class, $provisioningService);
	}
}
