<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 T-Systems International
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

use OC\AppFramework\Bootstrap\Coordinator;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Service\ProvisioningEventService;
use OCA\UserOIDC\Service\ProvisioningService;
use PHPUnit\Framework\TestCase;

class RegistrationsTest extends TestCase {
	private Application $app;

	public function setUp(): void {
		parent::setUp();

		$this->app = new Application();

		$coordinator = \OC::$server->get(Coordinator::class);
		$this->app->register($coordinator->getRegistrationContext()->for(Application::APP_ID));
	}

	public function testProvisioningServiceRegistration(): void {
		$provisioningService = $this->app->getContainer()->get(ProvisioningService::class);

		$this->assertInstanceOf(ProvisioningEventService::class, $provisioningService);
	}
}
