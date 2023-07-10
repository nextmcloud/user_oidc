<?php
/*
 * @copyright Copyright (c) 2021 T-Systems International
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


use OCP\Http\Client\IClientService;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IResponse;

use OCP\AppFramework\App;
use OCA\UserOIDC\AppInfo\Application;

use OCA\UserOIDC\Db\Provider;

use PHPUnit\Framework\TestCase;

class EventProvisioningServiceTest extends TestCase {
	public function setUp(): void {
		parent::setUp();
		$this->app = new App(Application::APP_ID);

		$this->provider = $this->getMockBuilder(Provider::class)
							->addMethods(['getDiscoveryEndpoint'])
							->getMock();
		$this->client = $this->getMockForAbstractClass(IClient::class);
		$this->clientFactory = $this->getMockForAbstractClass(IClientService::class);
		$this->clientFactory->expects($this->any())
							->method('newClient')
							->willReturn($this->client);
		$this->response = $this->getMockForAbstractClass(IResponse::class);
	}

	public function testUidMapped() {
	}

	public function testUidNotMapped() {
	}

	public function testDisplaynameMapped() {
	}

	public function testDisplaynameNotMapped() {
	}

	public function testQuotaMapped() {
	}

	public function testQuotaNotMapped() {
	}

	public function testMappingProblem() {
	}

	public function testSuccess() {
	}

	public function testDenied() {
	}

	public function testDeniedRedirect() {
	}
}
