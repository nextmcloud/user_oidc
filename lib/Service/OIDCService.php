<?php
/*
 * @copyright Copyright (c) 2021 Julius Härtl <jus@bitgrid.net>
 *
 * @author Julius Härtl <jus@bitgrid.net>
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

namespace OCA\UserOIDC\Service;

use OCA\UserOIDC\Db\Provider;
use OCP\Http\Client\IClientService;
use OCP\Security\ICrypto;
use Psr\Log\LoggerInterface;
use Throwable;

class OIDCService {

	/** @var LoggerInterface */
	private $logger;
	/** @var IClientService */
	private $clientService;
	/** @var ICrypto */
	private $crypto;

	public function __construct(
		DiscoveryService $discoveryService,
		LoggerInterface $logger,
		IClientService $clientService,
		ICrypto $crypto
	) {
		$this->discoveryService = $discoveryService;
		$this->logger = $logger;
		$this->clientService = $clientService;
		$this->crypto = $crypto;
	}

	public function userinfo(Provider $provider, string $accessToken): array {
		$url = $this->discoveryService->obtainDiscovery($provider)['userinfo_endpoint'] ?? null;
		if ($url === null) {
			return [];
		}

		$client = $this->clientService->newClient();
		$this->logger->debug('Fetching user info endpoint');
		$options = [
			'headers' => [
				'Authorization' => 'Bearer ' . $accessToken,
			],
		];
		try {
			return json_decode($client->get($url, $options)->getBody(), true);
		} catch (Throwable $e) {
			return [];
		}
	}

	public function introspection(Provider $provider, string $accessToken): array {
		try {
			$providerClientSecret = $this->crypto->decrypt($provider->getClientSecret());
		} catch (\Exception $e) {
			$this->logger->error('Failed to decrypt the client secret', ['exception' => $e]);
			return [];
		}
		$url = $this->discoveryService->obtainDiscovery($provider)['introspection_endpoint'] ?? null;
		if ($url === null) {
			return [];
		}

		$client = $this->clientService->newClient();
		$this->logger->debug('Fetching user info endpoint');
		$options = [
			'headers' => [
				'Authorization' => base64_encode($provider->getClientId() . ':' . $providerClientSecret),
			],
			'body' => [
				'token' => $accessToken,
			],
		];
		try {
			return json_decode($client->post($url, $options)->getBody(), true);
		} catch (Throwable $e) {
			return [];
		}
	}
}
