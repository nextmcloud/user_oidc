<?php
/**
 * @copyright Copyright (c) 2023 T-Systems International
 *
 * @author Bernd Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Store the refresh token in session to use it for
 * bearer self test.
 */

declare(strict_types=1);

namespace OCA\UserOIDC\Controller;

use OCP\IConfig;
use OCP\ISession;
use OCP\IRequest;

use OCA\UserOIDC\MagentaBearer\Listener\RefreshTokenListener;
use OCA\UserOIDC\Db\ProviderMapper;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Db\IMapperException;
use OCP\AppFramework\Http;
use OCP\Http\Client\IClientService;

class BearerSelfTestController extends Controller {
	public function __construct(IClientService $clientService,
							IConfig $config,
							ProviderMapper $providerMapper,
							ISession $session,
							IRequest $request) {
		$this->clientService = $clientService;
		$this->config = $config;
		$this->providerMapper = $providerMapper;
		$this->session = $session;
		$this->request = $request;
	}

	/**
	 * @return bool
	 */
	private function isSecure(): bool {
		// no restriction in debug mode
		return $this->config->getSystemValueBool('debug', false) ||
				($this->request->getServerProtocol() === 'https');
	}

	/**
	 * @PublicPage
	 * @NoCSRFRequired
	 * @UseSession
	 * @BruteForceProtection(action=bearertest)
	 *
	 * Use a stored refresh token from OIDC login
	 * and try to get a bearer token for our application.
	 * (MagentaCLOUD)
	 *
	 * If successful, the token can be send in a
	 * POST request to the test endpoint.
	 */
	public function tokenFromSession() {
		if (!$this->isSecure()) {
			return new JSONResponse('user_oidc', [ 'message' => 'Server not running https!' ], Http::STATUS_BAD_REQUEST);
		}

		$refresh_token = $this->session->get(RefreshTokenListener::TBEARER_SESSION_ID);
		if (!refresh_token) {
			return new JSONResponse('user_oidc', [ 'message' => 'No refresh token in session. Try (re)login!' ], Http::NOT_FOUND);
		}

		try {
			$provider = $this->providerMapper->findProviderByIdentifier('Telekom');

			$client = $this->clientService->newClient();
			$result = $client->post(
				$discovery['token_endpoint'],
				[
					'body' => [
						'client_id' => $provider->getClientId(),
						'client_secret' => $this->crypto->decrypt($provider->getClientSecret()),
						'grant_type' => 'refresh_token',
						'refresh_token' => $refreshToken,
						'scope' => 'magentacloud',
					],
				]
			);
	
			$tokenData = json_decode($result->getBody(), true);

			$successResponse = new JSONResponse("Bearer token successful acquired.", Http::OK);
			$successResponse->setHeader("X-UserToken", $tokenData[]);
			return $successResponse;
		} catch (IMapperException $eDB) {
			return new TemplateResponse('user_oidc', strval(Http::STATUS_SERVICE_UNAVAILABLE),
								[ 'message' => "Telekom provider not available or ambiguous!"],
								TemplateResponse::RENDER_AS_ERROR);
		}
	}

	/**
	 * @NoCSRFRequired
	 * @BruteForceProtection(action=bearertest)
	 *
	 * Check whether a valid bearer is POSTed
	 * and deliver informations about the token
	 * and the associated user
	 */
	public function checkToken() {
		if (!$this->isSecure()) {
			return new JSONResponse('user_oidc', [ 'message' => 'Server not running https!' ], Http::STATUS_BAD_REQUEST);
		}

		/* if () {

		} else {
			return new JSONResponse('user_oidc', [ 'message' => 'Not a bearer token authentication!' ], Http::NOT_FOUND);
		}
		*/
	}
}
