<?php

/** @noinspection AdditionOperationOnArraysInspection */

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2020, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\UserOIDC\Controller;

use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Controller\LoginController;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;
use OCP\IConfig;

use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\ProviderService;


class LogoutController extends Controller {
        private const REDIRECT_AFTER_LOGIN = 'oidc.redirect';

        public const USER_AGENT_CHROME = '/^Mozilla\/5\.0 \([^)]+\) AppleWebKit\/[0-9.]+ \(KHTML, like Gecko\)( Ubuntu Chromium\/[0-9.]+|) Chrome\/[0-9.]+ (Mobile Safari|Safari)\/[0-9.]+( (Vivaldi|Brave|OPR)\/[0-9.]+|)$/';
        public const USER_AGENT_ANDROID_MOBILE_CHROME = '#Android.*Chrome/[.0-9]*#';

    /** @var IConfig */
        private $config;

    /** @var ILogger */
        private $logger;

    /** @var ISession */
        private $session;

    /** @var IUserSession */
        private $userSession;

    /** @var ProviderService */
        private $providerService;

        /** @var DiscoveryService */
        private $discoveryService;


        public function __construct(
                IRequest $request,
                ILogger $logger,
        ISession $session,
        IUserSession $userSession,
        ProviderService $providerService,
        DiscoveryService $discoveryService,
        ICOnfig          $config
        ) {
                parent::__construct(Application::APP_ID, $request);

                $this->logger = $logger;
        $this->session = $session;
        $this->userSession = $userSession;
        $this->providerService = $providerService;
        $this->discoveryService = $discoveryService;
        $this->config = $config;
        }

    protected function defaultLoginPage() {
        $loginRedirect = $this->session->get(self::REDIRECT_AFTER_LOGIN);
        if ($loginRedirect == null) {
            $loginRedirect = \OC_Util::getDefaultPageUrl();
        }

        return $loginRedirect;
    }

    protected function ssoLogoutPage() {
        $provider = 'Telekom';
        $provider = $this->providerService->getProviderByIdentifier($provider);
        if ( $provider != null ) {
            try {
                $discovery = $this->discoveryService->obtainDiscovery($provider);
            } catch (\Exception $e) {
                $this->logger->error('Could not reach provider at URL ' . $provider->getDiscoveryEndpoint());
                return new RedirectResponse($this->defaultLoginPage());
            }
            $ssoPage = $discovery['logout_endpoint'];
            $this->logger->debug("Logout with endpoint " . $ssoPage);
            if (!is_null($ssoPage)) {
                return new RedirectResponse($ssoPage . '?redirectURL=' . $this->defaultLoginPage());
            } else {
                return new RedirectResponse($this->defaultLoginPage());
            }
        } else {
            // TODO: lacking a good strategy for multiple providers yet
            return new RedirectResponse($this->defaultLoginPage());
        }
    }


        /**
     * @NoAdminRequired
         * @NoCSRFRequired
     * @UseSession
     */
        public function sessionlogout() {
        $this->logger->debug("Logout for user " . $this->userSession->getUser()->getUID());
        $loginToken = $this->request->getCookie('nc_token');
                if (!is_null($loginToken)) {
                        $this->config->deleteUserValue($this->userSession->getUser()->getUID(), 'login_token', $loginToken);
                }
                $this->userSession->logout();

                $this->session->clear();

        // TODO: for now, we only support logout with 'Telekom' provider
        $response = $this->ssoLogoutPage();

                if (!$this->request->isUserAgent([self::USER_AGENT_CHROME, self::USER_AGENT_ANDROID_MOBILE_CHROME])) {
                        $response->addHeader('Clear-Site-Data', '"cache", "storage"');
                }
        return $response;
    }

        /**
         * @PublicPage
         * @NoCSRFRequired
     * @NoAdminRequired
     *
     * @param string $logout_token
         */
        public function logout($logout_token = '') {
        // TODO: we have no real usecase for Backchannel logout yet.

        // If we need to implement it, we have to catch the session_token from OepID web login
        // and cache it for the associated userid because the backchannel does not have any
        // other session information.

        // for details, see
        // https://accounts.login.idm.telekom.com/devguide/telekom_login/OpenIDConnectBackChannelLogout.html
        // tbs2014/tbs2014
        $this->logger->debug("Backchannel logout received: " . $logout_token);
        return new DataResponse();
        }
}
