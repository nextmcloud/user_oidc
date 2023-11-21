<?php

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

namespace OCA\UserOIDC\AppInfo;

use Exception;
use OC_App;
use OC_User;
use OCA\Files\Event\LoadAdditionalScriptsEvent;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Listener\TimezoneHandlingListener;
use OCA\UserOIDC\Service\ID4MeService;
use OCA\UserOIDC\Service\SettingsService;
use OCA\UserOIDC\Service\ProvisioningService;
use OCA\UserOIDC\Service\ProvisioningEventService;
use OCA\UserOIDC\MagentaBearer\MBackend;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\IUserSession;
use Throwable;
use Psr\Container\ContainerInterface;

// this is needed only for the special, shortened client login flow
use OCP\Security\ISecureRandom;
use OCP\ISession;

class Application extends App implements IBootstrap {
	public const APP_ID = 'user_oidc';
	public const OIDC_API_REQ_HEADER = 'Authorization';

	private $backend;
	private $cachedProviders;

	public function __construct(array $urlParams = []) {
		parent::__construct(self::APP_ID, $urlParams);
	}

	public function register(IRegistrationContext $context): void {
		// Register the composer autoloader required for the added jwt-token libs
		include_once __DIR__ . '/../../vendor/autoload.php';

		// override registration of provisioning srevice to use event-based solution
		$this->getContainer()->registerService(ProvisioningService::class, function (ContainerInterface $c): ProvisioningService {
			return $c->get(ProvisioningEventService::class);
		});

		/** @var IUserManager $userManager */
		$userManager = $this->getContainer()->get(IUserManager::class);

		/* Register our own user backend */
		$this->backend = $this->getContainer()->get(MBackend::class);
		$userManager->registerBackend($this->backend);
		OC_User::useBackend($this->backend);

		$context->registerEventListener(LoadAdditionalScriptsEvent::class, TimezoneHandlingListener::class);
	}

	public function boot(IBootContext $context): void {
		$context->injectFn(\Closure::fromCallable([$this->backend, 'injectSession']));
		/** @var IUserSession $userSession */
		$userSession = $this->getContainer()->get(IUserSession::class);
		if ($userSession->isLoggedIn()) {
			return;
		}

		try {
			$context->injectFn(\Closure::fromCallable([$this, 'registerRedirect']));
			$context->injectFn(\Closure::fromCallable([$this, 'registerLogin']));
			// this is the custom auto-redirect for MagentaCLOUD client access
			$context->injectFn(\Closure::fromCallable([$this, 'registerNmcClientFlow']));
		} catch (Throwable $e) {
		}
	}

	/**
	 * This is the automatic redirect exclusively for Nextcloud/Magentacloud clients
	 * completely skipping consent layer
	 */
	private function registerNmcClientFlow(IRequest $request, 
            IURLGenerator $urlGenerator,
            ProviderMapper $providerMapper, 
            ISession $session, 
            ISecureRandom $random): void {
		
        $providers = $this->getCachedProviders($providerMapper);

		// Handle immediate redirect on client first-time login
		$isClientLoginFlow = false;
		try {
			$isClientLoginFlow = $request->getPathInfo() === '/login/flow';
		} catch (Exception $e) {
			// in case any errors happen when checking for the path do not apply redirect logic as it is only needed for the login
		}
		if ($isClientLoginFlow) {
			// only redirect if Telekom provider registered
			$tproviders = array_values(array_filter($providers, function ($p) {
				return strtolower($p->getIdentifier()) === "telekom";
			}));
			if (count($tproviders) == 0) {
                // always show normal login flow as error fallback
                return;
            }

            $stateToken = $random->generate(
                64,
                ISecureRandom::CHAR_LOWER.ISecureRandom::CHAR_UPPER.ISecureRandom::CHAR_DIGITS
            );
            $session->set('client.flow.state.token', $stateToken);
 
            // call the service to get the params, but suppress the template
            // compute grant redirect Url to go directly to Telekom login
            $redirectUrl = $urlGenerator->linkToRoute('core.ClientFlowLogin.grantPage', [
                'stateToken' => $stateToken,
                // grantPage service operation is deriving oauth2 client name (again),
                // so we simply pass on clientIdentifier or empty string 
                'clientIdentifier' => $request->getParam('clientIdentifier', ''),
                'direct' => $request->getParam('direct', '0')
            ]);
            if ($redirectUrl === null) {
                // always show normal login flow as error fallback
                return;
            }

            // direct login, consent layer later
			$targetUrl = $urlGenerator->linkToRoute(self::APP_ID . '.login.login', [
			    'providerId' => $tproviders[0]->getId(),
				'redirectUrl' => $redirectUrl
			]);
			header('Location: ' . $targetUrl);
			exit();
		}
	}

	private function registerRedirect(IRequest $request, IURLGenerator $urlGenerator, SettingsService $settings, ProviderMapper $providerMapper): void {
		$providers = $this->getCachedProviders($providerMapper);
		$redirectUrl = $request->getParam('redirect_url');

		// Handle immediate redirect to the oidc provider if just one is configured and no other backends are allowed
		$isDefaultLogin = false;
		try {
			$isDefaultLogin = $request->getPathInfo() === '/login' && $request->getParam('direct') !== '1';
		} catch (Exception $e) {
			// in case any errors happen when checking for the path do not apply redirect logic as it is only needed for the login
		}
		if ($isDefaultLogin && !$settings->getAllowMultipleUserBackEnds() && count($providers) === 1) {
			$targetUrl = $urlGenerator->linkToRoute(self::APP_ID . '.login.login', [
				'providerId' => $providers[0]->getId(),
				'redirectUrl' => $redirectUrl
			]);
			header('Location: ' . $targetUrl);
			exit();
		}
	}

	private function registerLogin(IRequest $request, IL10N $l10n, IURLGenerator $urlGenerator, ProviderMapper $providerMapper): void {
		$redirectUrl = $request->getParam('redirect_url');
		$providers = $this->getCachedProviders($providerMapper);
		foreach ($providers as $provider) {
			// FIXME: Move to IAlternativeLogin but requires boot due to db connection
			OC_App::registerLogIn([
				'name' => $l10n->t('Login with %1s', [$provider->getIdentifier()]),
				'href' => $urlGenerator->linkToRoute(self::APP_ID . '.login.login', ['providerId' => $provider->getId(), 'redirectUrl' => $redirectUrl]),
			]);
		}

		/** @var ID4MeService $id4meService */
		$id4meService = $this->getContainer()->get(ID4MeService::class);
		if ($id4meService->getID4ME()) {
			OC_App::registerLogIn([
				'name' => 'ID4ME',
				'href' => $urlGenerator->linkToRoute(self::APP_ID . '.id4me.login'),
			]);
		}
	}

	private function getCachedProviders(ProviderMapper $providerMapper): array {
		if (!isset($this->cachedProviders)) {
			$this->cachedProviders = $providerMapper->getProviders();
		}

		return $this->cachedProviders;
	}
}
