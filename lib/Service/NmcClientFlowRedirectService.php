<?php

declare(strict_types=1);

namespace OCA\UserOIDC\Service;

use Exception;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserSession;
use OCP\Security\ISecureRandom;

class NmcClientFlowRedirectService {
	public function __construct(
		private IRequest $request,
		private IURLGenerator $urlGenerator,
		private ProviderMapper $providerMapper,
		private ISession $session,
		private ISecureRandom $random,
		private IUserSession $userSession,
	) {
	}

	public function handle(): void {
		try {
			if ($this->request->getPathInfo() !== '/login/flow') {
				return;
			}
		} catch (\Throwable $e) {
			return;
		}

		if ($this->userSession->isLoggedIn()) {
			return;
		}

		try {
			if ($this->request->getPathInfo() !== '/login/flow') {
				return;
			}
		} catch (Exception) {
			return;
		}

		$providers = $this->providerMapper->getProviders();

		$telekomProviders = array_values(array_filter(
			$providers,
			static fn ($provider): bool => strtolower($provider->getIdentifier()) === 'telekom'
		));

		if (count($telekomProviders) !== 1) {
			return;
		}

		$stateToken = $this->random->generate(
			64,
			ISecureRandom::CHAR_LOWER . ISecureRandom::CHAR_UPPER . ISecureRandom::CHAR_DIGITS
		);

		$this->session->set('client.flow.state.token', $stateToken);

		$redirectUrl = $this->urlGenerator->linkToRoute('core.ClientFlowLogin.grantPage', [
			'stateToken' => $stateToken,
			'clientIdentifier' => $this->request->getParam('clientIdentifier', ''),
			'direct' => $this->request->getParam('direct', '0'),
		]);

		$targetUrl = $this->urlGenerator->linkToRoute(Application::APP_ID . '.login.login', [
			'providerId' => $telekomProviders[0]->getId(),
			'redirectUrl' => $redirectUrl,
		]);

		header('Location: ' . $targetUrl);
		exit();
	}
}
