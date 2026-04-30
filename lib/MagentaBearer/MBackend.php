<?php

declare(strict_types=1);

namespace OCA\UserOIDC\MagentaBearer;

use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\Provider;
use OCA\UserOIDC\User\Backend;
use OCA\UserOIDC\User\BearerValidationResult;

class MBackend extends Backend {
	public function getBackendName(): string {
		return Application::APP_ID . '\\MagentaBearer';
	}

	public function isSessionActive(): bool {
		$headerToken = $this->request->getHeader(Application::OIDC_API_REQ_HEADER);

		return is_string($headerToken)
			&& preg_match('/^\s*bearer\s+\S+/i', $headerToken) === 1;
	}

	protected function validateBearerToken(Provider $provider, string $headerToken): ?BearerValidationResult {
		try {
			$sharedSecret = $this->crypto->decrypt($provider->getBearerSecret());

			$bearerToken = $this->magentaTokenService->decryptToken($headerToken, $sharedSecret);
			$this->magentaTokenService->verifySignature($bearerToken, $sharedSecret);

			$payload = $this->magentaTokenService->decode($bearerToken);
			$this->magentaTokenService->verifyClaims($payload, ['http://auth.magentacloud.de']);

			$uidAttribute = $this->providerService->getSetting(
				$provider->getId(),
				ProviderService::SETTING_MAPPING_UID,
				'sub',
			);

			$userId = $payload->{$uidAttribute} ?? null;

			if (!$this->isAcceptableUserId($userId)) {
				$this->logger->debug('No valid user id in Telekom bearer token', [
					'providerId' => $provider->getId(),
					'uidAttribute' => $uidAttribute,
				]);
				return null;
			}

			return new BearerValidationResult($userId, $payload);
		} catch (SignatureException $e) {
			$this->logger->debug('Telekom bearer signature does not match provider', [
				'providerId' => $provider->getId(),
				'exception' => $e,
			]);
			return null;
		} catch (InvalidTokenException $e) {
			$this->logger->debug('Invalid Telekom bearer token', [
				'providerId' => $provider->getId(),
				'exception' => $e,
			]);
			return null;
		} catch (\Throwable $e) {
			$this->logger->debug('Could not validate Telekom bearer token', [
				'providerId' => $provider->getId(),
				'exception' => $e,
			]);
			return null;
		}
	}
}
