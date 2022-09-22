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

use OCA\UserOIDC\Event\AttributeMappedEvent;
use OCA\UserOIDC\Event\TokenObtainedEvent;
use OCA\UserOIDC\Event\UserAccountChangeEvent;
use OCA\UserOIDC\Service\DiscoveryService;
use OCA\UserOIDC\Service\ProviderService;
use OCA\UserOIDC\Service\UserService;
use OCA\UserOIDC\Service\InvalidTokenException;
use OCA\UserOIDC\Vendor\Firebase\JWT\JWT;
use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Http\Client\IClientService;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Security\ISecureRandom;

class LoginController extends Controller {
        private const STATE = 'oidc.state';
        private const NONCE = 'oidc.nonce';
        private const PROVIDERID = 'oidc.providerid';
        private const REDIRECT_AFTER_LOGIN = 'oidc.redirect';

        /** @var ISecureRandom */
        private $random;

        /** @var ISession */
        private $session;

        /** @var IClientService */
        private $clientService;

        /** @var IURLGenerator */
        private $urlGenerator;

        /** @var IUserSession */
        private $userSession;

        /** @var IUserManager */
        private $userManager;

        /** @var ProviderMapper */
        private $providerMapper;

        /** @var ILogger */
        private $logger;

        /** @var ProviderService */
        private $providerService;

        /** @var UserService */
        private $userService;

        /** @var DiscoveryService */
        private $discoveryService;

        public function __construct(
                IRequest $request,
                ProviderMapper $providerMapper,
                ProviderService $providerService,
                UserService $userService,
                DiscoveryService $discoveryService,
                ISecureRandom $random,
                ISession $session,
                IClientService $clientService,
                IURLGenerator $urlGenerator,
                IUserSession $userSession,
                IUserManager $userManager,
                IEventDispatcher $eventDispatcher,
                ILogger $logger
        ) {
                parent::__construct(Application::APP_ID, $request);

                $this->random = $random;
                $this->session = $session;
                $this->clientService = $clientService;
                $this->userService = $userService;
                $this->discoveryService = $discoveryService;
                $this->urlGenerator = $urlGenerator;
                $this->userSession = $userSession;
                $this->userManager = $userManager;
                $this->providerMapper = $providerMapper;
                $this->providerService = $providerService;
                $this->eventDispatcher = $eventDispatcher;
                $this->logger = $logger;
        }

        /**
         * @PublicPage
         * @NoCSRFRequired
         * @UseSession
         */
        public function login(int $providerId, string $redirectUrl = null) {
                if ($this->userSession->isLoggedIn()) {
                        return new RedirectResponse($redirectUrl);
                }
                $this->logger->debug('Initiating login for provider with id: ' . $providerId);

                //TODO: handle exceptions
                $provider = $this->providerMapper->getProvider($providerId);

                $state = $this->random->generate(32, ISecureRandom::CHAR_DIGITS . ISecureRandom::CHAR_UPPER);
                $this->session->set(self::STATE, $state);
                $this->session->set(self::REDIRECT_AFTER_LOGIN, $redirectUrl);

                $nonce = $this->random->generate(32, ISecureRandom::CHAR_DIGITS . ISecureRandom::CHAR_UPPER);
                $this->session->set(self::NONCE, $nonce);

                $this->session->set(self::PROVIDERID, $providerId);
                $this->session->close();

                $data = [
                        'client_id' => $provider->getClientId(),
                        'response_type' => 'code',
                        'scope' => $provider->getScope(),
                        'redirect_uri' => $this->urlGenerator->linkToRouteAbsolute(Application::APP_ID . '.login.code'),
                        // 'claims' => json_encode([
                        //      // more details about requesting claims:
                        //      // https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
                        //      'id_token' => [
                        //              // ['essential' => true] means it's mandatory but it won't trigger an error if it's not there
                        //              $uidAttribute => ['essential' => true],
                        //              // null means we want it
                        //              $emailAttribute => null,
                        //              $displaynameAttribute => null,
                        //              $quotaAttribute => null,
                        //      ],
                        //      'userinfo' => [
                        //              $uidAttribute => ['essential' => true],
                        //              $emailAttribute => null,
                        //              $displaynameAttribute => null,
                        //              $quotaAttribute => null,
                        //      ],
                        // ]),
                        'claims' => json_encode([
                                'id_token' => [
                                        'urn:telekom.com:all' => null
                                ],
                                'userinfo' => [
                                        'urn:telekom.com:all' => null
                                ],
                        ]),
                        'state' => $state,
                        'nonce' => $nonce,
                ];

                // pass discovery query parameters also on to the authentication
                // $discoveryUrl = parse_url($provider->getDiscoveryEndpoint());
                // if (isset($discoveryUrl["query"])) {
                //      $this->logger->debug('Add custom discovery query: ' . $discoveryUrl["query"]);
                //      $discoveryQuery = [];
                //      parse_str($discoveryUrl["query"], $discoveryQuery);
                //      $data += $discoveryQuery;
                // }

                try {
                        $discovery = $this->discoveryService->obtainDiscovery($provider);
                } catch (\Exception $e) {
                        $this->logger->error('Could not reach provider at URL ' . $provider->getDiscoveryEndpoint());
                        $response = new Http\TemplateResponse('', 'error', [
                                'errors' => [
                                        ['error' => 'Could not the reach OpenID Connect provider.']
                                ]
                        ], Http\TemplateResponse::RENDER_AS_ERROR);
                        $response->setStatus(404);
                        return $response;
                }

                //TODO verify discovery
                $url = $discovery['authorization_endpoint'] . '?' . http_build_query($data);
                $this->logger->debug('Redirecting user to: ' . $url);

        // Workaround to avoid empty session on special conditions in Safari
                // https://github.com/nextcloud/user_oidc/pull/358
        // it is only relevant for the login case, not in general
                if ($this->request->isUserAgent(['/Safari/']) && !$this->request->isUserAgent(['/Chrome/'])) {
                        return new Http\DataDisplayResponse('<meta http-equiv="refresh" content="0; url=' . $url . '" />');
                } else {
                        return new RedirectResponse($url);
                }
        }



        /**
         * @PublicPage
         * @NoCSRFRequired
         * @UseSession
         */
        public function code($state = '', $code = '', $scope = '') {
                $this->logger->debug('Code login with core: ' . $code . ' and state: ' . $state);

                if ($this->session->get(self::STATE) !== $state) {
                        $this->logger->debug('state does not match');

                        // TODO show page with forbidden
                        return new JSONResponse([
                                'got' => $state,
                                'expected' => $this->session->get(self::STATE),
                        ], Http::STATUS_FORBIDDEN);
                }

                // TODO: may remove providerId from session and iterate all providers
                $providerId = (int)$this->session->get(self::PROVIDERID);
                $provider = $this->providerMapper->getProvider($providerId);

                $discovery = $this->discoveryService->obtainDiscovery($provider);
                $this->logger->debug('Obtaining data from: ' . $discovery['token_endpoint']);

                $client = $this->clientService->newClient();
                $result = $client->post(
                        $discovery['token_endpoint'],
                        [
                                'body' => [
                                        'code' => $code,
                                        'client_id' => $provider->getClientId(),
                                        'client_secret' => $provider->getClientSecret(),
                                        'redirect_uri' => $this->urlGenerator->linkToRouteAbsolute(Application::APP_ID . '.login.code'),
                                        'grant_type' => 'authorization_code',
                                ],
                        ]
                );

                $data = json_decode($result->getBody(), true);
                $this->logger->debug('Received code response: ' . json_encode($data, JSON_THROW_ON_ERROR));
                $this->eventDispatcher->dispatchTyped(new TokenObtainedEvent($data, $provider, $discovery));

                $this->logger->debug('id_token=' . $data['id_token']);

                // TODO: proper error handling
                $payload = JWT::decode($data['id_token'], $this->discoveryService->obtainJWK($provider), array_keys(JWT::$supported_algs));
                // JWT decode has already done the following steps
                // @throws DomainException              Algorithm was not provided
                // @throws UnexpectedValueException     Provided JWT was invalid
                // @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
                // @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
                // @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
                // @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
                //
                // For details:
                // @see https://github.com/firebase/php-jwt
                // the nonce is used to associate the token to the previous redirect
        if (isset($payload->nonce) && $payload->nonce !== $this->session->get(self::NONCE)) {
                        $this->logger->debug('Nonce does not match');
                        // TODO: error properly
                        return new JSONResponse(['invalid nonce'], Http::STATUS_UNAUTHORIZED);
                }

                $clientId = $provider->getClientId();
                if ($payload->aud !== $clientId && !in_array($clientId, $payload->aud, true)) {
                        $this->logger->error("Invalid token (access): Token signature ok, but audience does not fit!");
                        return new JSONResponse(['invalid audience'], Http::STATUS_UNAUTHORIZED);
                }

                // TODO: may also add code_verifier
                $this->logger->debug('Parsed the JWT payload: ' . json_encode($payload, JSON_THROW_ON_ERROR));

                try {
                $uid = $this->userService->determineUID($providerId, $payload);
                $displayname = $this->userService->determineDisplayname($providerId, $payload);
                $email = $this->userService->determineEmail($providerId, $payload);
                $quota = $this->userService->determineQuota($providerId, $payload);
                } catch (AttributeValueException $eAttribute) {
                        return new JSONResponse($eAttribute->getMessage(), Http::STATUS_NOT_ACCEPTABLE);
                }

        $userReaction = $this->userService->changeUserAccount($uid, $displayname, $email, $quota, $payload);
                if ($userReaction->isAccessAllowed()) {
            $this->logger->info("{$uid}: user accepted by OpenId web authorization, reason: " . $userReaction->getReason() );
                        $user = $this->userManager->get($uid);
                        $this->userSession->setUser($user);
                        $this->userSession->completeLogin($user, ['loginName' => $user->getUID(), 'password' => '']);
                        $this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());
            $this->userSession->createRememberMeToken($user);
        } else {
            $this->logger->info("{$uid}: user rejected by OpenId web authorization, reason: " . $userReaction->getReason() );
        }

                if ($userReaction->getRedirectUrl() != null) {
            // redirect determined by business event rules
            $this->logger->debug("{$uid}: Custom redirect to: " . $userReaction->getRedirectUrl() );
            return new RedirectResponse($userReaction->getRedirectUrl());
        } else if ($userReaction->isAccessAllowed()) {
            // positive default
            $successRedirect = $this->session->get(self::REDIRECT_AFTER_LOGIN);
            if ($successRedirect == null) {
                $successRedirect = \OC_Util::getDefaultPageUrl();
            }
            $this->logger->debug("{$uid}: Standard redirect to: " . $successRedirect );
            return new RedirectResponse($successRedirect);
        } else {
            // negative default
            return new JSONResponse([ $userReaction->getReason() ], Http::STATUS_UNAUTHORIZED);
        }
        }
}
