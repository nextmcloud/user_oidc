<?php
/*
 * @copyright Copyright (c) 2023 T-Systems International
 *
 * @author B. Rederlechner <bernd.rederlechner@t-systems.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 */

declare(strict_types=1);

namespace OCA\UserOIDC\Event;

/**
 * Represents the result of an account change event decision.
 * Used to signal whether access is allowed and optional redirect/reason info.
 */
class UserAccountChangeResult {

	/** @var bool */
	private $accessAllowed;

	/** @var string */
	private $reason;

	/** @var string|null */
	private $redirectUrl;

	public function __construct(bool $accessAllowed, string $reason = '', ?string $redirectUrl = null) {
		$this->accessAllowed = $accessAllowed;
		$this->redirectUrl = $redirectUrl;
		$this->reason = $reason;
	}

	/**
	 * Whether access for this user is allowed.
	 *
	 * @return bool
	 */
	public function isAccessAllowed(): bool {
		return $this->accessAllowed;
	}

	/**
	 * Set whether access for this user is allowed.
	 *
	 * @param bool $accessAllowed
	 * @return void
	 */
	public function setAccessAllowed(bool $accessAllowed): void {
		$this->accessAllowed = $accessAllowed;
	}

	/**
	 * Returns the optional alternate redirect URL.
	 *
	 * @return string|null
	 */
	public function getRedirectUrl(): ?string {
		return $this->redirectUrl;
	}

	/**
	 * Sets the optional alternate redirect URL.
	 *
	 * @param string|null $redirectUrl
	 * @return void
	 */
	public function setRedirectUrl(?string $redirectUrl): void {
		$this->redirectUrl = $redirectUrl;
	}

	/**
	 * Returns the decision reason.
	 *
	 * @return string
	 */
	public function getReason(): string {
		return $this->reason;
	}

	/**
	 * Sets the decision reason.
	 *
	 * @param string $reason
	 * @return void
	 */
	public function setReason(string $reason): void {
		$this->reason = $reason;
	}
}
