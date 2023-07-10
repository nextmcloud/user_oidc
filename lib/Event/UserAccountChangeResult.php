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
 * Event to provide custom mapping logic based on the OIDC token data
 * In order to avoid further processing the event propagation should be stopped
 * in the listener after processing as the value might get overwritten afterwards
 * by other listeners through $event->stopPropagation();
 */
class UserAccountChangeResult
{

    /** @var bool */
    private $accessAllowed;
    /** @var string */
    private $reason;
    /** @var string */
    private $redirectUrl;

    public function __construct(bool $accessAllowed, string $reason = '', ?string $redirectUrl = null)
    {
        $this->accessAllowed = $accessAllowed;
        $this->redirectUrl = $redirectUrl;
        $this->reason = $reason;
    }

    /**
     * @return value for the logged in user attribute
     */
    public function isAccessAllowed(): bool
    {
        return $this->accessAllowed;
    }

    public function setAccessAllowed(bool $accessAllowed): void
    {
        $this->accessAllowed = $accessAllowed;
    }

    /**
     * @return get optional alternate redirect address
     */
    public function getRedirectUrl(): ?string
    {
        return $this->redirectUrl;
    }

    /**
     * @return set optional alternate redirect address
     */
    public function setRedirectUrl(?string $redirectUrl): void
    {
        $this->redirectUrl = $redirectUrl;
    }

    /**
     * @return get decision reason
     */
    public function getReason(): string
    {
        return $this->reason;
    }

    /**
     * @return set decision reason
     */
    public function setReason(string $reason): void
    {
        $this->reason = $reason;
    }
}
