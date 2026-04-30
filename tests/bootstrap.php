<?php

declare(strict_types=1);

use OCP\App\IAppManager;
use OCP\Server;

if (!defined('PHPUNIT_RUN')) {
	define('PHPUNIT_RUN', 1);
}

require_once __DIR__ . '/../../../lib/base.php';
require_once __DIR__ . '/../../../tests/autoload.php';

/**
 * Register composer autoloader once
 */
$composerAutoloader = require __DIR__ . '/../vendor/autoload.php';

/**
 * Register test namespace via Composer autoload
 */
$composerAutoloader->addPsr4(
	'OCA\\UserOIDC\\BaseTest\\',
	__DIR__ . '/unit/MagentaCloud/',
	true
);

/**
 * Load app
 */
Server::get(IAppManager::class)->loadApp('user_oidc');

/**
 * Cleanup hooks to ensure test isolation
 */
if (class_exists(\OC_Hook::class)) {
	\OC_Hook::clear();
}
