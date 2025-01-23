<?php
/**
 * SPDX-FileCopyrightText: 2016 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

if (!defined('PHPUNIT_RUN')) {
	define('PHPUNIT_RUN', 1);
}
require_once __DIR__ . '/../../../lib/base.php';
require_once __DIR__ . '/../vendor/autoload.php';

\OC::$loader->addValidRoot(OC::$SERVERROOT . '/tests');
\OC::$composerAutoloader->addPsr4('OCA\\UserOIDC\\BaseTest\\', dirname(__FILE__) . '/unit/MagentaCloud/', true);
\OC_App::loadApp('user_oidc');

OC_Hook::clear();
