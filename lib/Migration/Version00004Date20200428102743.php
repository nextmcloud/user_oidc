<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\UserOIDC\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * Auto-generated migration step: Please modify to your needs!
 */
class Version00004Date20200428102743 extends SimpleMigrationStep {

	/**
	 * @param IOutput $output
	 * @param Closure $schemaClosure The `\Closure` returns a `ISchemaWrapper`
	 * @param array $options
	 * @return null|ISchemaWrapper
	 */
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options) {

		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		$table = $schema->createTable('user_oidc_providers');
		$table->addColumn('id', 'integer', [
			'autoincrement' => true,
			'notnull' => true,
			'length' => 4,
		]);
		$table->addColumn('identifier', 'string', [
			'notnull' => true,
			'length' => 128,
		]);
		$table->addColumn('client_id', 'string', [
			'notnull' => true,
			'length' => 64,
		]);
		$table->addColumn('client_secret', 'string', [
			'notnull' => true,
			'length' => 64,
		]);
		$table->addColumn('discovery_endpoint', 'string', [
			'notnull' => false,
			'length' => 255,
		]);
		$table->setPrimaryKey(['id']);

		return $schema;
	}
}
