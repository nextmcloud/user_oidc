<?php

declare(strict_types=1);

namespace OCA\UserOIDC\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;
use OCP\Security\ICrypto;

class Version010304Date20230902125945 extends SimpleMigrationStep {

	/**
	 * @var IDBConnection
	 */
	private $connection;
	/**
	 * @var ICrypto
	 */
	private $crypto;

	public function __construct(
		IDBConnection $connection,
		ICrypto $crypto,
	) {
		$this->connection = $connection;
		$this->crypto = $crypto;
	}

	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options) {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		$tableName = 'user_oidc_providers';

		if ($schema->hasTable($tableName)) {
			$table = $schema->getTable($tableName);
			if ($table->hasColumn('bearer_secret')) {
				$column = $table->getColumn('bearer_secret');
				$column->setLength(512);
				return $schema;
			}
		}

		return null;
	}

	public function postSchemaChange(IOutput $output, Closure $schemaClosure, array $options) {
		$tableName = 'user_oidc_providers';

		// update secrets in user_oidc_providers and user_oidc_id4me
		$qbUpdate = $this->connection->getQueryBuilder();
		$qbUpdate->update($tableName)
			->set('bearer_secret', $qbUpdate->createParameter('updateSecret'))
			->where(
				$qbUpdate->expr()->eq('id', $qbUpdate->createParameter('updateId'))
			);

		$qbSelect = $this->connection->getQueryBuilder();
		$qbSelect->select('id', 'bearer_secret')
			->from($tableName);
		$req = $qbSelect->executeQuery();
		while ($row = $req->fetch()) {
			$id = $row['id'];
			$secret = $row['bearer_secret'];
			$encryptedSecret = $this->crypto->encrypt($secret);
			$qbUpdate->setParameter('updateSecret', $encryptedSecret, IQueryBuilder::PARAM_STR);
			$qbUpdate->setParameter('updateId', $id, IQueryBuilder::PARAM_INT);
			$qbUpdate->executeStatement();
		}
		$req->closeCursor();
	}
}
