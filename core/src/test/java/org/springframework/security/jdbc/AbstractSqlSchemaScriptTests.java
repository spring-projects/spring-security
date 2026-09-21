/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.jdbc;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.UUID;
import java.util.function.Supplier;

import javax.sql.DataSource;

import org.junit.jupiter.api.Tag;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.mssqlserver.MSSQLServerContainer;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.oracle.OracleContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Base class for tests that execute one of the {@code .sql} schema scripts shipped in
 * {@code src/main/resources} against a real database and then verify the result.
 *
 * <p>
 * Subclasses call {@link #verifySchemaScript(String, String, SchemaVerifier)
 * verifySchemaScript} with the name of a database, the classpath location of a script,
 * and a callback. The script is run against a freshly created database, and the callback
 * is then handed a {@link SchemaContext} that exposes the initialized {@link DataSource}
 * and {@link Connection} so that the component under test can be exercised for real.
 *
 * <p>
 * Databases are provisioned in one of two ways, depending on the name supplied:
 * <ul>
 * <li>{@code hsqldb} and {@code h2} run in-process, so they need no Docker daemon.</li>
 * <li>{@code postgresql}, {@code mysql}, {@code oracle} and {@code sqlserver} run in a
 * Testcontainers-managed container. These tests are skipped, rather than failed, when no
 * Docker daemon is available.</li>
 * </ul>
 *
 * <p>
 * Not every database offers a case-insensitive character type. Where one exists the
 * schema scripts use it (HSQLDB and H2 declare columns as {@code varchar_ignorecase}) and
 * a plain equality lookup is case-insensitive. Where one does not, an equality lookup is
 * case-sensitive, and a query has to lower-case both sides to behave the same way. The
 * {@link SchemaContext} derives this from the database name and supplies a matching query
 * through {@link SchemaContext#getUsersByUsernameQuery()} and its siblings, so that a
 * single verifier can assert identical behaviour on every platform.
 *
 * <p>
 * These tests need a real database, and the container-backed ones need a Docker daemon
 * and several minutes to run, so they are tagged {@value #TAG} and excluded from the
 * {@code test} task. Run them with {@code ./gradlew :spring-security-core:sqlTest}. The
 * tag is inherited, so every subclass is excluded too.
 *
 * @author Josh Long
 * @see Database
 */
@Tag(AbstractSqlSchemaScriptTests.TAG)
public abstract class AbstractSqlSchemaScriptTests {

	/**
	 * JUnit tag applied to every schema script test.
	 */
	public static final String TAG = "sql";

	/**
	 * Runs {@code script} against a newly provisioned {@code database} and hands the
	 * result to {@code verifier}, assuming the script declares whichever character type
	 * is idiomatic for that platform.
	 * @param database the name of the database to provision, for example
	 * {@code postgresql}. Must be one of the names understood by {@link Database}.
	 * @param script the classpath location of the {@code .sql} script to execute
	 * @param verifier invoked with the initialized database
	 */
	protected void verifySchemaScript(String database, String script, SchemaVerifier verifier) throws Exception {
		verifySchemaScript(database, script, Database.forName(database).getDefaultColumnCase(), verifier);
	}

	/**
	 * Runs {@code script} against a newly provisioned {@code database} and hands the
	 * result to {@code verifier}.
	 *
	 * <p>
	 * Case sensitivity is a property of the script as much as of the platform: HSQLDB and
	 * H2 only ignore case because {@code users-hsqldb.sql} and {@code users-h2.sql}
	 * declare {@code varchar_ignorecase} columns. A portable script that sticks to
	 * standard {@code varchar} is case-sensitive on those same platforms, so it has to
	 * say so here.
	 * @param database the name of the database to provision, for example
	 * {@code postgresql}. Must be one of the names understood by {@link Database}.
	 * @param script the classpath location of the {@code .sql} script to execute
	 * @param columnCase how the columns the script declares compare text, overriding
	 * {@link Database#getDefaultColumnCase() the platform default}
	 * @param verifier invoked with the initialized database
	 */
	protected void verifySchemaScript(String database, String script, ColumnCase columnCase, SchemaVerifier verifier)
			throws Exception {
		Database target = Database.forName(database);
		if (target.isContainerBased()) {
			assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
					() -> "Docker is not available, skipping " + target.getName());
			try (JdbcDatabaseContainer<?> container = target.createContainer()) {
				container.start();
				SingleConnectionDataSource dataSource = this.dataSource(container.getDriverClassName(),
						container.getJdbcUrl(), container.getUsername(), container.getPassword());
				try {
					populateAndVerify(target, columnCase, dataSource, script, verifier);
				}
				finally {
					dataSource.destroy();
				}
			}
		}
		else {
			SingleConnectionDataSource dataSource = dataSource(target.getDriverClassName(), target.newEmbeddedUrl(),
					target.getEmbeddedUsername(), "");
			try {
				populateAndVerify(target, columnCase, dataSource, script, verifier);
			}
			finally {
				shutdownEmbedded(dataSource);
				dataSource.destroy();
			}
		}
	}

	private void populateAndVerify(Database database, ColumnCase columnCase, DataSource dataSource, String script,
			SchemaVerifier verifier) throws Exception {
		ClassPathResource resource = new ClassPathResource(script);
		if (!resource.exists()) {
			throw new IllegalArgumentException("No such script on the classpath: " + script);
		}
		new ResourceDatabasePopulator(resource).execute(dataSource);
		verifier.verify(new SchemaContext(database, columnCase, dataSource));
	}

	private SingleConnectionDataSource dataSource(String driverClassName, String url, String username,
			String password) {
		SingleConnectionDataSource dataSource = new SingleConnectionDataSource(url, username, password, true);
		dataSource.setDriverClassName(driverClassName);
		return dataSource;
	}

	private void shutdownEmbedded(DataSource dataSource) {
		try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
			statement.execute("SHUTDOWN");
		}
		catch (SQLException ex) {
			// the in-memory database is discarded with the connection either way
		}
	}

	/**
	 * Callback invoked once the schema script has been executed successfully.
	 */
	@FunctionalInterface
	public interface SchemaVerifier {

		void verify(SchemaContext context) throws Exception;

	}

	/**
	 * How the character columns a schema script declares compare text. Determines whether
	 * a lookup can rely on plain equality or has to lower-case both sides.
	 */
	public enum ColumnCase {

		/**
		 * The columns ignore case, as HSQLDB and H2 {@code varchar_ignorecase} columns
		 * do, so {@code username = ?} already matches regardless of case.
		 */
		INSENSITIVE,

		/**
		 * The columns respect case, as a standard {@code varchar} column does, so a
		 * lookup has to lower-case both sides to ignore case.
		 */
		SENSITIVE

	}

	/**
	 * The databases a schema script can be verified against, and the capabilities of each
	 * that a verifier needs to adapt to.
	 */
	public enum Database {

		/**
		 * HSQLDB, in-process. Declares {@code varchar_ignorecase} columns.
		 */
		HSQLDB("hsqldb", ColumnCase.INSENSITIVE, "org.hsqldb.jdbc.JDBCDriver", "sa",
				() -> "jdbc:hsqldb:mem:" + unique(), null),

		/**
		 * H2, in-process. Declares {@code varchar_ignorecase} columns.
		 */
		H2("h2", ColumnCase.INSENSITIVE, "org.h2.Driver", "sa", () -> "jdbc:h2:mem:" + unique() + ";DB_CLOSE_DELAY=-1",
				null),

		/**
		 * PostgreSQL, in a container. Has no case-insensitive character type without the
		 * {@code citext} extension.
		 */
		POSTGRESQL("postgresql", ColumnCase.SENSITIVE, null, null, null, () -> new PostgreSQLContainer("postgres:16")),

		/**
		 * MySQL, in a container. Case sensitivity depends on the column collation rather
		 * than the type, so lookups are lower-cased here for determinism.
		 */
		MYSQL("mysql", ColumnCase.SENSITIVE, null, null, null, () -> new MySQLContainer("mysql:8")),

		/**
		 * Oracle, in a container. Has no case-insensitive character type without a
		 * linguistic collation.
		 */
		ORACLE("oracle", ColumnCase.SENSITIVE, null, null, null,
				() -> new OracleContainer("gvenzl/oracle-free:slim-faststart")),

		/**
		 * Microsoft SQL Server, in a container. Case sensitivity depends on the column
		 * collation rather than the type, so lookups are lower-cased here for
		 * determinism.
		 */
		SQLSERVER("sqlserver", ColumnCase.SENSITIVE, null, null, null,
				() -> new MSSQLServerContainer("mcr.microsoft.com/mssql/server:2022-latest").acceptLicense());

		private final String name;

		private final ColumnCase defaultColumnCase;

		private final String driverClassName;

		private final String embeddedUsername;

		private final Supplier<String> embeddedUrl;

		private final Supplier<JdbcDatabaseContainer<?>> container;

		Database(String name, ColumnCase defaultColumnCase, String driverClassName, String embeddedUsername,
				Supplier<String> embeddedUrl, Supplier<JdbcDatabaseContainer<?>> container) {
			this.name = name;
			this.defaultColumnCase = defaultColumnCase;
			this.driverClassName = driverClassName;
			this.embeddedUsername = embeddedUsername;
			this.embeddedUrl = embeddedUrl;
			this.container = container;
		}

		/**
		 * Returns the {@code Database} matching {@code name}, which is the same token
		 * used to name the platform-specific schema scripts, for example
		 * {@code postgresql} for {@code users-postgresql.sql}.
		 */
		public static Database forName(String name) {
			for (Database database : values()) {
				if (database.name.equalsIgnoreCase(name)) {
					return database;
				}
			}
			throw new IllegalArgumentException("Unsupported database '" + name + "'");
		}

		private static String unique() {
			return "schema_" + UUID.randomUUID().toString().replace("-", "");
		}

		public String getName() {
			return this.name;
		}

		/**
		 * How the character columns declared by this platform's own schema script compare
		 * text. Used as the default when a caller does not say otherwise.
		 */
		public ColumnCase getDefaultColumnCase() {
			return this.defaultColumnCase;
		}

		public boolean isContainerBased() {
			return this.container != null;
		}

		JdbcDatabaseContainer<?> createContainer() {
			return this.container.get();
		}

		String getDriverClassName() {
			return this.driverClassName;
		}

		String getEmbeddedUsername() {
			return this.embeddedUsername;
		}

		String newEmbeddedUrl() {
			return this.embeddedUrl.get();
		}

	}

	/**
	 * Handed to a {@link SchemaVerifier} once the schema script has run. Exposes the
	 * initialized database along with the queries appropriate to the platform's handling
	 * of case.
	 */
	public static final class SchemaContext {

		private final Database database;

		private final ColumnCase columnCase;

		private final DataSource dataSource;

		private SchemaContext(Database database, ColumnCase columnCase, DataSource dataSource) {
			this.database = database;
			this.columnCase = columnCase;
			this.dataSource = dataSource;
		}

		public Database getDatabase() {
			return this.database;
		}

		public DataSource getDataSource() {
			return this.dataSource;
		}

		/**
		 * A connection to the initialized database. The caller is responsible for closing
		 * it.
		 */
		public Connection getConnection() throws SQLException {
			return this.dataSource.getConnection();
		}

		/**
		 * How the columns created by the script that has just run compare text.
		 */
		public ColumnCase getColumnCase() {
			return this.columnCase;
		}

		/**
		 * Rewrites {@code predicate} so that it compares {@code column} against a bind
		 * parameter without regard to case, using the cheapest form the platform
		 * supports. Where the schema declares a case-insensitive type the column is
		 * compared directly; otherwise both sides are lower-cased.
		 * @param column the column to compare
		 */
		public String caseInsensitiveComparison(String column) {
			if (this.columnCase == ColumnCase.INSENSITIVE) {
				return column + " = ?";
			}
			return "lower(" + column + ") = lower(?)";
		}

		/**
		 * The {@code usersByUsernameQuery} to configure on the object under test so that
		 * lookups ignore case on this platform.
		 */
		public String getUsersByUsernameQuery() {
			return "select username,password,enabled from users where " + caseInsensitiveComparison("username");
		}

		/**
		 * The {@code authoritiesByUsernameQuery} to configure on the object under test so
		 * that lookups ignore case on this platform.
		 */
		public String getAuthoritiesByUsernameQuery() {
			return "select username,authority from authorities where " + caseInsensitiveComparison("username");
		}

		/**
		 * The {@code userExistsSql} to configure on the object under test so that lookups
		 * ignore case on this platform.
		 */
		public String getUserExistsSql() {
			return "select count(*) from users where " + caseInsensitiveComparison("username");
		}

		@Override
		public String toString() {
			return this.database.getName().toLowerCase(Locale.ROOT);
		}

	}

}
