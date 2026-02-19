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

package org.springframework.security.acls.aot.hint;

import org.jspecify.annotations.Nullable;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.*;

import java.util.stream.Stream;

/**
 * {@link RuntimeHintsRegistrar} for ACL (Access Control List) classes.
 *
 * @author Josh Long
 */
class AclRuntimeHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		registerAclDomainHints(hints);
		registerJdbcSchemaHints(hints);
	}

	private void registerAclDomainHints(RuntimeHints hints) {
		// Register core ACL domain types
		Stream.of(Acl.class, AccessControlEntry.class, AuditableAccessControlEntry.class,
						ObjectIdentity.class, Sid.class, AclImpl.class, AccessControlEntry.class,
						AuditLogger.class, ObjectIdentityImpl.class, PrincipalSid.class, GrantedAuthoritySid.class, BasePermission.class)
				.forEach(c -> hints.reflection().registerType(TypeReference.of(c), builder ->
						builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
								MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS)));


	}

	private void registerJdbcSchemaHints(RuntimeHints hints) {
		String[] sqlFiles = new String[]{
				"createAclSchema.sql",
				"createAclSchemaMySQL.sql",
				"createAclSchemaOracle.sql",
				"createAclSchemaPostgres.sql",
				"createAclSchemaSqlServer.sql",
				"createAclSchemaWithAclClassIdType.sql",
				"select.sql"
		};
		for (String sqlFile : sqlFiles) {
			Resource sqlResource = new ClassPathResource(sqlFile);
			if (sqlResource.exists()) {
				hints.resources().registerResource(sqlResource);
			}
		}
	}

}
