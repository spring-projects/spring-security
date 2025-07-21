/*
 * Copyright 2004, 2005, 2006, 2017, 2018 Acegi Technology Pty Limited
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

package org.springframework.security.acls.jdbc;

import java.io.Serializable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.ConversionService;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityGenerator;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;

/**
 * Simple JDBC-based implementation of <code>AclService</code>.
 * <p>
 * Requires the "dirty" flags in {@link org.springframework.security.acls.domain.AclImpl}
 * and {@link org.springframework.security.acls.domain.AccessControlEntryImpl} to be set,
 * so that the implementation can detect changed parameters easily.
 *
 * @author Ben Alex
 */
public class JdbcAclService implements AclService {

	protected static final Log log = LogFactory.getLog(JdbcAclService.class);

	private static final String DEFAULT_SELECT_ACL_CLASS_COLUMNS = "class.class as class";

	private static final String DEFAULT_SELECT_ACL_CLASS_COLUMNS_WITH_ID_TYPE = DEFAULT_SELECT_ACL_CLASS_COLUMNS
			+ ", class.class_id_type as class_id_type";

	private static final String DEFAULT_SELECT_ACL_WITH_PARENT_SQL = "select obj.object_id_identity as obj_id, "
			+ DEFAULT_SELECT_ACL_CLASS_COLUMNS
			+ " from acl_object_identity obj, acl_object_identity parent, acl_class class "
			+ "where obj.parent_object = parent.id and obj.object_id_class = class.id "
			+ "and parent.object_id_identity = ? and parent.object_id_class = ("
			+ "select id FROM acl_class where acl_class.class = ?)";

	private static final String DEFAULT_SELECT_ACL_WITH_PARENT_SQL_WITH_CLASS_ID_TYPE = "select obj.object_id_identity as obj_id, "
			+ DEFAULT_SELECT_ACL_CLASS_COLUMNS_WITH_ID_TYPE
			+ " from acl_object_identity obj, acl_object_identity parent, acl_class class "
			+ "where obj.parent_object = parent.id and obj.object_id_class = class.id "
			+ "and parent.object_id_identity = ? and parent.object_id_class = ("
			+ "select id FROM acl_class where acl_class.class = ?)";

	protected final JdbcOperations jdbcOperations;

	private final LookupStrategy lookupStrategy;

	private boolean aclClassIdSupported;

	private String findChildrenSql = DEFAULT_SELECT_ACL_WITH_PARENT_SQL;

	private AclClassIdUtils aclClassIdUtils;

	private ObjectIdentityGenerator objectIdentityGenerator;

	public JdbcAclService(DataSource dataSource, LookupStrategy lookupStrategy) {
		this(new JdbcTemplate(dataSource), lookupStrategy);
	}

	public JdbcAclService(JdbcOperations jdbcOperations, LookupStrategy lookupStrategy) {
		Assert.notNull(jdbcOperations, "JdbcOperations required");
		Assert.notNull(lookupStrategy, "LookupStrategy required");
		this.jdbcOperations = jdbcOperations;
		this.lookupStrategy = lookupStrategy;
		this.aclClassIdUtils = new AclClassIdUtils();
		this.objectIdentityGenerator = new ObjectIdentityRetrievalStrategyImpl();
	}

	@Override
	public List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity) {
		Object[] args = { parentIdentity.getIdentifier().toString(), parentIdentity.getType() };
		List<ObjectIdentity> objects = this.jdbcOperations.query(this.findChildrenSql,
				(rs, rowNum) -> mapObjectIdentityRow(rs), args);
		return (!objects.isEmpty()) ? objects : null;
	}

	private ObjectIdentity mapObjectIdentityRow(ResultSet rs) throws SQLException {
		String javaType = rs.getString("class");
		Serializable identifier = (Serializable) rs.getObject("obj_id");
		identifier = this.aclClassIdUtils.identifierFrom(identifier, rs);
		return this.objectIdentityGenerator.createObjectIdentity(identifier, javaType);
	}

	@Override
	public Acl readAclById(ObjectIdentity object, List<Sid> sids) throws NotFoundException {
		Map<ObjectIdentity, Acl> map = readAclsById(Collections.singletonList(object), sids);
		Assert.isTrue(map.containsKey(object),
				() -> "There should have been an Acl entry for ObjectIdentity " + object);
		return map.get(object);
	}

	@Override
	public Acl readAclById(ObjectIdentity object) throws NotFoundException {
		return readAclById(object, null);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects) throws NotFoundException {
		return readAclsById(objects, null);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids)
			throws NotFoundException {
		Map<ObjectIdentity, Acl> result = this.lookupStrategy.readAclsById(objects, sids);
		// Check every requested object identity was found (throw NotFoundException if
		// needed)
		for (ObjectIdentity oid : objects) {
			if (!result.containsKey(oid)) {
				throw new NotFoundException("Unable to find ACL information for object identity '" + oid + "'");
			}
		}
		return result;
	}

	/**
	 * Allows customization of the SQL query used to find child object identities.
	 * @param findChildrenSql
	 */
	public void setFindChildrenQuery(String findChildrenSql) {
		this.findChildrenSql = findChildrenSql;
	}

	public void setAclClassIdSupported(boolean aclClassIdSupported) {
		this.aclClassIdSupported = aclClassIdSupported;
		if (aclClassIdSupported) {
			// Change the default children select if it hasn't been overridden
			if (this.findChildrenSql.equals(DEFAULT_SELECT_ACL_WITH_PARENT_SQL)) {
				this.findChildrenSql = DEFAULT_SELECT_ACL_WITH_PARENT_SQL_WITH_CLASS_ID_TYPE;
			}
			else {
				log.debug("Find children statement has already been overridden, so not overridding the default");
			}
		}
	}

	public void setConversionService(ConversionService conversionService) {
		this.aclClassIdUtils = new AclClassIdUtils(conversionService);
	}

	public void setObjectIdentityGenerator(ObjectIdentityGenerator objectIdentityGenerator) {
		Assert.notNull(objectIdentityGenerator, "objectIdentityGenerator cannot be null");
		this.objectIdentityGenerator = objectIdentityGenerator;
	}

	protected boolean isAclClassIdSupported() {
		return this.aclClassIdSupported;
	}

}
