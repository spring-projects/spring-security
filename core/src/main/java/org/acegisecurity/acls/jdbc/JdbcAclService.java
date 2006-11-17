/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.acegisecurity.acls.jdbc;

import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.AclService;
import org.acegisecurity.acls.NotFoundException;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityImpl;
import org.acegisecurity.acls.sid.Sid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import org.springframework.util.Assert;

import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.List;
import java.util.Map;

import javax.sql.DataSource;


/**
 * Simple JDBC-based implementation of <code>AclService</code>.<p>Requires the "dirty" flags in {@link
 * org.acegisecurity.acls.domain.AclImpl} and {@link org.acegisecurity.acls.domain.AccessControlEntryImpl} to be set,
 * so that the implementation can detect changed parameters easily.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JdbcAclService implements AclService {
    //~ Static fields/initializers =====================================================================================

    protected static final Log log = LogFactory.getLog(JdbcAclService.class);
    private static final String selectAclObjectWithParent = "SELECT obj.object_id_identity obj_id, class.class class "
        + "FROM acl_object_identity obj, acl_object_identity parent, acl_class class "
        + "WHERE obj.parent_object = parent.id AND obj.object_id_class = class.id "
        + "AND parent.object_id_identity = ? AND parent.object_id_class = ("
        + "SELECT id FROM acl_class WHERE acl_class.class = ?)";

    //~ Instance fields ================================================================================================

    protected JdbcTemplate jdbcTemplate;
    private LookupStrategy lookupStrategy;

    //~ Constructors ===================================================================================================

    public JdbcAclService(DataSource dataSource, LookupStrategy lookupStrategy) {
        Assert.notNull(dataSource, "DataSource required");
        Assert.notNull(lookupStrategy, "LookupStrategy required");
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.lookupStrategy = lookupStrategy;
    }

    //~ Methods ========================================================================================================

    public ObjectIdentity[] findChildren(ObjectIdentity parentIdentity) {
        Object[] args = {parentIdentity.getIdentifier(), parentIdentity.getJavaType().getName()};
        List objects = jdbcTemplate.query(selectAclObjectWithParent, args,
                new RowMapper() {
                    public Object mapRow(ResultSet rs, int rowNum)
                        throws SQLException {
                        String javaType = rs.getString("class");
                        String identifier = rs.getString("obj_id");

                        return new ObjectIdentityImpl(javaType, identifier);
                    }
                });

        return (ObjectIdentityImpl[]) objects.toArray(new ObjectIdentityImpl[] {});
    }

    public Acl readAclById(ObjectIdentity object, Sid[] sids)
        throws NotFoundException {
        Map map = readAclsById(new ObjectIdentity[] {object}, sids);

        if (map.size() == 0) {
            throw new NotFoundException("Could not find ACL");
        } else {
            return (Acl) map.get(object);
        }
    }

    public Acl readAclById(ObjectIdentity object) throws NotFoundException {
        return readAclById(object, null);
    }

    public Map readAclsById(ObjectIdentity[] objects) {
        return readAclsById(objects, null);
    }

    public Map readAclsById(ObjectIdentity[] objects, Sid[] sids)
        throws NotFoundException {
        return lookupStrategy.readAclsById(objects, sids);
    }
}
