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
package org.springframework.security.acls.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;


/**
 * Simple JDBC-based implementation of <code>AclService</code>.
 * <p>
 * Requires the "dirty" flags in {@link org.springframework.security.acls.domain.AclImpl} and
 * {@link org.springframework.security.acls.domain.AccessControlEntryImpl} to be set, so that the implementation can
 * detect changed parameters easily.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JdbcAclService implements AclService {
    //~ Static fields/initializers =====================================================================================

    protected static final Log log = LogFactory.getLog(JdbcAclService.class);
    private static final String selectAclObjectWithParent = "select obj.object_id_identity as obj_id, class.class as class "
        + "from acl_object_identity obj, acl_object_identity parent, acl_class class "
        + "where obj.parent_object = parent.id and obj.object_id_class = class.id "
        + "and parent.object_id_identity = ? and parent.object_id_class = ("
        + "select id FROM acl_class where acl_class.class = ?)";

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

    public List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity) {
        Object[] args = {parentIdentity.getIdentifier(), parentIdentity.getJavaType().getName()};
        List<ObjectIdentity> objects = jdbcTemplate.query(selectAclObjectWithParent, args,
                new RowMapper<ObjectIdentity>() {
                    public ObjectIdentity mapRow(ResultSet rs, int rowNum) throws SQLException {
                        String javaType = rs.getString("class");
                        Long identifier = new Long(rs.getLong("obj_id"));

                        return new ObjectIdentityImpl(javaType, identifier);
                    }
                });

        if (objects.size() == 0) {
            return null;
        }

        return objects;
    }

    public Acl readAclById(ObjectIdentity object, List<Sid> sids) throws NotFoundException {
        Map<ObjectIdentity, Acl> map = readAclsById(Arrays.asList(object), sids);
        Assert.isTrue(map.containsKey(object), "There should have been an Acl entry for ObjectIdentity " + object);

        return (Acl) map.get(object);
    }

    public Acl readAclById(ObjectIdentity object) throws NotFoundException {
        return readAclById(object, null);
    }

    public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects) throws NotFoundException {
        return readAclsById(objects, null);
    }

    public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) throws NotFoundException {
        Map<ObjectIdentity, Acl> result = lookupStrategy.readAclsById(objects, sids);

        // Check every requested object identity was found (throw NotFoundException if needed)
        for (int i = 0; i < objects.size(); i++) {
            if (!result.containsKey(objects.get(i))) {
                throw new NotFoundException("Unable to find ACL information for object identity '"
                    + objects.get(i) + "'");
            }
        }

        return result;
    }
}
