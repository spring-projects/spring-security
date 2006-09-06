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

import org.acegisecurity.acls.AclService;
import org.acegisecurity.acls.NotFoundException;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.sid.Sid;

import org.springframework.jdbc.core.JdbcTemplate;

import org.springframework.util.Assert;

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
public class JdbcAclService implements AclService /*, MutableAclService */ {
    //~ Instance fields ================================================================================================

    private AclCache aclCache;
    private JdbcTemplate template;
    private LookupStrategy lookupStrategy;

    //~ Constructors ===================================================================================================

    public JdbcAclService(DataSource dataSource, AclCache aclCache, LookupStrategy lookupStrategy) {
        Assert.notNull(dataSource, "DataSource required");
        Assert.notNull(aclCache, "AclCache required");
        Assert.notNull(lookupStrategy, "LookupStrategy required");
        this.template = new JdbcTemplate(dataSource);
        this.aclCache = aclCache;
        this.lookupStrategy = lookupStrategy;
    }

    //~ Methods ========================================================================================================

    public Map readAclsById(ObjectIdentity[] objects) {
        return readAclsById(objects, null);
    }

    /**
     * Method required by interface.
     *
     * @param objects DOCUMENT ME!
     * @param sids DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws NotFoundException DOCUMENT ME!
     */
    public Map readAclsById(ObjectIdentity[] objects, Sid[] sids)
        throws NotFoundException {
        return lookupStrategy.readAclsById(objects, sids);
    }
}
