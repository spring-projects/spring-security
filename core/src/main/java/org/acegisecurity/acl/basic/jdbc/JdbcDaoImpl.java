/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.acl.basic.jdbc;

import net.sf.acegisecurity.acl.basic.AclObjectIdentity;
import net.sf.acegisecurity.acl.basic.BasicAclDao;
import net.sf.acegisecurity.acl.basic.BasicAclEntry;
import net.sf.acegisecurity.acl.basic.NamedEntityObjectIdentity;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContextException;

import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.jdbc.object.MappingSqlQuery;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.sql.DataSource;


/**
 * <p>
 * Retrieves ACL details from a JDBC location.
 * </p>
 * 
 * <p>
 * A default database structure is assumed (see {@link
 * #DEF_ACLS_BY_OBJECT_IDENTITY_QUERY}). This may be overridden by setting the
 * default query strings to use. If this does not provide enough flexibility,
 * another strategy would be to subclass this class and override the {@link
 * MappingSqlQuery} instance used, via the {@link #initMappingSqlQueries()}
 * extension point.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JdbcDaoImpl extends JdbcDaoSupport implements BasicAclDao {
    //~ Static fields/initializers =============================================

    public static final String DEF_ACLS_BY_OBJECT_IDENTITY_QUERY = "SELECT OBJECT_IDENTITY, RECIPIENT, PARENT_OBJECT_IDENTITY, MASK, ACL_CLASS FROM acls WHERE object_identity = ?";
    private static final Log logger = LogFactory.getLog(JdbcDaoSupport.class);

    //~ Instance fields ========================================================

    private MappingSqlQuery aclsByObjectIdentity;
    private String aclsByObjectIdentityQuery;

    //~ Constructors ===========================================================

    public JdbcDaoImpl() {
        aclsByObjectIdentityQuery = DEF_ACLS_BY_OBJECT_IDENTITY_QUERY;
    }

    //~ Methods ================================================================

    /**
     * Returns the ACLs associated with the requested
     * <code>AclObjectIdentity</code>.
     * 
     * <P>
     * The {@link BasicAclEntry}s returned by this method will have
     * <code>String</code>-based recipients. This will not be a problem if you
     * are using the <code>GrantedAuthorityEffectiveAclsResolver</code>, which
     * is the default configured against <code>BasicAclProvider</code>.
     * </p>
     * 
     * <P>
     * This method will only return ACLs for requests where the
     * <code>AclObjectIdentity</code> is of type {@link
     * NamedEntityObjectIdentity}. Of course, you can subclass or replace this
     * class and support your own custom <code>AclObjectIdentity</code> types.
     * </p>
     *
     * @param aclObjectIdentity for which ACL information is required (cannot
     *        be <code>null</code> and must be an instance of
     *        <code>NamedEntityObjectIdentity</code>)
     *
     * @return the ACLs that apply (without any <code>null</code>s inside the
     *         array), or <code>null</code> if not found or if an incompatible
     *         <code>AclObjectIdentity</code> was requested
     */
    public BasicAclEntry[] getAcls(AclObjectIdentity aclObjectIdentity) {
        // Ensure we can process this type of AclObjectIdentity
        if (!(aclObjectIdentity instanceof NamedEntityObjectIdentity)) {
            return null;
        }

        NamedEntityObjectIdentity neoi = (NamedEntityObjectIdentity) aclObjectIdentity;

        // Compose the String we expect to find in the RDBMS
        String aclObjectIdentityString = neoi.getClassname() + ":"
            + neoi.getId();

        // Lookup the BasicAclEntrys from RDBMS (may include null responses)
        List acls = aclsByObjectIdentity.execute(aclObjectIdentityString);

        // Now prune list of null responses (to meet interface contract)
        List toReturnAcls = new Vector();
        Iterator iter = acls.iterator();

        while (iter.hasNext()) {
            Object object = iter.next();

            if (object != null) {
                toReturnAcls.add(object);
            }
        }

        // Return null if nothing of use found (to meet interface contract)
        if (toReturnAcls.size() > 0) {
            return (BasicAclEntry[]) toReturnAcls.toArray(new BasicAclEntry[] {});
        } else {
            return null;
        }
    }

    public void setAclsByObjectIdentity(
        MappingSqlQuery aclsByObjectIdentityQuery) {
        this.aclsByObjectIdentity = aclsByObjectIdentityQuery;
    }

    public MappingSqlQuery getAclsByObjectIdentity() {
        return aclsByObjectIdentity;
    }

    /**
     * Allows the default query string used to retrieve ACLs based on object
     * identity to be overriden, if default table or column names need to be
     * changed. The default query is {@link
     * #DEF_ACLS_BY_OBJECT_IDENTITY_QUERY}; when modifying this query, ensure
     * that all returned columns are mapped back to the same column names as
     * in the default query.
     *
     * @param queryString The query string to set
     */
    public void setAclsByObjectIdentityQuery(String queryString) {
        aclsByObjectIdentityQuery = queryString;
    }

    public String getAclsByObjectIdentityQuery() {
        return aclsByObjectIdentityQuery;
    }

    protected void initDao() throws ApplicationContextException {
        initMappingSqlQueries();
    }

    /**
     * Extension point to allow other MappingSqlQuery objects to be substituted
     * in a subclass
     */
    protected void initMappingSqlQueries() {
        setAclsByObjectIdentity(new AclsByObjectIdentityMapping(getDataSource()));
    }

    //~ Inner Classes ==========================================================

    /**
     * Query object to look up ACL entries.
     * 
     * <P>
     * The executed SQL requires the following information be made available
     * from the indicated placeholders: 1. OBJECT_IDENTITY, 2. RECIPIENT, 3.
     * PARENT_OBJECT_IDENTITY, 4. MASK, and 5. ACL_CLASS
     * </p>
     */
    protected class AclsByObjectIdentityMapping extends MappingSqlQuery {
        protected AclsByObjectIdentityMapping(DataSource ds) {
            super(ds, aclsByObjectIdentityQuery);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rownum)
            throws SQLException {
            String objectIdentity = rs.getString(1);
            String recipient = rs.getString(2);
            String parentObjectIdentity = rs.getString(3);
            int mask = rs.getInt(4);
            String aclClass = rs.getString(5);

            // Try to create the indicated BasicAclEntry class
            BasicAclEntry entry;

            try {
                Class aclClazz = this.getClass().getClassLoader().loadClass(aclClass);
                entry = (BasicAclEntry) aclClazz.newInstance();
            } catch (ClassNotFoundException cnf) {
                logger.error(cnf);

                return null;
            } catch (InstantiationException ie) {
                logger.error(ie);

                return null;
            } catch (IllegalAccessException iae) {
                logger.error(iae);

                return null;
            }

            // Now set each of the ACL's properties
            entry.setAclObjectIdentity(buildIdentity(objectIdentity));
            entry.setAclObjectParentIdentity(buildIdentity(parentObjectIdentity));
            entry.setRecipient(recipient);
            entry.setMask(mask);

            if ((entry.getRecipient() == null)
                || (entry.getAclObjectIdentity() == null)) {
                // Problem with retrieval of ACL 
                // (shouldn't happen if DB schema defined NOT NULL columns)
                logger.error("recipient or aclObjectIdentity is null");

                return null;
            }

            return entry;
        }

        private AclObjectIdentity buildIdentity(String identity) {
            if (identity == null) {
                // Must be an empty parent, so return null
                return null;
            }

            int delim = identity.lastIndexOf(":");
            String classname = identity.substring(0, delim);
            String id = identity.substring(delim + 1);

            return new NamedEntityObjectIdentity(classname, id);
        }
    }
}
