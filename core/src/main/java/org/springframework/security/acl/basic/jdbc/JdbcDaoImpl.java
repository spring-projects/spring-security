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

package org.springframework.security.acl.basic.jdbc;

import org.springframework.security.acl.basic.AclObjectIdentity;
import org.springframework.security.acl.basic.BasicAclDao;
import org.springframework.security.acl.basic.BasicAclEntry;
import org.springframework.security.acl.basic.NamedEntityObjectIdentity;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContextException;

import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.jdbc.object.MappingSqlQuery;

import org.springframework.util.Assert;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import java.util.List;
import java.util.Vector;

import javax.sql.DataSource;


/**
 * Retrieves ACL details from a JDBC location.
 * <p>
 * A default database structure is assumed. This may be overridden by setting the default query strings to use.
 * If this does not provide enough flexibility, another strategy would be to subclass this class and override the
 * {@link MappingSqlQuery} instance used, via the {@link #initMappingSqlQueries()} extension point.
 * </p>
 * @deprecated Use new spring-security-acl module instead
 */
public class JdbcDaoImpl extends JdbcDaoSupport implements BasicAclDao {
    //~ Static fields/initializers =====================================================================================

    public static final String RECIPIENT_USED_FOR_INHERITENCE_MARKER = "___INHERITENCE_MARKER_ONLY___";
    public static final String DEF_ACLS_BY_OBJECT_IDENTITY_QUERY =
            "SELECT RECIPIENT, MASK FROM acl_permission WHERE acl_object_identity = ?";
    public static final String DEF_OBJECT_PROPERTIES_QUERY =
            "SELECT CHILD.ID, "
                + "CHILD.OBJECT_IDENTITY, "
                + "CHILD.ACL_CLASS, "
                + "PARENT.OBJECT_IDENTITY as PARENT_OBJECT_IDENTITY "
                + "FROM acl_object_identity as CHILD "
                + "LEFT OUTER JOIN acl_object_identity as PARENT ON CHILD.parent_object=PARENT.id "
                + "WHERE CHILD.object_identity = ?";
    private static final Log logger = LogFactory.getLog(JdbcDaoImpl.class);

    //~ Instance fields ================================================================================================

    protected MappingSqlQuery aclsByObjectIdentity;
    protected MappingSqlQuery objectProperties;
    private String aclsByObjectIdentityQuery;
    private String objectPropertiesQuery;

    //~ Constructors ===================================================================================================

    public JdbcDaoImpl() {
        aclsByObjectIdentityQuery = DEF_ACLS_BY_OBJECT_IDENTITY_QUERY;
        objectPropertiesQuery = DEF_OBJECT_PROPERTIES_QUERY;
    }

    //~ Methods ========================================================================================================

    /**
     * Responsible for covering a <code>AclObjectIdentity</code> to a <code>String</code> that can be located
     * in the RDBMS.
     *
     * @param aclObjectIdentity to locate
     *
     * @return the object identity as a <code>String</code>
     */
    protected String convertAclObjectIdentityToString(AclObjectIdentity aclObjectIdentity) {
        // Ensure we can process this type of AclObjectIdentity
        Assert.isInstanceOf(NamedEntityObjectIdentity.class, aclObjectIdentity,
            "Only aclObjectIdentity of type NamedEntityObjectIdentity supported (was passed: " + aclObjectIdentity
            + ")");

        NamedEntityObjectIdentity neoi = (NamedEntityObjectIdentity) aclObjectIdentity;

        // Compose the String we expect to find in the RDBMS
        return neoi.getClassname() + ":" + neoi.getId();
    }

    /**
     * Constructs an individual <code>BasicAclEntry</code> from the passed <code>AclDetailsHolder</code>s.<P>Guarantees
     * to never return <code>null</code> (exceptions are thrown in the event of any issues).</p>
     *
     * @param propertiesInformation mandatory information about which instance to create, the object identity, and the
     *        parent object identity (<code>null</code> or empty <code>String</code>s prohibited for
     *        <code>aclClass</code> and <code>aclObjectIdentity</code>
     * @param aclInformation optional information about the individual ACL record (if <code>null</code> only an
     *        "inheritence marker" instance is returned which will include a recipient of {@link
     *        #RECIPIENT_USED_FOR_INHERITENCE_MARKER} ; if not <code>null</code>, it is prohibited to present
     *        <code>null</code> or an empty <code>String</code> for <code>recipient</code>)
     *
     * @return a fully populated instance suitable for use by external objects
     *
     * @throws IllegalArgumentException if the indicated ACL class could not be created
     */
    private BasicAclEntry createBasicAclEntry(AclDetailsHolder propertiesInformation, AclDetailsHolder aclInformation) {
        BasicAclEntry entry;

        try {
            entry = (BasicAclEntry) propertiesInformation.getAclClass().newInstance();
        } catch (InstantiationException ie) {
            throw new IllegalArgumentException(ie.getMessage());
        } catch (IllegalAccessException iae) {
            throw new IllegalArgumentException(iae.getMessage());
        }

        entry.setAclObjectIdentity(propertiesInformation.getAclObjectIdentity());
        entry.setAclObjectParentIdentity(propertiesInformation.getAclObjectParentIdentity());

        if (aclInformation == null) {
            // this is an inheritence marker instance only
            entry.setMask(0);
            entry.setRecipient(RECIPIENT_USED_FOR_INHERITENCE_MARKER);
        } else {
            // this is an individual ACL entry
            entry.setMask(aclInformation.getMask());
            entry.setRecipient(aclInformation.getRecipient());
        }

        return entry;
    }

    /**
     * Returns the ACLs associated with the requested <code>AclObjectIdentity</code>.<P>The {@link
     * BasicAclEntry}s returned by this method will have <code>String</code>-based recipients. This will not be a
     * problem if you are using the <code>GrantedAuthorityEffectiveAclsResolver</code>, which is the default
     * configured against <code>BasicAclProvider</code>.</p>
     *  <P>This method will only return ACLs for requests where the <code>AclObjectIdentity</code> is of type
     * {@link NamedEntityObjectIdentity}. Of course, you can subclass or replace this class and support your own
     * custom <code>AclObjectIdentity</code> types.</p>
     *
     * @param aclObjectIdentity for which ACL information is required (cannot be <code>null</code> and must be an
     *        instance of <code>NamedEntityObjectIdentity</code>)
     *
     * @return the ACLs that apply (without any <code>null</code>s inside the array), or <code>null</code> if not found
     *         or if an incompatible <code>AclObjectIdentity</code> was requested
     */
    public BasicAclEntry[] getAcls(AclObjectIdentity aclObjectIdentity) {
        String aclObjectIdentityString;

        try {
            aclObjectIdentityString = convertAclObjectIdentityToString(aclObjectIdentity);
        } catch (IllegalArgumentException unsupported) {
            return null; // pursuant to contract described in JavaDocs above
        }

        // Lookup the object's main properties from the RDBMS (guaranteed no nulls)
        List objects = objectProperties.execute(aclObjectIdentityString);

        if (objects.size() == 0) {
            // this is an unknown object identity string
            return null;
        }

        // Cast to an object properties holder (there should only be one record)
        AclDetailsHolder propertiesInformation = (AclDetailsHolder) objects.get(0);

        // Lookup the object's ACLs from RDBMS (guaranteed no nulls)
        List acls = aclsByObjectIdentity.execute(propertiesInformation.getForeignKeyId());

        if (acls.size() == 0) {
            // return merely an inheritence marker (as we know about the object but it has no related ACLs)
            return new BasicAclEntry[] {createBasicAclEntry(propertiesInformation, null)};
        } else {
            // return the individual ACL instances
            AclDetailsHolder[] aclHolders = (AclDetailsHolder[]) acls.toArray(new AclDetailsHolder[] {});
            List toReturnAcls = new Vector();

            for (int i = 0; i < aclHolders.length; i++) {
                toReturnAcls.add(createBasicAclEntry(propertiesInformation, aclHolders[i]));
            }

            return (BasicAclEntry[]) toReturnAcls.toArray(new BasicAclEntry[] {});
        }
    }

    public MappingSqlQuery getAclsByObjectIdentity() {
        return aclsByObjectIdentity;
    }

    public String getAclsByObjectIdentityQuery() {
        return aclsByObjectIdentityQuery;
    }

    public String getObjectPropertiesQuery() {
        return objectPropertiesQuery;
    }

    protected void initDao() throws ApplicationContextException {
        initMappingSqlQueries();
    }

    /**
     * Extension point to allow other MappingSqlQuery objects to be substituted in a subclass
     */
    protected void initMappingSqlQueries() {
        setAclsByObjectIdentity(new AclsByObjectIdentityMapping(getDataSource()));
        setObjectProperties(new ObjectPropertiesMapping(getDataSource()));
    }

    public void setAclsByObjectIdentity(MappingSqlQuery aclsByObjectIdentityQuery) {
        this.aclsByObjectIdentity = aclsByObjectIdentityQuery;
    }

    /**
     * Allows the default query string used to retrieve ACLs based on object identity to be overriden, if
     * default table or column names need to be changed. The default query is {@link
     * #DEF_ACLS_BY_OBJECT_IDENTITY_QUERY}; when modifying this query, ensure that all returned columns are mapped
     * back to the same column names as in the default query.
     *
     * @param queryString The query string to set
     */
    public void setAclsByObjectIdentityQuery(String queryString) {
        aclsByObjectIdentityQuery = queryString;
    }

    public void setObjectProperties(MappingSqlQuery objectPropertiesQuery) {
        this.objectProperties = objectPropertiesQuery;
    }

    public void setObjectPropertiesQuery(String queryString) {
        objectPropertiesQuery = queryString;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Used to hold details of a domain object instance's properties, or an individual ACL entry.<P>Not all
     * properties will be set. The actual properties set will depend on which <code>MappingSqlQuery</code> creates the
     * object.</p>
     *  <P>Does not enforce <code>null</code>s or empty <code>String</code>s as this is performed by the
     * <code>MappingSqlQuery</code> objects (or preferably the backend RDBMS via schema constraints).</p>
     */
    protected final class AclDetailsHolder {
        private AclObjectIdentity aclObjectIdentity;
        private AclObjectIdentity aclObjectParentIdentity;
        private Class aclClass;
        private Object recipient;
        private int mask;
        private long foreignKeyId;

/**
         * Record details of an individual ACL entry (usually from the
         * ACL_PERMISSION table)
         *
         * @param recipient the recipient
         * @param mask the integer to be masked
         */
        public AclDetailsHolder(Object recipient, int mask) {
            this.recipient = recipient;
            this.mask = mask;
        }

/**
         * Record details of a domain object instance's properties (usually
         * from the ACL_OBJECT_IDENTITY table)
         *
         * @param foreignKeyId used by the
         *        <code>AclsByObjectIdentityMapping</code> to locate the
         *        individual ACL entries
         * @param aclObjectIdentity the object identity of the domain object
         *        instance
         * @param aclObjectParentIdentity the object identity of the domain
         *        object instance's parent
         * @param aclClass the class of which a new instance which should be
         *        created for each individual ACL entry (or an inheritence
         *        "holder" class if there are no ACL entries)
         */
        public AclDetailsHolder(long foreignKeyId, AclObjectIdentity aclObjectIdentity,
            AclObjectIdentity aclObjectParentIdentity, Class aclClass) {
            this.foreignKeyId = foreignKeyId;
            this.aclObjectIdentity = aclObjectIdentity;
            this.aclObjectParentIdentity = aclObjectParentIdentity;
            this.aclClass = aclClass;
        }

        public Class getAclClass() {
            return aclClass;
        }

        public AclObjectIdentity getAclObjectIdentity() {
            return aclObjectIdentity;
        }

        public AclObjectIdentity getAclObjectParentIdentity() {
            return aclObjectParentIdentity;
        }

        public long getForeignKeyId() {
            return foreignKeyId;
        }

        public int getMask() {
            return mask;
        }

        public Object getRecipient() {
            return recipient;
        }
    }

    /**
     * Query object to look up individual ACL entries.<P>Returns the generic <code>AclDetailsHolder</code>
     * object.</p>
     *  <P>Guarantees to never return <code>null</code> (exceptions are thrown in the event of any issues).</p>
     *  <P>The executed SQL requires the following information be made available from the indicated
     * placeholders: 1. RECIPIENT, 2. MASK.</p>
     */
    protected class AclsByObjectIdentityMapping extends MappingSqlQuery {
        protected AclsByObjectIdentityMapping(DataSource ds) {
            super(ds, aclsByObjectIdentityQuery);
            declareParameter(new SqlParameter(Types.BIGINT));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rownum)
            throws SQLException {
            String recipient = rs.getString(1);
            int mask = rs.getInt(2);
            Assert.hasText(recipient, "recipient required");

            return new AclDetailsHolder(recipient, mask);
        }
    }

    /**
     * Query object to look up properties for an object identity.<P>Returns the generic
     * <code>AclDetailsHolder</code> object.</p>
     *  <P>Guarantees to never return <code>null</code> (exceptions are thrown in the event of any issues).</p>
     *  <P>The executed SQL requires the following information be made available from the indicated
     * placeholders: 1. ID, 2. OBJECT_IDENTITY, 3. ACL_CLASS and 4. PARENT_OBJECT_IDENTITY.</p>
     */
    protected class ObjectPropertiesMapping extends MappingSqlQuery {
        protected ObjectPropertiesMapping(DataSource ds) {
            super(ds, objectPropertiesQuery);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
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

        protected Object mapRow(ResultSet rs, int rownum)
            throws SQLException {
            long id = rs.getLong(1); // required
            String objectIdentity = rs.getString(2); // required
            String aclClass = rs.getString(3); // required
            String parentObjectIdentity = rs.getString(4); // optional
            Assert.hasText(objectIdentity,
                "required DEF_OBJECT_PROPERTIES_QUERY value (objectIdentity) returned null or empty");
            Assert.hasText(aclClass, "required DEF_OBJECT_PROPERTIES_QUERY value (aclClass) returned null or empty");

            Class aclClazz;

            try {
                aclClazz = this.getClass().getClassLoader().loadClass(aclClass);
            } catch (ClassNotFoundException cnf) {
                throw new IllegalArgumentException(cnf.getMessage());
            }

            return new AclDetailsHolder(id,
                    buildIdentity(objectIdentity), buildIdentity(parentObjectIdentity), aclClazz);
        }
    }
}
