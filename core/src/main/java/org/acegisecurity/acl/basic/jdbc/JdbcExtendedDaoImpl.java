/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.acl.basic.jdbc;

import org.acegisecurity.acl.basic.AclObjectIdentity;
import org.acegisecurity.acl.basic.BasicAclEntry;
import org.acegisecurity.acl.basic.BasicAclExtendedDao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContextException;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DataRetrievalFailureException;

import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.object.MappingSqlQuery;
import org.springframework.jdbc.object.SqlUpdate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import java.util.Iterator;
import java.util.List;

import javax.sql.DataSource;


/**
 * <p>
 * Extension of the base {@link JdbcDaoImpl}, which implements {@link
 * BasicAclExtendedDao}.
 * </p>
 * 
 * <p>
 * A default database structure is assumed. This may be overridden by setting
 * the default query strings to use.
 * </p>
 * 
 * <p>
 * This implementation works with <code>String</code> based recipients and
 * {@link org.acegisecurity.acl.basic.NamedEntityObjectIdentity} only. The
 * latter can be changed by overriding {@link
 * #convertAclObjectIdentityToString(AclObjectIdentity)}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JdbcExtendedDaoImpl extends JdbcDaoImpl
    implements BasicAclExtendedDao {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(JdbcExtendedDaoImpl.class);
    public static final String DEF_ACL_OBJECT_IDENTITY_DELETE_STATEMENT = "DELETE FROM acl_object_identity WHERE id = ?";
    public static final String DEF_ACL_OBJECT_IDENTITY_INSERT_STATEMENT = "INSERT INTO acl_object_identity (object_identity, parent_object, acl_class) VALUES (?, ?, ?)";
    public static final String DEF_ACL_PERMISSION_DELETE_STATEMENT = "DELETE FROM acl_permission WHERE acl_object_identity = ? AND recipient = ?";
    public static final String DEF_ACL_PERMISSION_INSERT_STATEMENT = "INSERT INTO acl_permission (acl_object_identity, recipient, mask) VALUES (?, ?, ?)";
    public static final String DEF_ACL_PERMISSION_UPDATE_STATEMENT = "UPDATE acl_permission SET mask = ? WHERE id = ?";
    public static final String DEF_LOOKUP_PERMISSION_ID_QUERY = "SELECT id FROM acl_permission WHERE acl_object_identity = ? AND recipient = ?";

    //~ Instance fields ========================================================

    private AclObjectIdentityDelete aclObjectIdentityDelete;
    private AclObjectIdentityInsert aclObjectIdentityInsert;
    private AclPermissionDelete aclPermissionDelete;
    private AclPermissionInsert aclPermissionInsert;
    private AclPermissionUpdate aclPermissionUpdate;
    private MappingSqlQuery lookupPermissionIdMapping;
    private String aclObjectIdentityDeleteStatement;
    private String aclObjectIdentityInsertStatement;
    private String aclPermissionDeleteStatement;
    private String aclPermissionInsertStatement;
    private String aclPermissionUpdateStatement;
    private String lookupPermissionIdQuery;

    //~ Constructors ===========================================================

    public JdbcExtendedDaoImpl() {
        aclObjectIdentityDeleteStatement = DEF_ACL_OBJECT_IDENTITY_DELETE_STATEMENT;
        aclObjectIdentityInsertStatement = DEF_ACL_OBJECT_IDENTITY_INSERT_STATEMENT;
        aclPermissionDeleteStatement = DEF_ACL_PERMISSION_DELETE_STATEMENT;
        aclPermissionInsertStatement = DEF_ACL_PERMISSION_INSERT_STATEMENT;
        aclPermissionUpdateStatement = DEF_ACL_PERMISSION_UPDATE_STATEMENT;
        lookupPermissionIdQuery = DEF_LOOKUP_PERMISSION_ID_QUERY;
    }

    //~ Methods ================================================================

    public void setAclObjectIdentityDelete(
        AclObjectIdentityDelete aclObjectIdentityDelete) {
        this.aclObjectIdentityDelete = aclObjectIdentityDelete;
    }

    public AclObjectIdentityDelete getAclObjectIdentityDelete() {
        return aclObjectIdentityDelete;
    }

    public void setAclObjectIdentityDeleteStatement(
        String aclObjectIdentityDeleteStatement) {
        this.aclObjectIdentityDeleteStatement = aclObjectIdentityDeleteStatement;
    }

    public String getAclObjectIdentityDeleteStatement() {
        return aclObjectIdentityDeleteStatement;
    }

    public void setAclObjectIdentityInsert(
        AclObjectIdentityInsert aclObjectIdentityInsert) {
        this.aclObjectIdentityInsert = aclObjectIdentityInsert;
    }

    public AclObjectIdentityInsert getAclObjectIdentityInsert() {
        return aclObjectIdentityInsert;
    }

    public void setAclObjectIdentityInsertStatement(
        String aclObjectIdentityInsertStatement) {
        this.aclObjectIdentityInsertStatement = aclObjectIdentityInsertStatement;
    }

    public String getAclObjectIdentityInsertStatement() {
        return aclObjectIdentityInsertStatement;
    }

    public void setAclPermissionDelete(AclPermissionDelete aclPermissionDelete) {
        this.aclPermissionDelete = aclPermissionDelete;
    }

    public AclPermissionDelete getAclPermissionDelete() {
        return aclPermissionDelete;
    }

    public void setAclPermissionDeleteStatement(
        String aclPermissionDeleteStatement) {
        this.aclPermissionDeleteStatement = aclPermissionDeleteStatement;
    }

    public String getAclPermissionDeleteStatement() {
        return aclPermissionDeleteStatement;
    }

    public void setAclPermissionInsert(AclPermissionInsert aclPermissionInsert) {
        this.aclPermissionInsert = aclPermissionInsert;
    }

    public AclPermissionInsert getAclPermissionInsert() {
        return aclPermissionInsert;
    }

    public void setAclPermissionInsertStatement(
        String aclPermissionInsertStatement) {
        this.aclPermissionInsertStatement = aclPermissionInsertStatement;
    }

    public String getAclPermissionInsertStatement() {
        return aclPermissionInsertStatement;
    }

    public void setAclPermissionUpdate(AclPermissionUpdate aclPermissionUpdate) {
        this.aclPermissionUpdate = aclPermissionUpdate;
    }

    public AclPermissionUpdate getAclPermissionUpdate() {
        return aclPermissionUpdate;
    }

    public void setAclPermissionUpdateStatement(
        String aclPermissionUpdateStatement) {
        this.aclPermissionUpdateStatement = aclPermissionUpdateStatement;
    }

    public String getAclPermissionUpdateStatement() {
        return aclPermissionUpdateStatement;
    }

    public void setLookupPermissionIdMapping(
        MappingSqlQuery lookupPermissionIdMapping) {
        this.lookupPermissionIdMapping = lookupPermissionIdMapping;
    }

    public MappingSqlQuery getLookupPermissionIdMapping() {
        return lookupPermissionIdMapping;
    }

    public void setLookupPermissionIdQuery(String lookupPermissionIdQuery) {
        this.lookupPermissionIdQuery = lookupPermissionIdQuery;
    }

    public String getLookupPermissionIdQuery() {
        return lookupPermissionIdQuery;
    }

    public void changeMask(AclObjectIdentity aclObjectIdentity,
        Object recipient, Integer newMask) throws DataAccessException {
        // Retrieve acl_object_identity record details
        AclDetailsHolder aclDetailsHolder = lookupAclDetailsHolder(aclObjectIdentity);

        // Retrieve applicable acl_permission.id
        long permissionId = lookupPermissionId(aclDetailsHolder.getForeignKeyId(),
                recipient.toString());

        if (permissionId == -1) {
            throw new DataRetrievalFailureException(
                "Could not locate existing acl_permission for aclObjectIdentity: "
                + aclObjectIdentity + ", recipient: " + recipient.toString());
        }

        // Change permission
        aclPermissionUpdate.update(new Long(permissionId), newMask);
    }

    public void create(BasicAclEntry basicAclEntry) throws DataAccessException {
        // Create acl_object_identity record if required
        createAclObjectIdentityIfRequired(basicAclEntry);

        // Only continue if a recipient is specifed (null recipient indicates
        // just wanted to ensure the acl_object_identity was created)
        if (basicAclEntry.getRecipient() == null) {
            return;
        }

        // Retrieve acl_object_identity record details
        AclDetailsHolder aclDetailsHolder = lookupAclDetailsHolder(basicAclEntry
                .getAclObjectIdentity());

        // Ensure there isn't an existing record for this recipient
        if (lookupPermissionId(aclDetailsHolder.getForeignKeyId(),
                basicAclEntry.getRecipient()) != -1) {
            throw new DataIntegrityViolationException(
                "This recipient already exists for this aclObjectIdentity");
        }

        // Create acl_permission
        aclPermissionInsert.insert(new Long(aclDetailsHolder.getForeignKeyId()),
            basicAclEntry.getRecipient().toString(),
            new Integer(basicAclEntry.getMask()));
    }

    public void delete(AclObjectIdentity aclObjectIdentity)
        throws DataAccessException {
        // Retrieve acl_object_identity record details
        AclDetailsHolder aclDetailsHolder = lookupAclDetailsHolder(aclObjectIdentity);

        // Retrieve all acl_permissions applying to this acl_object_identity
        Iterator acls = aclsByObjectIdentity.execute(aclDetailsHolder
                .getForeignKeyId()).iterator();

        // Delete all existing acl_permissions applying to this acl_object_identity
        while (acls.hasNext()) {
            AclDetailsHolder permission = (AclDetailsHolder) acls.next();
            delete(aclObjectIdentity, permission.getRecipient());
        }

        // Delete acl_object_identity
        aclObjectIdentityDelete.delete(new Long(
                aclDetailsHolder.getForeignKeyId()));
    }

    public void delete(AclObjectIdentity aclObjectIdentity, Object recipient)
        throws DataAccessException {
        // Retrieve acl_object_identity record details
        AclDetailsHolder aclDetailsHolder = lookupAclDetailsHolder(aclObjectIdentity);

        // Delete acl_permission
        aclPermissionDelete.delete(new Long(aclDetailsHolder.getForeignKeyId()),
            recipient.toString());
    }

    protected void initDao() throws ApplicationContextException {
        super.initDao();
        lookupPermissionIdMapping = new LookupPermissionIdMapping(getDataSource());
        aclPermissionInsert = new AclPermissionInsert(getDataSource());
        aclObjectIdentityInsert = new AclObjectIdentityInsert(getDataSource());
        aclPermissionDelete = new AclPermissionDelete(getDataSource());
        aclObjectIdentityDelete = new AclObjectIdentityDelete(getDataSource());
        aclPermissionUpdate = new AclPermissionUpdate(getDataSource());
    }

    /**
     * Convenience method that creates an acl_object_identity record if
     * required.
     *
     * @param basicAclEntry containing the <code>AclObjectIdentity</code> to
     *        create
     *
     * @throws DataAccessException
     */
    private void createAclObjectIdentityIfRequired(BasicAclEntry basicAclEntry)
        throws DataAccessException {
        String aclObjectIdentityString = convertAclObjectIdentityToString(basicAclEntry
                .getAclObjectIdentity());

        // Lookup the object's main properties from the RDBMS (guaranteed no nulls)
        List objects = objectProperties.execute(aclObjectIdentityString);

        if (objects.size() == 0) {
            if (basicAclEntry.getAclObjectParentIdentity() != null) {
                AclDetailsHolder parentDetails = lookupAclDetailsHolder(basicAclEntry
                        .getAclObjectParentIdentity());

                // Must create the acl_object_identity record
                aclObjectIdentityInsert.insert(aclObjectIdentityString,
                    new Long(parentDetails.getForeignKeyId()),
                    basicAclEntry.getClass().getName());
            } else {
                // Must create the acl_object_identity record
                aclObjectIdentityInsert.insert(aclObjectIdentityString, null,
                    basicAclEntry.getClass().getName());
            }
        }
    }

    /**
     * Convenience method that obtains a given acl_object_identity record.
     *
     * @param aclObjectIdentity to lookup
     *
     * @return details of the record
     *
     * @throws DataRetrievalFailureException if record could not be found
     */
    private AclDetailsHolder lookupAclDetailsHolder(
        AclObjectIdentity aclObjectIdentity)
        throws DataRetrievalFailureException {
        String aclObjectIdentityString = convertAclObjectIdentityToString(aclObjectIdentity);

        // Lookup the object's main properties from the RDBMS (guaranteed no nulls)
        List objects = objectProperties.execute(aclObjectIdentityString);

        if (objects.size() == 0) {
            throw new DataRetrievalFailureException(
                "aclObjectIdentity not found: " + aclObjectIdentityString);
        }

        // Should only be one record
        return (AclDetailsHolder) objects.get(0);
    }

    /**
     * Convenience method to lookup the acl_permission applying to a given
     * acl_object_identity.id and acl_permission.recipient.
     *
     * @param aclObjectIdentityId to locate
     * @param recipient to locate
     *
     * @return the acl_permission.id of the record, or -1 if not found
     *
     * @throws DataAccessException DOCUMENT ME!
     */
    private long lookupPermissionId(long aclObjectIdentityId, Object recipient)
        throws DataAccessException {
        List list = lookupPermissionIdMapping.execute(new Object[] {new Long(
                        aclObjectIdentityId), recipient});

        if (list.size() == 0) {
            return -1;
        }

        return ((Long) list.get(0)).longValue();
    }

    //~ Inner Classes ==========================================================

    protected class AclObjectIdentityDelete extends SqlUpdate {
        protected AclObjectIdentityDelete(DataSource ds) {
            super(ds, aclObjectIdentityDeleteStatement);
            declareParameter(new SqlParameter(Types.BIGINT));
            compile();
        }

        protected void delete(Long aclObjectIdentity)
            throws DataAccessException {
            super.update(aclObjectIdentity.intValue());
        }
    }

    protected class AclObjectIdentityInsert extends SqlUpdate {
        protected AclObjectIdentityInsert(DataSource ds) {
            super(ds, aclObjectIdentityInsertStatement);
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.BIGINT));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected void insert(String objectIdentity,
            Long parentAclObjectIdentity, String aclClass)
            throws DataAccessException {
            Object[] objs = new Object[] {objectIdentity, parentAclObjectIdentity, aclClass};
            super.update(objs);
        }
    }

    protected class AclPermissionDelete extends SqlUpdate {
        protected AclPermissionDelete(DataSource ds) {
            super(ds, aclPermissionDeleteStatement);
            declareParameter(new SqlParameter(Types.BIGINT));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected void delete(Long aclObjectIdentity, String recipient)
            throws DataAccessException {
            super.update(new Object[] {aclObjectIdentity, recipient});
        }
    }

    protected class AclPermissionInsert extends SqlUpdate {
        protected AclPermissionInsert(DataSource ds) {
            super(ds, aclPermissionInsertStatement);
            declareParameter(new SqlParameter(Types.BIGINT));
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.INTEGER));
            compile();
        }

        protected void insert(Long aclObjectIdentity, String recipient,
            Integer mask) throws DataAccessException {
            Object[] objs = new Object[] {aclObjectIdentity, recipient, mask};
            super.update(objs);
        }
    }

    protected class AclPermissionUpdate extends SqlUpdate {
        protected AclPermissionUpdate(DataSource ds) {
            super(ds, aclPermissionUpdateStatement);
            declareParameter(new SqlParameter(Types.BIGINT));
            declareParameter(new SqlParameter(Types.INTEGER));
            compile();
        }

        protected void update(Long aclPermissionId, Integer newMask)
            throws DataAccessException {
            super.update(newMask.intValue(), aclPermissionId.intValue());
        }
    }

    protected class LookupPermissionIdMapping extends MappingSqlQuery {
        protected LookupPermissionIdMapping(DataSource ds) {
            super(ds, lookupPermissionIdQuery);
            declareParameter(new SqlParameter(Types.BIGINT));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rownum)
            throws SQLException {
            return new Long(rs.getLong(1));
        }
    }
}
