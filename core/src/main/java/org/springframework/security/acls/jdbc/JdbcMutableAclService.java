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

import org.springframework.security.Authentication;

import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AlreadyExistsException;
import org.springframework.security.acls.ChildrenExistException;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.MutableAclService;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.GrantedAuthoritySid;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;

import org.springframework.security.context.SecurityContextHolder;

import org.springframework.dao.DataAccessException;

import org.springframework.jdbc.core.BatchPreparedStatementSetter;

import org.springframework.transaction.support.TransactionSynchronizationManager;

import org.springframework.util.Assert;

import java.lang.reflect.Array;

import java.sql.PreparedStatement;
import java.sql.SQLException;

import java.util.List;

import javax.sql.DataSource;


/**
 * Provides a base implementation of {@link MutableAclService}.
 *
 * @author Ben Alex
 * @author Johannes Zlattinger
 * @version $Id$
 */
public class JdbcMutableAclService extends JdbcAclService implements MutableAclService {
    //~ Instance fields ================================================================================================

    private AclCache aclCache;
    private String deleteClassByClassNameString = "DELETE FROM acl_class WHERE class=?";
    private String deleteEntryByObjectIdentityForeignKey = "DELETE FROM acl_entry WHERE acl_object_identity=?";
    private String deleteObjectIdentityByPrimaryKey = "DELETE FROM acl_object_identity WHERE id=?";
    private String identityQuery = "call identity()";
    private String insertClass = "INSERT INTO acl_class (id, class) VALUES (null, ?)";
    private String insertEntry = "INSERT INTO acl_entry "
        + "(id, acl_object_identity, ace_order, sid, mask, granting, audit_success, audit_failure)"
        + "VALUES (null, ?, ?, ?, ?, ?, ?, ?)";
    private String insertObjectIdentity = "INSERT INTO acl_object_identity "
        + "(id, object_id_class, object_id_identity, owner_sid, entries_inheriting) " + "VALUES (null, ?, ?, ?, ?)";
    private String insertSid = "INSERT INTO acl_sid (id, principal, sid) VALUES (null, ?, ?)";
    private String selectClassPrimaryKey = "SELECT id FROM acl_class WHERE class=?";
    private String selectCountObjectIdentityRowsForParticularClassNameString = "SELECT COUNT(acl_object_identity.id) "
        + "FROM acl_object_identity, acl_class WHERE acl_class.id = acl_object_identity.object_id_class and class=?";
    private String selectObjectIdentityPrimaryKey = "SELECT acl_object_identity.id FROM acl_object_identity, acl_class "
        + "WHERE acl_object_identity.object_id_class = acl_class.id and acl_class.class=? "
        + "and acl_object_identity.object_id_identity = ?";
    private String selectSidPrimaryKey = "SELECT id FROM acl_sid WHERE principal=? AND sid=?";
    private String updateObjectIdentity = "UPDATE acl_object_identity SET "
        + "parent_object = ?, owner_sid = ?, entries_inheriting = ?" + " where id = ?";

    //~ Constructors ===================================================================================================

    public JdbcMutableAclService(DataSource dataSource, LookupStrategy lookupStrategy, AclCache aclCache) {
        super(dataSource, lookupStrategy);
        Assert.notNull(aclCache, "AclCache required");
        this.aclCache = aclCache;
    }

    //~ Methods ========================================================================================================

    public MutableAcl createAcl(ObjectIdentity objectIdentity)
        throws AlreadyExistsException {
        Assert.notNull(objectIdentity, "Object Identity required");

        // Check this object identity hasn't already been persisted
        if (retrieveObjectIdentityPrimaryKey(objectIdentity) != null) {
            throw new AlreadyExistsException("Object identity '" + objectIdentity + "' already exists");
        }

        // Need to retrieve the current principal, in order to know who "owns" this ACL (can be changed later on)
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        PrincipalSid sid = new PrincipalSid(auth);

        // Create the acl_object_identity row
        createObjectIdentity(objectIdentity, sid);

        // Retrieve the ACL via superclass (ensures cache registration, proper retrieval etc)
        Acl acl = readAclById(objectIdentity);
        Assert.isInstanceOf(MutableAcl.class, acl, "MutableAcl should be been returned");

        return (MutableAcl) acl;
    }

    /**
     * Creates a new row in acl_entry for every ACE defined in the passed MutableAcl object.
     *
     * @param acl containing the ACEs to insert
     */
    protected void createEntries(final MutableAcl acl) {
        jdbcTemplate.batchUpdate(insertEntry,
            new BatchPreparedStatementSetter() {
                public int getBatchSize() {
                    return acl.getEntries().length;
                }

                public void setValues(PreparedStatement stmt, int i)
                        throws SQLException {
                    AccessControlEntry entry_ = (AccessControlEntry) Array.get(acl.getEntries(), i);
                    Assert.isTrue(entry_ instanceof AccessControlEntryImpl, "Unknown ACE class");

                    AccessControlEntryImpl entry = (AccessControlEntryImpl) entry_;

                    stmt.setLong(1, ((Long) acl.getId()).longValue());
                    stmt.setInt(2, i);
                    stmt.setLong(3, createOrRetrieveSidPrimaryKey(entry.getSid(), true).longValue());
                    stmt.setInt(4, entry.getPermission().getMask());
                    stmt.setBoolean(5, entry.isGranting());
                    stmt.setBoolean(6, entry.isAuditSuccess());
                    stmt.setBoolean(7, entry.isAuditFailure());
                }
            });
    }

    /**
     * Creates an entry in the acl_object_identity table for the passed ObjectIdentity. The Sid is also
     * necessary, as acl_object_identity has defined the sid column as non-null.
     *
     * @param object to represent an acl_object_identity for
     * @param owner for the SID column (will be created if there is no acl_sid entry for this particular Sid already)
     */
    protected void createObjectIdentity(ObjectIdentity object, Sid owner) {
        Long sidId = createOrRetrieveSidPrimaryKey(owner, true);
        Long classId = createOrRetrieveClassPrimaryKey(object.getJavaType(), true);
        jdbcTemplate.update(insertObjectIdentity,
            new Object[] {classId, object.getIdentifier().toString(), sidId, new Boolean(true)});
    }

    /**
     * Retrieves the primary key from acl_class, creating a new row if needed and the allowCreate property is
     * true.
     *
     * @param clazz to find or create an entry for (this implementation uses the fully-qualified class name String)
     * @param allowCreate true if creation is permitted if not found
     *
     * @return the primary key or null if not found
     */
    protected Long createOrRetrieveClassPrimaryKey(Class clazz, boolean allowCreate) {
        List classIds = jdbcTemplate.queryForList(selectClassPrimaryKey, new Object[] {clazz.getName()}, Long.class);
        Long classId = null;

        if (classIds.isEmpty()) {
            if (allowCreate) {
                classId = null;
                jdbcTemplate.update(insertClass, new Object[] {clazz.getName()});
                Assert.isTrue(TransactionSynchronizationManager.isSynchronizationActive(),
                        "Transaction must be running");
                classId = new Long(jdbcTemplate.queryForLong(identityQuery));
            }
        } else {
            classId = (Long) classIds.iterator().next();
        }

        return classId;
    }

    /**
     * Retrieves the primary key from acl_sid, creating a new row if needed and the allowCreate property is
     * true.
     *
     * @param sid to find or create
     * @param allowCreate true if creation is permitted if not found
     *
     * @return the primary key or null if not found
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    protected Long createOrRetrieveSidPrimaryKey(Sid sid, boolean allowCreate) {
        Assert.notNull(sid, "Sid required");

        String sidName = null;
        boolean principal = true;

        if (sid instanceof PrincipalSid) {
            sidName = ((PrincipalSid) sid).getPrincipal();
        } else if (sid instanceof GrantedAuthoritySid) {
            sidName = ((GrantedAuthoritySid) sid).getGrantedAuthority();
            principal = false;
        } else {
            throw new IllegalArgumentException("Unsupported implementation of Sid");
        }

        List sidIds = jdbcTemplate.queryForList(selectSidPrimaryKey, new Object[] {new Boolean(principal), sidName},
                Long.class);
        Long sidId = null;

        if (sidIds.isEmpty()) {
            if (allowCreate) {
                sidId = null;
                jdbcTemplate.update(insertSid, new Object[] {new Boolean(principal), sidName});
                Assert.isTrue(TransactionSynchronizationManager.isSynchronizationActive(),
                        "Transaction must be running");
                sidId = new Long(jdbcTemplate.queryForLong(identityQuery));
            }
        } else {
            sidId = (Long) sidIds.iterator().next();
        }

        return sidId;
    }

    public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren)
        throws ChildrenExistException {
        Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(objectIdentity.getIdentifier(), "Object Identity doesn't provide an identifier");

        // Recursively call this method for children, or handle children if they don't want automatic recursion
        ObjectIdentity[] children = findChildren(objectIdentity);

        if (deleteChildren) {
            for (int i = 0; i < children.length; i++) {
                deleteAcl(children[i], true);
            }
        } else if (children.length > 0) {
            throw new ChildrenExistException("Cannot delete '" + objectIdentity + "' (has " + children.length
                + " children)");
        }

        // Delete this ACL's ACEs in the acl_entry table
        deleteEntries(objectIdentity);

        // Delete this ACL's acl_object_identity row
        deleteObjectIdentityAndOptionallyClass(objectIdentity);

        // Clear the cache
        aclCache.evictFromCache(objectIdentity);
    }

    /**
     * Deletes all ACEs defined in the acl_entry table belonging to the presented ObjectIdentity
     *
     * @param oid the rows in acl_entry to delete
     */
    protected void deleteEntries(ObjectIdentity oid) {
        jdbcTemplate.update(deleteEntryByObjectIdentityForeignKey,
                new Object[] {retrieveObjectIdentityPrimaryKey(oid)});
    }

    /**
     * Deletes a single row from acl_object_identity that is associated with the presented ObjectIdentity. In
     * addition, deletes the corresponding row from acl_class if there are no more entries in acl_object_identity that
     * use that particular acl_class. This keeps the acl_class table reasonably small.
     *
     * @param oid to delete the acl_object_identity (and clean up acl_class for that class name if appropriate)
     */
    protected void deleteObjectIdentityAndOptionallyClass(ObjectIdentity oid) {
        // Delete the acl_object_identity row
        jdbcTemplate.update(deleteObjectIdentityByPrimaryKey, new Object[] {retrieveObjectIdentityPrimaryKey(oid)});

        // Delete the acl_class row, assuming there are no other references to it in acl_object_identity
        Object[] className = {oid.getJavaType().getName()};
        long numObjectIdentities = jdbcTemplate.queryForLong(selectCountObjectIdentityRowsForParticularClassNameString,
                className);

        if (numObjectIdentities == 0) {
            // No more rows
            jdbcTemplate.update(deleteClassByClassNameString, className);
        }
    }

    /**
     * Retrieves the primary key from the acl_object_identity table for the passed ObjectIdentity. Unlike some
     * other methods in this implementation, this method will NOT create a row (use {@link
     * #createObjectIdentity(ObjectIdentity, Sid)} instead).
     *
     * @param oid to find
     *
     * @return the object identity or null if not found
     */
    protected Long retrieveObjectIdentityPrimaryKey(ObjectIdentity oid) {
        try {
            return new Long(jdbcTemplate.queryForLong(selectObjectIdentityPrimaryKey,
                    new Object[] {oid.getJavaType().getName(), oid.getIdentifier()}));
        } catch (DataAccessException notFound) {
            return null;
        }
    }

    /**
     * This implementation will simply delete all ACEs in the database and recreate them on each invocation of
     * this method. A more comprehensive implementation might use dirty state checking, or more likely use ORM
     * capabilities for create, update and delete operations of {@link MutableAcl}.
     *
     * @param acl DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws NotFoundException DOCUMENT ME!
     */
    public MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {
        Assert.notNull(acl.getId(), "Object Identity doesn't provide an identifier");

        // Delete this ACL's ACEs in the acl_entry table
        deleteEntries(acl.getObjectIdentity());

        // Create this ACL's ACEs in the acl_entry table
        createEntries(acl);

        // Change the mutable columns in acl_object_identity
        updateObjectIdentity(acl);

        // Clear the cache
        aclCache.evictFromCache(acl.getObjectIdentity());

        // Retrieve the ACL via superclass (ensures cache registration, proper retrieval etc)
        return (MutableAcl) super.readAclById(acl.getObjectIdentity());
    }

    /**
     * Updates an existing acl_object_identity row, with new information presented in the passed MutableAcl
     * object. Also will create an acl_sid entry if needed for the Sid that owns the MutableAcl.
     *
     * @param acl to modify (a row must already exist in acl_object_identity)
     *
     * @throws NotFoundException DOCUMENT ME!
     */
    protected void updateObjectIdentity(MutableAcl acl) {
        Long parentId = null;

        if (acl.getParentAcl() != null) {
            Assert.isInstanceOf(ObjectIdentityImpl.class, acl.getParentAcl().getObjectIdentity(),
                "Implementation only supports ObjectIdentityImpl");

            ObjectIdentityImpl oii = (ObjectIdentityImpl) acl.getParentAcl().getObjectIdentity();
            parentId = retrieveObjectIdentityPrimaryKey(oii);
        }

        Assert.notNull(acl.getOwner(), "Owner is required in this implementation");

        Long ownerSid = createOrRetrieveSidPrimaryKey(acl.getOwner(), true);
        int count = jdbcTemplate.update(updateObjectIdentity,
                new Object[] {parentId, ownerSid, new Boolean(acl.isEntriesInheriting()), acl.getId()});

        if (count != 1) {
            throw new NotFoundException("Unable to locate ACL to update");
        }
    }
}
