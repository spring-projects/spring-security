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

import org.acegisecurity.GrantedAuthority;

import org.acegisecurity.acls.AccessControlEntry;
import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.NotFoundException;
import org.acegisecurity.acls.Permission;
import org.acegisecurity.acls.UnloadedSidException;
import org.acegisecurity.acls.domain.AccessControlEntryImpl;
import org.acegisecurity.acls.domain.AclImpl;
import org.acegisecurity.acls.domain.BasePermission;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityImpl;
import org.acegisecurity.acls.sid.GrantedAuthoritySid;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;

import org.springframework.dao.DataAccessException;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.ResultSetExtractor;

import org.springframework.util.Assert;

import java.lang.reflect.Field;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.sql.DataSource;


/**
 * Performs lookups in a manner that is compatible with ANSI SQL.<p>NB: This implementation does attempt to provide
 * reasonably optimised lookups - within the constraints of a normalised database and standard ANSI SQL features. If
 * you are willing to sacrifice either of these constraints (eg use a particular database feature such as hierarchical
 * queries or materalized views, or reduce normalisation) you are likely to achieve better performance. In such
 * situations you will need to provide your own custom <code>LookupStrategy</code>. This class does not support
 * subclassing, as it is likely to change in future releases and therefore subclassing is unsupported.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public final class BasicLookupStrategy implements LookupStrategy {
    //~ Instance fields ================================================================================================

    private AclCache aclCache;
    private JdbcTemplate jdbcTemplate;
    private GrantedAuthority[] auths;
    private int batchSize = 50;

    //~ Constructors ===================================================================================================

/**
     * Constructor accepting mandatory arguments
     *
     * @param dataSource to access the database
     * @param aclCache the cache where fully-loaded elements can be stored
     * @param auths as per the format defined by {@link
     *        AclImpl#setAuthorities(GrantedAuthority[])} for instances
     *        created by this implementation
     */
    public BasicLookupStrategy(DataSource dataSource, AclCache aclCache, GrantedAuthority[] auths) {
        Assert.notNull(dataSource, "DataSource required");
        Assert.notNull(aclCache, "AclCache required");
        Assert.notEmpty(auths, "GrantedAuthority[] with three elements required");
        Assert.isTrue(auths.length == 3, "GrantedAuthority[] with three elements required");
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.aclCache = aclCache;
        this.auths = auths;
    }

    //~ Methods ========================================================================================================

    private static String computeRepeatingSql(String repeatingSql, int requiredRepetitions) {
        Assert.isTrue(requiredRepetitions >= 1, "Must be => 1");

        String startSql = "select ACL_OBJECT_IDENTITY.OBJECT_ID_IDENTITY, ACL_ENTRY.ACE_ORDER, "
            + "ACL_OBJECT_IDENTITY.ID as ACL_ID, " + "ACL_OBJECT_IDENTITY.PARENT_OBJECT, "
            + "ACL_OBJECT_IDENTITY,ENTRIES_INHERITING, "
            + "ACL_ENTRY.ID as ACE_ID, ACL_ENTRY.MASK, ACL_ENTRY.GRANTING, ACL_ENTRY.AUDIT_SUCCESS, ACL_ENTRY.AUDIT_FAILURE, "
            + "ACE_SID.PRINCIPAL as ACE_PRINCIPAL, ACE_SID.SID as ACE_SID, "
            + "ACL_SID.PRINCIPAL as ACL_PRINCIPAL, ACL_SID.SID as ACL_SID, " + "ACL_CLASS.CLASS "
            + "from ACL_OBJECT_IDENTITY, ACL_ENTRY, ACL_SID ACE_SID, ACL_SID ACL_SID, ACL_CLASS "
            + "where ACL_ENTRY.ACL_OBJECT_IDENTITY = ACL_OBJECT_IDENTITY.ID " + "and ACE_SID.ID = ACL_ENTRY.SID "
            + "and ACL_SID.ID = ACL_OBJECT_IDENTITY.OWNER_SID "
            + "and ACL_CLASS.ID = ACL_OBJECT_IDENTITY.OBJECT_ID_CLASS " + "and ( ";

        String endSql = ") order by ACL_ENTRY.ACL_OBJECT_IDENTITY asc, ACL_ENTRY.ACE_ORDER asc";

        StringBuffer sqlStringBuffer = new StringBuffer();
        sqlStringBuffer.append(startSql);

        for (int i = 1; i <= requiredRepetitions; i++) {
            sqlStringBuffer.append(repeatingSql);

            if (i != requiredRepetitions) {
                sqlStringBuffer.append(" or ");
            }
        }

        sqlStringBuffer.append(endSql);

        return sqlStringBuffer.toString();
    }

    /**
     * The final phase of converting the <code>Map</code> of <code>AclImpl</code> instances which contain
     * <code>StubAclParent</code>s into proper, valid <code>AclImpl</code>s with correct ACL parents.
     *
     * @param inputMap the unconverted <code>AclImpl</code>s
     * @param currentIdentity the current<code>Acl</code> that we wish to convert (this may be
     *
     * @return
     *
     * @throws IllegalStateException DOCUMENT ME!
     */
    private AclImpl convert(Map inputMap, Long currentIdentity) {
        Assert.notEmpty(inputMap, "InputMap required");
        Assert.notNull(currentIdentity, "CurrentIdentity required");

        // Retrieve this Acl from the InputMap
        Acl uncastAcl = (Acl) inputMap.get(currentIdentity);
        Assert.isInstanceOf(AclImpl.class, uncastAcl, "The inputMap contained a non-AclImpl");

        AclImpl inputAcl = (AclImpl) uncastAcl;

        Acl parent = inputAcl.getParentAcl();

        if ((parent != null) && parent instanceof StubAclParent) {
            // Lookup the parent
            StubAclParent stubAclParent = (StubAclParent) parent;
            parent = convert(inputMap, stubAclParent.getId());
        }

        // Now we have the parent (if there is one), create the true AclImpl
        AclImpl result = new AclImpl(inputAcl.getObjectIdentity(), (Long) inputAcl.getId(), parent, auths, null,
                inputAcl.isEntriesInheriting(), inputAcl.getOwner());

        // Copy the "aces" from the input to the destination
        Field field = getAccessibleField(AclImpl.class, "aces");

        try {
            field.set(result, field.get(inputAcl));
        } catch (IllegalAccessException ex) {
            throw new IllegalStateException("Could not obtain or set AclImpl.ace field");
        }

        return result;
    }

    /**
     * Accepts the current <code>ResultSet</code> row, and converts it into an <code>AclImpl</code> that
     * contains a <code>StubAclParent</code>
     *
     * @param acls the Map we should add the converted Acl to
     * @param rs the ResultSet focused on a current row
     *
     * @throws SQLException if something goes wrong converting values
     * @throws IllegalStateException DOCUMENT ME!
     */
    private void convertCurrentResultIntoObject(Map acls, ResultSet rs)
        throws SQLException {
        Long id = new Long(rs.getLong("ACL_ID"));

        // If we already have an ACL for this ID, just create the ACE
        AclImpl acl = (AclImpl) acls.get(id);

        if (acl == null) {
            // Make an AclImpl and pop it into the Map
            ObjectIdentity objectIdentity = new ObjectIdentityImpl(rs.getString("CLASS"),
                    new Long(rs.getLong("OBJECT_ID_IDENTITY")));

            Acl parentAcl = null;
            long parentAclId = rs.getLong("PARENT_OBJECT");

            if (parentAclId != 0) {
                parentAcl = new StubAclParent(new Long(parentAclId));
            }

            boolean entriesInheriting = rs.getBoolean("ENTRIES_INHERITING");
            Sid owner;

            if (rs.getBoolean("ACL_PRINCIPAL")) {
                owner = new PrincipalSid(rs.getString("ACL_SID"));
            } else {
                owner = new GrantedAuthoritySid(rs.getString("ACL_SID"));
            }

            acl = new AclImpl(objectIdentity, id, parentAcl, auths, null, entriesInheriting, owner);
            acls.put(id, acl);
        }

        // Add an extra ACE to the ACL (ORDER BY maintains the ACE list order)
        Long aceId = new Long(rs.getLong("ACE_ID"));
        Sid recipient;

        if (rs.getBoolean("ACE_PRINCIPAL")) {
            recipient = new PrincipalSid(rs.getString("ACE_SID"));
        } else {
            recipient = new GrantedAuthoritySid(rs.getString("ACE_SID"));
        }

        Permission permission = BasePermission.buildFromMask(rs.getInt("MASK"));
        boolean granting = rs.getBoolean("GRANTING");
        boolean auditSuccess = rs.getBoolean("AUDIT_SUCCESS");
        boolean auditFailure = rs.getBoolean("AUDIT_FAILURE");

        AccessControlEntryImpl ace = new AccessControlEntryImpl(aceId, acl, recipient, permission, granting,
                auditSuccess, auditFailure);

        Field acesField = getAccessibleField(AclImpl.class, "aces");
        List aces;

        try {
            aces = (List) acesField.get(acl);
        } catch (IllegalAccessException ex) {
            throw new IllegalStateException("Could not obtain AclImpl.ace field", ex);
        }

        // Add the ACE if it doesn't already exist in the ACL.aces field
        if (!aces.contains(ace)) {
            aces.add(ace);
        }
    }

    private static Field getAccessibleField(Class clazz, String protectedField) {
        Field field = null;

        try {
            field = clazz.getDeclaredField(protectedField);
        } catch (NoSuchFieldException nsf) {}

        if (field == null) {
            // Unable to locate, so try the superclass (if there is one)
            if (clazz.getSuperclass() != null) {
                getAccessibleField(clazz.getSuperclass(), protectedField);
            } else {
                throw new IllegalArgumentException("Couldn't find '" + protectedField + "' field");
            }
        }

        // We have a field, so process
        field.setAccessible(true);

        return field;
    }

    /**
     * Looks up a batch of <code>ObjectIdentity</code>s directly from the database.<p>The caller is responsible
     * for optimization issues, such as selecting the identities to lookup, ensuring the cache doesn't contain them
     * already, and adding the returned elements to the cache etc.</p>
     *  <p>This subclass is required to return fully valid <code>Acl</code>s, including properly-configured
     * parent ACLs.</p>
     *
     * @param objectIdentities DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    private Map lookupObjectIdentities(final ObjectIdentity[] objectIdentities) {
        Assert.notEmpty(objectIdentities, "Must provide identities to lookup");

        final Map acls = new HashMap(); // contains Acls with StubAclParents

        // Make the "acls" map contain all requested objectIdentities
        // (including markers to each parent in the hierarchy)
        String sql = computeRepeatingSql("(ACL_OBJECT_IDENTITY.OBJECT_ID_IDENTITY = ? and ACL_CLASS.CLASS = ?)",
                objectIdentities.length);
        System.out.println("Executing lookupObjectIdentities; length: " + objectIdentities.length);
        jdbcTemplate.query(sql,
            new PreparedStatementSetter() {
                public void setValues(PreparedStatement ps)
                    throws SQLException {
                    for (int i = 0; i < objectIdentities.length; i++) {
                        // Determine prepared statement values for this iteration
                        String javaType = objectIdentities[i].getJavaType().getName();
                        Assert.isInstanceOf(Long.class, objectIdentities[i].getIdentifier(),
                            "This class requires ObjectIdentity.getIdentifier() to be a Long");

                        long id = ((Long) objectIdentities[i].getIdentifier()).longValue();

                        // Inject values
                        ps.setLong((2 * i) + 1, id);
                        ps.setString((2 * i) + 2, javaType);
                    }
                }
            }, new ProcessResultSet(acls));

        // Finally, convert our "acls" containing StubAclParents into true Acls
        Map resultMap = new HashMap();
        Iterator iter = acls.values().iterator();

        while (iter.hasNext()) {
            Acl inputAcl = (Acl) iter.next();
            Assert.isInstanceOf(AclImpl.class, inputAcl, "Map should have contained an AclImpl");
            Assert.isInstanceOf(Long.class, ((AclImpl) inputAcl).getId(), "Acl.getId() must be Long");

            Acl result = convert(acls, (Long) ((AclImpl) inputAcl).getId());
            resultMap.put(result.getObjectIdentity(), result);
        }

        return resultMap;
    }

    /**
     * Locates the primary key IDs specified in "findNow", adding AclImpl instances with StubAclParents to the
     * "acls" Map.
     *
     * @param acls the AclImpls (with StubAclParents)
     * @param findNow Long-based primary keys to retrieve
     */
    private void lookupPrimaryKeys(final Map acls, final Set findNow) {
        Assert.notNull(acls, "ACLs are required");
        Assert.notEmpty(findNow, "Items to find now required");

        String sql = computeRepeatingSql("(ACL_OBJECT_IDENTITY.ID = ?)", findNow.size());
        System.out.println("Executing lookupPrimaryKeys; length: " + findNow.size());

        jdbcTemplate.query(sql,
            new PreparedStatementSetter() {
                public void setValues(PreparedStatement ps)
                    throws SQLException {
                    Iterator iter = findNow.iterator();
                    int i = 0;

                    while (iter.hasNext()) {
                        i++;
                        ps.setLong(i, ((Long) iter.next()).longValue());
                    }
                }
            }, new ProcessResultSet(acls));
    }

    /**
     * The main method.<p>WARNING: This implementation completely disregards the "sids" argument! Every item in
     * the cache is expected to contain all SIDs.</p>
     *  <p>The implementation works in batch sizes specfied by {@link #batchSize}.</p>
     *
     * @param objects DOCUMENT ME!
     * @param sids DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws NotFoundException DOCUMENT ME!
     * @throws IllegalStateException DOCUMENT ME!
     */
    public Map readAclsById(ObjectIdentity[] objects, Sid[] sids)
        throws NotFoundException {
        Assert.isTrue(batchSize >= 1, "BatchSize must be >= 1");
        Assert.notEmpty(objects, "Objects to lookup required");

        Map result = new HashMap(); // contains FULLY loaded Acl objects

        Set currentBatchToLoad = new HashSet(); // contains ObjectIdentitys

        for (int i = 0; i < objects.length; i++) {
            // Check we don't already have this ACL in the results
            if (result.containsKey(objects[i])) {
                continue; // already in results, so move to next element
            }

            // Check cache for the present ACL entry
            Acl acl = aclCache.getFromCache(objects[i]);

            // Ensure any cached element supports all the requested SIDs
            // (they should always, as our base impl doesn't filter on SID)
            if (acl != null) {
                if (acl.isSidLoaded(sids)) {
                    result.put(acl.getObjectIdentity(), acl);

                    continue; // now in results, so move to next element
                } else {
                    throw new IllegalStateException(
                        "Error: SID-filtered element detected when implementation does not perform SID filtering - have you added something to the cache manually?");
                }
            }

            // To get this far, we have no choice but to retrieve it via JDBC
            // (although we don't do it until we get a batch of them to load)
            currentBatchToLoad.add(objects[i]);

            // Is it time to load from JDBC the currentBatchToLoad?
            if ((currentBatchToLoad.size() == this.batchSize) || ((i + 1) == objects.length)) {
                Map loadedBatch = lookupObjectIdentities((ObjectIdentity[]) currentBatchToLoad.toArray(
                            new ObjectIdentity[] {}));

                // Add loaded batch (all elements 100% initialized) to results
                result.putAll(loadedBatch);

                // Add the loaded batch to the cache
                Iterator loadedAclIterator = loadedBatch.values().iterator();

                while (loadedAclIterator.hasNext()) {
                    aclCache.putInCache((AclImpl) loadedAclIterator.next());
                }

                currentBatchToLoad.clear();
            }
        }

        // TODO: Now we're done, check every requested object identity was found (throw NotFoundException if needed)
        return result;
    }

    public void setBatchSize(int batchSize) {
        this.batchSize = batchSize;
    }

    //~ Inner Classes ==================================================================================================

    private class ProcessResultSet implements ResultSetExtractor {
        private Map acls;

        public ProcessResultSet(Map acls) {
            Assert.notNull(acls, "ACLs cannot be null");
            this.acls = acls;
        }

        public Object extractData(ResultSet rs) throws SQLException, DataAccessException {
            Set parentIdsToLookup = new HashSet(); // Set of parent_id Longs

            while (rs.next()) {
                // Convert current row into an Acl (albeit with a StubAclParent)
                convertCurrentResultIntoObject(acls, rs);

                // Figure out if this row means we need to lookup another parent
                long parentId = rs.getLong("PARENT_OBJECT");

                if (parentId != 0) {
                    // See if its already in the "acls"
                    if (acls.containsKey(new Long(parentId))) {
                        continue; // skip this while element
                    }

                    // Now try to find it in the cache
                    Acl cached = aclCache.getFromCache(new Long(parentId));

                    if (cached == null) {
                        parentIdsToLookup.add(new Long(parentId));
                    } else {
                        // Pop into the acls map, so our convert method doesn't
                        // need to deal with an unsynchronized AclCache
                        Assert.isInstanceOf(AclImpl.class, cached, "Cached ACL must be an AclImpl");
                        acls.put(((AclImpl) cached).getId(), cached);
                    }
                }
            }

            // Lookup parents, adding Acls (with StubAclParents) to "acl" map
            if (parentIdsToLookup.size() > 0) {
                lookupPrimaryKeys(acls, parentIdsToLookup);
            }

            // Return null to meet ResultSetExtractor method contract
            return null;
        }
    }

    private class StubAclParent implements Acl {
        private Long id;

        public StubAclParent(Long id) {
            this.id = id;
        }

        public AccessControlEntry[] getEntries() {
            throw new UnsupportedOperationException("Stub only");
        }

        public Long getId() {
            return id;
        }

        public ObjectIdentity getObjectIdentity() {
            throw new UnsupportedOperationException("Stub only");
        }

        public Acl getParentAcl() {
            throw new UnsupportedOperationException("Stub only");
        }

        public boolean isEntriesInheriting() {
            throw new UnsupportedOperationException("Stub only");
        }

        public boolean isGranted(Permission[] permission, Sid[] sids, boolean administrativeMode)
            throws NotFoundException, UnloadedSidException {
            throw new UnsupportedOperationException("Stub only");
        }

        public boolean isSidLoaded(Sid[] sids) {
            throw new UnsupportedOperationException("Stub only");
        }
    }
}
