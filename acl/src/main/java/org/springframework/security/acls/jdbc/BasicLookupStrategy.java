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

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.UnloadedSidException;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.GrantedAuthoritySid;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.util.FieldUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;


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

    private AclAuthorizationStrategy aclAuthorizationStrategy;
    private AclCache aclCache;
    private AuditLogger auditLogger;
    private JdbcTemplate jdbcTemplate;
    private int batchSize = 50;

    //~ Constructors ===================================================================================================

    /**
     * Constructor accepting mandatory arguments
     *
     * @param dataSource to access the database
     * @param aclCache the cache where fully-loaded elements can be stored
     * @param aclAuthorizationStrategy authorization strategy (required)
     */
    public BasicLookupStrategy(DataSource dataSource, AclCache aclCache,
        AclAuthorizationStrategy aclAuthorizationStrategy, AuditLogger auditLogger) {
        Assert.notNull(dataSource, "DataSource required");
        Assert.notNull(aclCache, "AclCache required");
        Assert.notNull(aclAuthorizationStrategy, "AclAuthorizationStrategy required");
        Assert.notNull(auditLogger, "AuditLogger required");
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.aclCache = aclCache;
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
        this.auditLogger = auditLogger;
    }

    //~ Methods ========================================================================================================

    private static String computeRepeatingSql(String repeatingSql, int requiredRepetitions) {
        Assert.isTrue(requiredRepetitions >= 1, "Must be => 1");

        String startSql = "select acl_object_identity.object_id_identity, " 
	        + "acl_entry.ace_order,  "
	        + "acl_object_identity.id as acl_id, " 
	        + "acl_object_identity.parent_object, "
	        + "acl_object_identity.entries_inheriting, " 
	        + "acl_entry.id as ace_id, "
	        + "acl_entry.mask,  "
	        + "acl_entry.granting,  "
	        + "acl_entry.audit_success, " 
	        + "acl_entry.audit_failure,  "
	        + "acl_sid.principal as ace_principal, " 
	        + "acl_sid.sid as ace_sid,  "
	        + "acli_sid.principal as acl_principal, " 
	        + "acli_sid.sid as acl_sid, "
	        + "acl_class.class " 
	        + "from acl_object_identity " 
	        + "left join acl_sid acli_sid on  acli_sid.id = acl_object_identity.owner_sid " 
	        + "left join acl_class on acl_class.id = acl_object_identity.object_id_class   "
	        + "left join acl_entry on acl_object_identity.id = acl_entry.acl_object_identity " 
	        + "left join acl_sid on acl_entry.sid = acl_sid.id  "
	        + "where ( ";

        String endSql = ") order by acl_object_identity.object_id_identity" 
        	+ " asc, acl_entry.ace_order asc";

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
        AclImpl result = new AclImpl(inputAcl.getObjectIdentity(), (Long) inputAcl.getId(), aclAuthorizationStrategy,
                auditLogger, parent, null, inputAcl.isEntriesInheriting(), inputAcl.getOwner());

        // Copy the "aces" from the input to the destination
        Field field = FieldUtils.getField(AclImpl.class, "aces");

        try {
            field.setAccessible(true);
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
        Long id = new Long(rs.getLong("acl_id"));

        // If we already have an ACL for this ID, just create the ACE
        AclImpl acl = (AclImpl) acls.get(id);

        if (acl == null) {
            // Make an AclImpl and pop it into the Map
            ObjectIdentity objectIdentity = new ObjectIdentityImpl(rs.getString("class"),
                    new Long(rs.getLong("object_id_identity")));

            Acl parentAcl = null;
            long parentAclId = rs.getLong("parent_object");

            if (parentAclId != 0) {
                parentAcl = new StubAclParent(new Long(parentAclId));
            }

            boolean entriesInheriting = rs.getBoolean("entries_inheriting");
            Sid owner;

            if (rs.getBoolean("acl_principal")) {
                owner = new PrincipalSid(rs.getString("acl_sid"));
            } else {
                owner = new GrantedAuthoritySid(rs.getString("acl_sid"));
            }

            acl = new AclImpl(objectIdentity, id, aclAuthorizationStrategy, auditLogger, parentAcl, null,
                    entriesInheriting, owner);
            acls.put(id, acl);
        }

        // Add an extra ACE to the ACL (ORDER BY maintains the ACE list order)
        // It is permissable to have no ACEs in an ACL (which is detected by a null ACE_SID)
        if (rs.getString("ace_sid") != null) {
            Long aceId = new Long(rs.getLong("ace_id"));
            Sid recipient;

            if (rs.getBoolean("ace_principal")) {
                recipient = new PrincipalSid(rs.getString("ace_sid"));
            } else {
                recipient = new GrantedAuthoritySid(rs.getString("ace_sid"));
            }

            int mask = rs.getInt("mask");
			Permission permission = convertMaskIntoPermission(mask);
            boolean granting = rs.getBoolean("granting");
            boolean auditSuccess = rs.getBoolean("audit_success");
            boolean auditFailure = rs.getBoolean("audit_failure");

            AccessControlEntryImpl ace = new AccessControlEntryImpl(aceId, acl, recipient, permission, granting,
                    auditSuccess, auditFailure);

            Field acesField = FieldUtils.getField(AclImpl.class, "aces");
            List aces;

            try {
                acesField.setAccessible(true);
                aces = (List) acesField.get(acl);
            } catch (IllegalAccessException ex) {
                throw new IllegalStateException("Could not obtain AclImpl.ace field: cause[" + ex.getMessage() + "]");
            }

            // Add the ACE if it doesn't already exist in the ACL.aces field
            if (!aces.contains(ace)) {
                aces.add(ace);
            }
        }
    }

	protected Permission convertMaskIntoPermission(int mask) {
		return BasePermission.buildFromMask(mask);
	}

    /**
     * Looks up a batch of <code>ObjectIdentity</code>s directly from the database.<p>The caller is responsible
     * for optimization issues, such as selecting the identities to lookup, ensuring the cache doesn't contain them
     * already, and adding the returned elements to the cache etc.</p>
     *  <p>This subclass is required to return fully valid <code>Acl</code>s, including properly-configured
     * parent ACLs.</p>
     *
     * @param objectIdentities DOCUMENT ME!
     * @param sids DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    private Map lookupObjectIdentities(final ObjectIdentity[] objectIdentities, Sid[] sids) {
        Assert.notEmpty(objectIdentities, "Must provide identities to lookup");

        final Map acls = new HashMap(); // contains Acls with StubAclParents

        // Make the "acls" map contain all requested objectIdentities
        // (including markers to each parent in the hierarchy)
        String sql = computeRepeatingSql("(acl_object_identity.object_id_identity = ? and acl_class.class = ?)",
                objectIdentities.length);

        Set parentsToLookup = (Set) jdbcTemplate.query(sql,
            new PreparedStatementSetter() {
                public void setValues(PreparedStatement ps)
                    throws SQLException {
                    for (int i = 0; i < objectIdentities.length; i++) {
                        // Determine prepared statement values for this iteration
                        String javaType = objectIdentities[i].getJavaType().getName();

                        // No need to check for nulls, as guaranteed non-null by ObjectIdentity.getIdentifier() interface contract
                        String identifier = objectIdentities[i].getIdentifier().toString();
                        long id = (Long.valueOf(identifier)).longValue();

                        // Inject values
                        ps.setLong((2 * i) + 1, id);
                        ps.setString((2 * i) + 2, javaType);
                    }
                }
            }, new ProcessResultSet(acls, sids));
        
        // Lookup the parents, now that our JdbcTemplate has released the database connection (SEC-547)
        if (parentsToLookup.size() > 0) {
        	lookupPrimaryKeys(acls, parentsToLookup, sids);
        }

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
     * @param sids DOCUMENT ME!
     */
    private void lookupPrimaryKeys(final Map acls, final Set findNow, final Sid[] sids) {
        Assert.notNull(acls, "ACLs are required");
        Assert.notEmpty(findNow, "Items to find now required");

        String sql = computeRepeatingSql("(acl_object_identity.id = ?)", findNow.size());

        Set parentsToLookup = (Set) jdbcTemplate.query(sql,
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
            }, new ProcessResultSet(acls, sids));
        
        // Lookup the parents, now that our JdbcTemplate has released the database connection (SEC-547)
        if (parentsToLookup.size() > 0) {
        	lookupPrimaryKeys(acls, parentsToLookup, sids);
        }
    }

    /**
     * The main method.<p>WARNING: This implementation completely disregards the "sids" argument! Every item
     * in the cache is expected to contain all SIDs. If you have serious performance needs (eg a very large number of
     * SIDs per object identity), you'll probably want to develop a custom {@link LookupStrategy} implementation
     * instead.</p>
     *  <p>The implementation works in batch sizes specfied by {@link #batchSize}.</p>
     *
     * @param objects the identities to lookup (required)
     * @param sids the SIDs for which identities are required (ignored by this implementation)
     *
     * @return a <tt>Map</tt> where keys represent the {@link ObjectIdentity} of the located {@link Acl} and values
     *         are the located {@link Acl} (never <tt>null</tt> although some entries may be missing; this method
     *         should not throw {@link NotFoundException}, as a chain of {@link LookupStrategy}s may be used
     *         to automatically create entries if required) 
     */
    public Map readAclsById(ObjectIdentity[] objects, Sid[] sids) {
        Assert.isTrue(batchSize >= 1, "BatchSize must be >= 1");
        Assert.notEmpty(objects, "Objects to lookup required");

        // Map<ObjectIdentity,Acl>
        Map result = new HashMap(); // contains FULLY loaded Acl objects

        Set currentBatchToLoad = new HashSet(); // contains ObjectIdentitys

        for (int i = 0; i < objects.length; i++) {
        	boolean aclFound = false;

        	// Check we don't already have this ACL in the results
            if (result.containsKey(objects[i])) {
                aclFound = true;
            }

            // Check cache for the present ACL entry
            if (!aclFound) {
            	Acl acl = aclCache.getFromCache(objects[i]);
            	
                // Ensure any cached element supports all the requested SIDs
                // (they should always, as our base impl doesn't filter on SID)
                if (acl != null) {
                    if (acl.isSidLoaded(sids)) {
                        result.put(acl.getObjectIdentity(), acl);
                        aclFound = true;
                    } else {
                        throw new IllegalStateException(
                            "Error: SID-filtered element detected when implementation does not perform SID filtering "
                                    + "- have you added something to the cache manually?");
                    }
                }
            }
            
            // Load the ACL from the database
            if (!aclFound) {
                currentBatchToLoad.add(objects[i]);
            }

            // Is it time to load from JDBC the currentBatchToLoad?
            if ((currentBatchToLoad.size() == this.batchSize) || ((i + 1) == objects.length)) {
            	if (currentBatchToLoad.size() > 0) {
            		Map loadedBatch = lookupObjectIdentities((ObjectIdentity[]) currentBatchToLoad.toArray(new ObjectIdentity[] {}), sids);

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
        }

        return result;
    }

    public void setBatchSize(int batchSize) {
        this.batchSize = batchSize;
    }

    //~ Inner Classes ==================================================================================================

    private class ProcessResultSet implements ResultSetExtractor {
        private Map acls;
        private Sid[] sids;

        public ProcessResultSet(Map acls, Sid[] sids) {
            Assert.notNull(acls, "ACLs cannot be null");
            this.acls = acls;
            this.sids = sids; // can be null
        }

        /**
         * Implementation of {@link ResultSetExtractor#extractData(ResultSet)}.
         * Creates an {@link Acl} for each row in the {@link ResultSet} and
         * ensures it is in member field <tt>acls</tt>.  Any {@link Acl} with
         * a parent will have the parents id returned in a set.  The returned
         * set of ids may requires further processing.
         * @param rs The {@link ResultSet} to be processed
         * @return a list of parent IDs remaining to be looked up (may be empty, but never <tt>null</tt>)
         * @throws SQLException
         * @throws DataAccessException
         */
        public Object extractData(ResultSet rs) throws SQLException, DataAccessException {
            Set parentIdsToLookup = new HashSet(); // Set of parent_id Longs

            while (rs.next()) {
                // Convert current row into an Acl (albeit with a StubAclParent)
                convertCurrentResultIntoObject(acls, rs);

                // Figure out if this row means we need to lookup another parent
                long parentId = rs.getLong("parent_object");

                if (parentId != 0) {
                    // See if it's already in the "acls"
                    if (acls.containsKey(new Long(parentId))) {
                        continue; // skip this while iteration
                    }

                    // Now try to find it in the cache
                    MutableAcl cached = aclCache.getFromCache(new Long(parentId));

                    if ((cached == null) || !cached.isSidLoaded(sids)) {
                        parentIdsToLookup.add(new Long(parentId));
                    } else {
                        // Pop into the acls map, so our convert method doesn't
                        // need to deal with an unsynchronized AclCache
                        acls.put(cached.getId(), cached);
                    }
                }
            }

            // Return the parents left to lookup to the calller
            return parentIdsToLookup;
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

        public Sid getOwner() {
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
