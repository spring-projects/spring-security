package org.springframework.security.acls;

import java.io.Serializable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityGenerator;
import org.springframework.security.acls.objectidentity.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.objectidentity.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.acls.sid.SidRetrievalStrategy;
import org.springframework.security.acls.sid.SidRetrievalStrategyImpl;
import org.springframework.security.expression.PermissionEvaluator;

/**
 * Used by Spring Security's expression-based access control implementation to evaluate permissions for a particular
 * object using the ACL module. Similar in behaviour to
 * {@link org.springframework.security.vote.AclEntryVoter AclEntryVoter}.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class AclPermissionEvaluator implements PermissionEvaluator {

    private final Log logger = LogFactory.getLog(getClass());

    private AclService aclService;
    private ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();
    private ObjectIdentityGenerator objectIdentityGenerator = new ObjectIdentityRetrievalStrategyImpl();
    private SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();

    public AclPermissionEvaluator(AclService aclService) {
        this.aclService = aclService;
    }

    /**
     * Determines whether the user has the given permission(s) on the domain object using the ACL
     * configuration. If the domain object is null, returns false (this can always be overridden using a null
     * check in the expression itself).
     */
    public boolean hasPermission(Authentication authentication, Object domainObject, Object permission) {
        if (domainObject == null) {
            return false;
        }

        ObjectIdentity objectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity(domainObject);

        return checkPermission(authentication, objectIdentity, permission);
    }

    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        ObjectIdentity objectIdentity = objectIdentityGenerator.createObjectIdentity(targetId, targetType);

        return checkPermission(authentication, objectIdentity, permission);
    }

    private boolean checkPermission(Authentication authentication, ObjectIdentity oid, Object permission) {
        // Obtain the SIDs applicable to the principal
        Sid[] sids = sidRetrievalStrategy.getSids(authentication);
        Permission[] requiredPermission = resolvePermission(permission);

        try {
            // Lookup only ACLs for SIDs we're interested in
            Acl acl = aclService.readAclById(oid, sids);

            if (acl.isGranted(requiredPermission, sids, false)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Access is granted");
                }

                return true;
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Returning false - ACLs returned, but insufficient permissions for this principal");
            }

        } catch (NotFoundException nfe) {
            if (logger.isDebugEnabled()) {
                logger.debug("Returning false - no ACLs apply for this principal");
            }
        }

        return false;

    }

    // TODO: Add permission resolver/PermissionFactory rewrite
    Permission[] resolvePermission(Object permission) {
        if (permission instanceof Integer) {
            return new Permission[] {BasePermission.buildFromMask(((Integer)permission).intValue())};
        }

        if (permission instanceof Permission) {
            return new Permission[] {(Permission)permission};
        }

        if (permission instanceof Permission[]) {
            return (Permission[]) permission;
        }

        if (permission instanceof String) {
            String permString = (String)permission;
            Permission p = null;

            try {
                p = BasePermission.buildFromName(permString);
            } catch(IllegalArgumentException notfound) {
                p = BasePermission.buildFromName(permString.toUpperCase());
            }

            if (p != null) {
                return new Permission[] {p};
            }

        }
        throw new IllegalArgumentException("unsupported permission: " + permission);
    }

    public void setObjectIdentityRetrievalStrategy(ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy) {
        this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
    }

    public void setObjectIdentityGenerator(ObjectIdentityGenerator objectIdentityGenerator) {
        this.objectIdentityGenerator = objectIdentityGenerator;
    }

    public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
        this.sidRetrievalStrategy = sidRetrievalStrategy;
    }
}
