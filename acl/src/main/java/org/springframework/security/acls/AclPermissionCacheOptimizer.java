package org.springframework.security.acls;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.PermissionCacheOptimizer;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;

/**
 * Batch loads ACLs for collections of objects to allow optimised filtering.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class AclPermissionCacheOptimizer implements PermissionCacheOptimizer {
    private final Log logger = LogFactory.getLog(getClass());
    private final AclService aclService;
    private SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();
    private ObjectIdentityRetrievalStrategy oidRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();

    public AclPermissionCacheOptimizer(AclService aclService) {
        this.aclService = aclService;
    }

    public void cachePermissionsFor(Authentication authentication, Collection<?> objects) {
        List<ObjectIdentity> oidsToCache = new ArrayList<ObjectIdentity>(objects.size());

        for (Object domainObject : objects) {
            if (domainObject == null) {
                continue;
            }
            ObjectIdentity oid = oidRetrievalStrategy.getObjectIdentity(domainObject);
            oidsToCache.add(oid);
        }

        List<Sid> sids = sidRetrievalStrategy.getSids(authentication);

        if (logger.isDebugEnabled()) {
            logger.debug("Eagerly loading Acls for " + oidsToCache.size() + " objects");
        }

        aclService.readAclsById(oidsToCache, sids);
    }

    public void setObjectIdentityRetrievalStrategy(ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy) {
        this.oidRetrievalStrategy = objectIdentityRetrievalStrategy;
    }

    public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
        this.sidRetrievalStrategy = sidRetrievalStrategy;
    }
}
