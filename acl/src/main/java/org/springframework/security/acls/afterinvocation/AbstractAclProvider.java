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

package org.springframework.security.acls.afterinvocation;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.Authentication;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.AfterInvocationProvider;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AclService;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.objectidentity.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.acls.sid.SidRetrievalStrategy;
import org.springframework.security.acls.sid.SidRetrievalStrategyImpl;

import org.springframework.util.Assert;


/**
 * Abstract {@link AfterInvocationProvider} which provides commonly-used ACL-related services.
 *
 * @author Ben Alex
 * @version $Id$
  */
public abstract class AbstractAclProvider implements AfterInvocationProvider {
    //~ Instance fields ================================================================================================

    protected AclService aclService;
    protected Class<?> processDomainObjectClass = Object.class;
    protected ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();
    protected SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();
    protected String processConfigAttribute;
    protected List<Permission> requirePermission = Arrays.asList(BasePermission.READ);

    //~ Constructors ===================================================================================================

    public AbstractAclProvider(AclService aclService, String processConfigAttribute, List<Permission> requirePermission) {
        Assert.hasText(processConfigAttribute, "A processConfigAttribute is mandatory");
        Assert.notNull(aclService, "An AclService is mandatory");

        if (requirePermission == null || requirePermission.isEmpty()) {
            throw new IllegalArgumentException("One or more requirePermission entries is mandatory");
        }

        this.aclService = aclService;
        this.processConfigAttribute = processConfigAttribute;
        this.requirePermission = requirePermission;
    }

    //~ Methods ========================================================================================================

    protected Class<?> getProcessDomainObjectClass() {
        return processDomainObjectClass;
    }

    protected boolean hasPermission(Authentication authentication, Object domainObject) {
        // Obtain the OID applicable to the domain object
        ObjectIdentity objectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity(domainObject);

        // Obtain the SIDs applicable to the principal
        List<Sid> sids = sidRetrievalStrategy.getSids(authentication);

        Acl acl = null;

        try {
            // Lookup only ACLs for SIDs we're interested in
            acl = aclService.readAclById(objectIdentity, sids);

            return acl.isGranted(requirePermission, sids, false);
        } catch (NotFoundException ignore) {
            return false;
        }
    }

    public void setObjectIdentityRetrievalStrategy(ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy) {
        Assert.notNull(objectIdentityRetrievalStrategy, "ObjectIdentityRetrievalStrategy required");
        this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
    }

    protected void setProcessConfigAttribute(String processConfigAttribute) {
        Assert.hasText(processConfigAttribute, "A processConfigAttribute is mandatory");
        this.processConfigAttribute = processConfigAttribute;
    }

    public void setProcessDomainObjectClass(Class<?> processDomainObjectClass) {
        Assert.notNull(processDomainObjectClass, "processDomainObjectClass cannot be set to null");
        this.processDomainObjectClass = processDomainObjectClass;
    }

    public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
        Assert.notNull(sidRetrievalStrategy, "SidRetrievalStrategy required");
        this.sidRetrievalStrategy = sidRetrievalStrategy;
    }

    public boolean supports(ConfigAttribute attribute) {
        return processConfigAttribute.equals(attribute.getAttribute());
    }

    /**
     * This implementation supports any type of class, because it does not query the presented secure object.
     *
     * @param clazz the secure object
     *
     * @return always <code>true</code>
     */
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
