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
package org.springframework.security.vote;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Iterator;

import org.springframework.security.Authentication;
import org.springframework.security.AuthorizationServiceException;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AclService;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.objectidentity.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.acls.sid.SidRetrievalStrategy;
import org.springframework.security.acls.sid.SidRetrievalStrategyImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;


/**
 * <p>
 * Given a domain object instance passed as a method argument, ensures the principal has appropriate permission
 * as indicated by the {@link AclService}.
 * <p>
 * The <tt>AclService</tt> is used to retrieve the access control list (ACL) permissions associated with a
 * domain object instance for the current <tt>Authentication</tt> object.
 * <p>
 * The voter will vote if any  {@link ConfigAttribute#getAttribute()} matches the {@link #processConfigAttribute}.
 * The provider will then locate the first method argument of type {@link #processDomainObjectClass}. Assuming that
 * method argument is non-null, the provider will then lookup the ACLs from the <code>AclManager</code> and ensure the
 * principal is {@link Acl#isGranted(org.springframework.security.acls.Permission[],
 * org.springframework.security.acls.sid.Sid[], boolean)} when presenting the {@link #requirePermission} array to that
 * method.
 * <p>
 * If the method argument is <tt>null</tt>, the voter will abstain from voting. If the method argument
 * could not be found, an {@link org.springframework.security.AuthorizationServiceException} will be thrown.
 * <p>
 * In practical terms users will typically setup a number of <tt>AclEntryVoter</tt>s. Each will have a
 * different {@link #processDomainObjectClass}, {@link #processConfigAttribute} and {@link #requirePermission}
 * combination. For example, a small application might employ the following instances of <tt>AclEntryVoter</tt>:
 *  <ul>
 *      <li>Process domain object class <code>BankAccount</code>, configuration attribute
 *      <code>VOTE_ACL_BANK_ACCONT_READ</code>, require permission <code>BasePermission.READ</code></li>
 *      <li>Process domain object class <code>BankAccount</code>, configuration attribute
 *      <code>VOTE_ACL_BANK_ACCOUNT_WRITE</code>, require permission list <code>BasePermission.WRITE</code> and
 *      <code>BasePermission.CREATE</code> (allowing the principal to have <b>either</b> of these two permissions)</li>
 *      <li>Process domain object class <code>Customer</code>, configuration attribute
 *      <code>VOTE_ACL_CUSTOMER_READ</code>, require permission <code>BasePermission.READ</code></li>
 *      <li>Process domain object class <code>Customer</code>, configuration attribute
 *      <code>VOTE_ACL_CUSTOMER_WRITE</code>, require permission list <code>BasePermission.WRITE</code> and
 *      <code>BasePermission.CREATE</code></li>
 *  </ul>
 *  Alternatively, you could have used a common superclass or interface for the {@link #processDomainObjectClass}
 * if both <code>BankAccount</code> and <code>Customer</code> had common parents.</p>
 *  <p>If the principal does not have sufficient permissions, the voter will vote to deny access.</p>
 *  <p>All comparisons and prefixes are case sensitive.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AclEntryVoter extends AbstractAclVoter {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(AclEntryVoter.class);

    //~ Instance fields ================================================================================================

    private AclService aclService;
    private ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();
    private SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();
    private String internalMethod;
    private String processConfigAttribute;
    private Permission[] requirePermission;

    //~ Constructors ===================================================================================================

    public AclEntryVoter(AclService aclService, String processConfigAttribute, Permission[] requirePermission) {
        Assert.notNull(processConfigAttribute, "A processConfigAttribute is mandatory");
        Assert.notNull(aclService, "An AclService is mandatory");

        if ((requirePermission == null) || (requirePermission.length == 0)) {
            throw new IllegalArgumentException("One or more requirePermission entries is mandatory");
        }

        this.aclService = aclService;
        this.processConfigAttribute = processConfigAttribute;
        this.requirePermission = requirePermission;
    }

    //~ Methods ========================================================================================================

    /**
     * Optionally specifies a method of the domain object that will be used to obtain a contained domain
     * object. That contained domain object will be used for the ACL evaluation. This is useful if a domain object
     * contains a parent that an ACL evaluation should be targeted for, instead of the child domain object (which
     * perhaps is being created and as such does not yet have any ACL permissions)
     *
     * @return <code>null</code> to use the domain object, or the name of a method (that requires no arguments) that
     *         should be invoked to obtain an <code>Object</code> which will be the domain object used for ACL
     *         evaluation
     */
    protected String getInternalMethod() {
        return internalMethod;
    }

    public void setInternalMethod(String internalMethod) {
        this.internalMethod = internalMethod;
    }

    protected String getProcessConfigAttribute() {
        return processConfigAttribute;
    }

    public void setObjectIdentityRetrievalStrategy(ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy) {
        Assert.notNull(objectIdentityRetrievalStrategy, "ObjectIdentityRetrievalStrategy required");
        this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
    }

    public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
        Assert.notNull(sidRetrievalStrategy, "SidRetrievalStrategy required");
        this.sidRetrievalStrategy = sidRetrievalStrategy;
    }

    public boolean supports(ConfigAttribute attribute) {
        if ((attribute.getAttribute() != null) && attribute.getAttribute().equals(getProcessConfigAttribute())) {
            return true;
        } else {
            return false;
        }
    }

    public int vote(Authentication authentication, Object object, ConfigAttributeDefinition config) {
        Iterator iter = config.getConfigAttributes().iterator();

        while (iter.hasNext()) {
            ConfigAttribute attr = (ConfigAttribute) iter.next();

            if (!this.supports(attr)) {
                continue;
            }
            // Need to make an access decision on this invocation
            // Attempt to locate the domain object instance to process
            Object domainObject = getDomainObjectInstance(object);

            // If domain object is null, vote to abstain
            if (domainObject == null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Voting to abstain - domainObject is null");
                }

                return AccessDecisionVoter.ACCESS_ABSTAIN;
            }

            // Evaluate if we are required to use an inner domain object
            if (StringUtils.hasText(internalMethod)) {
                try {
                    Class clazz = domainObject.getClass();
                    Method method = clazz.getMethod(internalMethod, new Class[0]);
                    domainObject = method.invoke(domainObject, new Object[0]);
                } catch (NoSuchMethodException nsme) {
                    throw new AuthorizationServiceException("Object of class '" + domainObject.getClass()
                        + "' does not provide the requested internalMethod: " + internalMethod);
                } catch (IllegalAccessException iae) {
                    logger.debug("IllegalAccessException", iae);

                    throw new AuthorizationServiceException("Problem invoking internalMethod: " + internalMethod
                        + " for object: " + domainObject);
                } catch (InvocationTargetException ite) {
                    logger.debug("InvocationTargetException", ite);

                    throw new AuthorizationServiceException("Problem invoking internalMethod: " + internalMethod
                        + " for object: " + domainObject);
                }
            }

            // Obtain the OID applicable to the domain object
            ObjectIdentity objectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity(domainObject);

            // Obtain the SIDs applicable to the principal
            Sid[] sids = sidRetrievalStrategy.getSids(authentication);

            Acl acl;

            try {
                // Lookup only ACLs for SIDs we're interested in
                acl = aclService.readAclById(objectIdentity, sids);
            } catch (NotFoundException nfe) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Voting to deny access - no ACLs apply for this principal");
                }

                return AccessDecisionVoter.ACCESS_DENIED;
            }

            try {
                if (acl.isGranted(requirePermission, sids, false)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Voting to grant access");
                    }

                    return AccessDecisionVoter.ACCESS_GRANTED;
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "Voting to deny access - ACLs returned, but insufficient permissions for this principal");
                    }

                    return AccessDecisionVoter.ACCESS_DENIED;
                }
            } catch (NotFoundException nfe) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Voting to deny access - no ACLs apply for this principal");
                }

                return AccessDecisionVoter.ACCESS_DENIED;
            }
        }

        // No configuration attribute matched, so abstain
        return AccessDecisionVoter.ACCESS_ABSTAIN;
    }
}
