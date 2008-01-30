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

import org.springframework.security.Authentication;
import org.springframework.security.AuthorizationServiceException;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;

import org.springframework.security.acl.AclEntry;
import org.springframework.security.acl.AclManager;
import org.springframework.security.acl.basic.BasicAclEntry;
import org.springframework.security.acl.basic.SimpleAclEntry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import java.util.Iterator;


/**
 * <p>Given a domain object instance passed as a method argument, ensures the principal has appropriate permission
 * as defined by the {@link AclManager}.</p>
 *  <p>The <code>AclManager</code> is used to retrieve the access control list (ACL) permissions associated with a
 * domain object instance for the current <code>Authentication</code> object. This class is designed to process {@link
 * AclEntry}s that are subclasses of {@link org.springframework.security.acl.basic.BasicAclEntry} only. Generally these are
 * obtained by using the {@link org.springframework.security.acl.basic.BasicAclProvider}.</p>
 *  <p>The voter will vote if any  {@link ConfigAttribute#getAttribute()} matches the {@link
 * #processConfigAttribute}. The provider will then locate the first method argument of type {@link
 * #processDomainObjectClass}. Assuming that method argument is non-null, the provider will then lookup the ACLs from
 * the <code>AclManager</code> and ensure the principal is {@link
 * org.springframework.security.acl.basic.BasicAclEntry#isPermitted(int)} for at least one of the {@link #requirePermission}s.</p>
 *  <p>If the method argument is <code>null</code>, the voter will abstain from voting. If the method argument
 * could not be found, an {@link org.springframework.security.AuthorizationServiceException} will be thrown.</p>
 *  <p>In practical terms users will typically setup a number of <code>BasicAclEntryVoter</code>s. Each will have a
 * different {@link #processDomainObjectClass}, {@link #processConfigAttribute} and {@link #requirePermission}
 * combination. For example, a small application might employ the following instances of
 * <code>BasicAclEntryVoter</code>:
 *  <ul>
 *      <li>Process domain object class <code>BankAccount</code>, configuration attribute
 *      <code>VOTE_ACL_BANK_ACCONT_READ</code>, require permission <code>SimpleAclEntry.READ</code></li>
 *      <li>Process domain object class <code>BankAccount</code>, configuration attribute
 *      <code>VOTE_ACL_BANK_ACCOUNT_WRITE</code>, require permission list <code>SimpleAclEntry.WRITE</code> and
 *      <code>SimpleAclEntry.CREATE</code> (allowing the principal to have <b>either</b> of these two permissions</li>
 *      <li>Process domain object class <code>Customer</code>, configuration attribute
 *      <code>VOTE_ACL_CUSTOMER_READ</code>, require permission <code>SimpleAclEntry.READ</code></li>
 *      <li>Process domain object class <code>Customer</code>, configuration attribute
 *      <code>VOTE_ACL_CUSTOMER_WRITE</code>, require permission list <code>SimpleAclEntry.WRITE</code> and
 *      <code>SimpleAclEntry.CREATE</code></li>
 *  </ul>
 *  Alternatively, you could have used a common superclass or interface for the {@link #processDomainObjectClass}
 * if both <code>BankAccount</code> and <code>Customer</code> had common parents.</p>
 *  <p>If the principal does not have sufficient permissions, the voter will vote to deny access.</p>
 *  <p>The <code>AclManager</code> is allowed to return any implementations of <code>AclEntry</code> it wishes.
 * However, this provider will only be able to validate against <code>AbstractBasicAclEntry</code>s, and thus a vote
 * to deny access will be made if no <code>AclEntry</code> is of type <code>AbstractBasicAclEntry</code>.</p>
 *  <p>All comparisons and prefixes are case sensitive.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAclEntryVoter extends AbstractAclVoter implements InitializingBean {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(BasicAclEntryVoter.class);

    //~ Instance fields ================================================================================================

    private AclManager aclManager;
    private String internalMethod;
    private String processConfigAttribute;
    private int[] requirePermission;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(processConfigAttribute, "A processConfigAttribute is mandatory");
        Assert.notNull(aclManager, "An aclManager is mandatory");

        if ((requirePermission == null) || (requirePermission.length == 0)) {
            throw new IllegalArgumentException("One or more requirePermission entries is mandatory");
        }
    }

    public AclManager getAclManager() {
        return aclManager;
    }

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
    public String getInternalMethod() {
        return internalMethod;
    }

    public String getProcessConfigAttribute() {
        return processConfigAttribute;
    }

    public int[] getRequirePermission() {
        return requirePermission;
    }

    public void setAclManager(AclManager aclManager) {
        this.aclManager = aclManager;
    }

    public void setInternalMethod(String internalMethod) {
        this.internalMethod = internalMethod;
    }

    public void setProcessConfigAttribute(String processConfigAttribute) {
        this.processConfigAttribute = processConfigAttribute;
    }

    public void setRequirePermission(int[] requirePermission) {
        this.requirePermission = requirePermission;
    }

    /**
     * Allow setting permissions with String literals instead of integers as {@link #setRequirePermission(int[])}
     *
     * @param requirePermission Permission literals
     * @see SimpleAclEntry#parsePermissions(String[]) for valid values
     */
    public void setRequirePermissionFromString(String[] requirePermission) {
        setRequirePermission(SimpleAclEntry.parsePermissions(requirePermission));
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

            if (this.supports(attr)) {
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
                if ((internalMethod != null) && !"".equals(internalMethod)) {
                    try {
                        Class clazz = domainObject.getClass();
                        Method method = clazz.getMethod(internalMethod, new Class[] {});
                        domainObject = method.invoke(domainObject, new Object[] {});
                    } catch (NoSuchMethodException nsme) {
                        throw new AuthorizationServiceException("Object of class '" + domainObject.getClass()
                            + "' does not provide the requested internalMethod: " + internalMethod);
                    } catch (IllegalAccessException iae) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("IllegalAccessException", iae);

                            if (iae.getCause() != null) {
                                logger.debug("Cause: " + iae.getCause().getMessage(), iae.getCause());
                            }
                        }

                        throw new AuthorizationServiceException("Problem invoking internalMethod: " + internalMethod
                            + " for object: " + domainObject);
                    } catch (InvocationTargetException ite) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("InvocationTargetException", ite);

                            if (ite.getCause() != null) {
                                logger.debug("Cause: " + ite.getCause().getMessage(), ite.getCause());
                            }
                        }

                        throw new AuthorizationServiceException("Problem invoking internalMethod: " + internalMethod
                            + " for object: " + domainObject);
                    }
                }

                // Obtain the ACLs applicable to the domain object
                AclEntry[] acls = aclManager.getAcls(domainObject, authentication);

                // If principal has no permissions for domain object, deny
                if ((acls == null) || (acls.length == 0)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Voting to deny access - no ACLs returned for this principal");
                    }

                    return AccessDecisionVoter.ACCESS_DENIED;
                }

                // Principal has some permissions for domain object, check them
                for (int i = 0; i < acls.length; i++) {
                    // Locate processable AclEntrys
                    if (acls[i] instanceof BasicAclEntry) {
                        BasicAclEntry processableAcl = (BasicAclEntry) acls[i];

                        // See if principal has any of the required permissions
                        for (int y = 0; y < requirePermission.length; y++) {
                            if (processableAcl.isPermitted(requirePermission[y])) {
                                if (logger.isDebugEnabled()) {
                                    logger.debug("Voting to grant access");
                                }

                                return AccessDecisionVoter.ACCESS_GRANTED;
                            }
                        }
                    }
                }

                // No permissions match
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "Voting to deny access - ACLs returned, but insufficient permissions for this principal");
                }

                return AccessDecisionVoter.ACCESS_DENIED;
            }
        }

        // No configuration attribute matched, so abstain
        return AccessDecisionVoter.ACCESS_ABSTAIN;
    }
}
