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
package org.springframework.security.afterinvocation;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthorizationServiceException;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.acl.AclEntry;
import org.springframework.security.acl.AclManager;
import org.springframework.security.acl.basic.BasicAclEntry;
import org.springframework.security.acl.basic.SimpleAclEntry;
import org.springframework.util.Assert;


/**
 * <p>Given a <code>Collection</code> of domain object instances returned from a secure object invocation, remove
 * any <code>Collection</code> elements the principal does not have appropriate permission to access as defined by the
 * {@link AclManager}.</p>
 *  <p>The <code>AclManager</code> is used to retrieve the access control list (ACL) permissions associated with
 * each <code>Collection</code>  domain object instance element for the current <code>Authentication</code> object.
 * This class is designed to process {@link AclEntry}s that are subclasses of {@link
 * org.springframework.security.acl.basic.BasicAclEntry} only. Generally these are obtained by using the {@link
 * org.springframework.security.acl.basic.BasicAclProvider}.</p>
 *  <p>This after invocation provider will fire if any {@link ConfigAttribute#getAttribute()} matches the {@link
 * #processConfigAttribute}. The provider will then lookup the ACLs from the <code>AclManager</code> and ensure the
 * principal is {@link org.springframework.security.acl.basic.BasicAclEntry#isPermitted(int)} for at least one of the {@link
 * #requirePermission}s for each <code>Collection</code> element. If the principal does not have at least one of the
 * permissions, that element will not be included in the returned <code>Collection</code>.</p>
 *  <p>Often users will setup a <code>BasicAclEntryAfterInvocationProvider</code> with a {@link
 * #processConfigAttribute} of <code>AFTER_ACL_COLLECTION_READ</code> and a {@link #requirePermission} of
 * <code>SimpleAclEntry.READ</code>. These are also the defaults.</p>
 *  <p>The <code>AclManager</code> is allowed to return any implementations of <code>AclEntry</code> it wishes.
 * However, this provider will only be able to validate against <code>BasicAclEntry</code>s, and thus a
 * <code>Collection</code> element will be filtered from the resulting <code>Collection</code> if no
 * <code>AclEntry</code> is of type <code>BasicAclEntry</code>.</p>
 *  <p>If the provided <code>returnObject</code> is <code>null</code>, a <code>null</code><code>Collection</code>
 * will be returned. If the provided <code>returnObject</code> is not a <code>Collection</code>, an {@link
 * AuthorizationServiceException} will be thrown.</p>
 *  <p>All comparisons and prefixes are case sensitive.</p>
 *
 * @author Ben Alex
 * @author Paulo Neves
 * @version $Id$
 * @deprecated Use new spring-security-acl module instead
 */
public class BasicAclEntryAfterInvocationCollectionFilteringProvider implements AfterInvocationProvider,
    InitializingBean {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(BasicAclEntryAfterInvocationCollectionFilteringProvider.class);

    //~ Instance fields ================================================================================================

    private AclManager aclManager;
    private Class processDomainObjectClass = Object.class;
    private String processConfigAttribute = "AFTER_ACL_COLLECTION_READ";
    private int[] requirePermission = {SimpleAclEntry.READ};

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(processConfigAttribute, "A processConfigAttribute is mandatory");
        Assert.notNull(aclManager, "An aclManager is mandatory");

        if ((requirePermission == null) || (requirePermission.length == 0)) {
            throw new IllegalArgumentException("One or more requirePermission entries is mandatory");
        }
    }

    public Object decide(Authentication authentication, Object object, List<ConfigAttribute> config,
        Object returnedObject) throws AccessDeniedException {
        Iterator iter = config.iterator();

        while (iter.hasNext()) {
            ConfigAttribute attr = (ConfigAttribute) iter.next();

            if (this.supports(attr)) {
                // Need to process the Collection for this invocation
                if (returnedObject == null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Return object is null, skipping");
                    }

                    return null;
                }

                Filterer filterer = null;

                if (returnedObject instanceof Collection) {
                    Collection collection = (Collection) returnedObject;
                    filterer = new CollectionFilterer(collection);
                } else if (returnedObject.getClass().isArray()) {
                    Object[] array = (Object[]) returnedObject;
                    filterer = new ArrayFilterer(array);
                } else {
                    throw new AuthorizationServiceException("A Collection or an array (or null) was required as the "
                            + "returnedObject, but the returnedObject was: " + returnedObject);
                }

                // Locate unauthorised Collection elements
                Iterator collectionIter = filterer.iterator();

                while (collectionIter.hasNext()) {
                    Object domainObject = collectionIter.next();

                    boolean hasPermission = false;

                    if (domainObject == null) {
                        hasPermission = true;
                    } else if (!processDomainObjectClass.isAssignableFrom(domainObject.getClass())) {
                        hasPermission = true;
                    } else {
                        AclEntry[] acls = aclManager.getAcls(domainObject, authentication);

                        if ((acls != null) && (acls.length != 0)) {
                            for (int i = 0; i < acls.length; i++) {
                                // Locate processable AclEntrys
                                if (acls[i] instanceof BasicAclEntry) {
                                    BasicAclEntry processableAcl = (BasicAclEntry) acls[i];

                                    // See if principal has any of the required permissions
                                    for (int y = 0; y < requirePermission.length; y++) {
                                        if (processableAcl.isPermitted(requirePermission[y])) {
                                            hasPermission = true;

                                            if (logger.isDebugEnabled()) {
                                                logger.debug("Principal is authorised for element: " + domainObject
                                                    + " due to ACL: " + processableAcl.toString());
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (!hasPermission) {
                            filterer.remove(domainObject);

                            if (logger.isDebugEnabled()) {
                                logger.debug("Principal is NOT authorised for element: " + domainObject);
                            }
                        }
                    }
                }

                return filterer.getFilteredObject();
            }
        }

        return returnedObject;
    }

    public AclManager getAclManager() {
        return aclManager;
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

    public void setProcessConfigAttribute(String processConfigAttribute) {
        this.processConfigAttribute = processConfigAttribute;
    }

    public void setProcessDomainObjectClass(Class processDomainObjectClass) {
        Assert.notNull(processDomainObjectClass, "processDomainObjectClass cannot be set to null");
        this.processDomainObjectClass = processDomainObjectClass;
    }

    public void setRequirePermission(int[] requirePermission) {
        this.requirePermission = requirePermission;
    }

    /**
     * Allow setting permissions with String literals instead of integers as {@link
     * #setRequirePermission(int[])}
     *
     * @param requiredPermissions permission literals
     *
     * @see SimpleAclEntry#parsePermissions(String[]) for valid values
     */
    public void setRequirePermissionFromString(String[] requiredPermissions) {
        setRequirePermission(SimpleAclEntry.parsePermissions(requiredPermissions));
    }

    public boolean supports(ConfigAttribute attribute) {
        if ((attribute.getAttribute() != null) && attribute.getAttribute().equals(getProcessConfigAttribute())) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * This implementation supports any type of class, because it does not query the presented secure object.
     *
     * @param clazz the secure object
     *
     * @return always <code>true</code>
     */
    public boolean supports(Class clazz) {
        return true;
    }
}
