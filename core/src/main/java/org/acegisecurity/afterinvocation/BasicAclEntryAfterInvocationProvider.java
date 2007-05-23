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

package org.acegisecurity.afterinvocation;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.Authentication;
import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.ConfigAttributeDefinition;

import org.acegisecurity.acl.AclEntry;
import org.acegisecurity.acl.AclManager;
import org.acegisecurity.acl.basic.BasicAclEntry;
import org.acegisecurity.acl.basic.SimpleAclEntry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;

import org.springframework.util.Assert;

import java.util.Iterator;

/**
 * <p>Given a domain object instance returned from a secure object invocation, ensures the principal has
 * appropriate permission as defined by the {@link AclManager}.</p>
 *  <p>The <code>AclManager</code> is used to retrieve the access control list (ACL) permissions associated with a
 * domain object instance for the current <code>Authentication</code> object. This class is designed to process {@link
 * AclEntry}s that are subclasses of {@link org.acegisecurity.acl.basic.BasicAclEntry} only. Generally these are
 * obtained by using the {@link org.acegisecurity.acl.basic.BasicAclProvider}.</p>
 *  <p>This after invocation provider will fire if any  {@link ConfigAttribute#getAttribute()} matches the {@link
 * #processConfigAttribute}. The provider will then lookup the ACLs from the <code>AclManager</code> and ensure the
 * principal is {@link org.acegisecurity.acl.basic.BasicAclEntry#isPermitted(int)} for at least one of the {@link
 * #requirePermission}s.</p>
 *  <p>Often users will setup a <code>BasicAclEntryAfterInvocationProvider</code> with a {@link
 * #processConfigAttribute} of <code>AFTER_ACL_READ</code> and a {@link #requirePermission} of
 * <code>SimpleAclEntry.READ</code>. These are also the defaults.</p>
 *  <p>If the principal does not have sufficient permissions, an <code>AccessDeniedException</code> will be thrown.</p>
 *  <p>The <code>AclManager</code> is allowed to return any implementations of <code>AclEntry</code> it wishes.
 * However, this provider will only be able to validate against <code>BasicAclEntry</code>s, and thus access will be
 * denied if no <code>AclEntry</code> is of type <code>BasicAclEntry</code>.</p>
 *  <p>If the provided <code>returnObject</code> is <code>null</code>, permission will always be granted and
 * <code>null</code> will be returned.</p>
 *  <p>All comparisons and prefixes are case sensitive.</p>
 */
public class BasicAclEntryAfterInvocationProvider implements AfterInvocationProvider, InitializingBean,
    MessageSourceAware {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(BasicAclEntryAfterInvocationProvider.class);

    //~ Instance fields ================================================================================================

    private AclManager aclManager;
    private Class processDomainObjectClass = Object.class;
    protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
    private String processConfigAttribute = "AFTER_ACL_READ";
    private int[] requirePermission = {SimpleAclEntry.READ};

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(processConfigAttribute, "A processConfigAttribute is mandatory");
        Assert.notNull(aclManager, "An aclManager is mandatory");
        Assert.notNull(messages, "A message source must be set");

        if ((requirePermission == null) || (requirePermission.length == 0)) {
            throw new IllegalArgumentException("One or more requirePermission entries is mandatory");
        }
    }

    public Object decide(Authentication authentication, Object object, ConfigAttributeDefinition config,
        Object returnedObject) throws AccessDeniedException {
        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attr = (ConfigAttribute) iter.next();

            if (this.supports(attr)) {
                // Need to make an access decision on this invocation
                if (returnedObject == null) {
                    // AclManager interface contract prohibits nulls
                    // As they have permission to null/nothing, grant access
                    if (logger.isDebugEnabled()) {
                        logger.debug("Return object is null, skipping");
                    }

                    return null;
                }

                if (!processDomainObjectClass.isAssignableFrom(returnedObject.getClass())) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Return object is not applicable for this provider, skipping");
                    }

                    return null;
                }

                AclEntry[] acls = aclManager.getAcls(returnedObject, authentication);

                if ((acls == null) || (acls.length == 0)) {
                    throw new AccessDeniedException(messages.getMessage(
                            "BasicAclEntryAfterInvocationProvider.noPermission",
                            new Object[] {authentication.getName(), returnedObject},
                            "Authentication {0} has NO permissions at all to the domain object {1}", LocaleContextHolder.getLocale()));
                }

                for (int i = 0; i < acls.length; i++) {
                    // Locate processable AclEntrys
                    if (acls[i] instanceof BasicAclEntry) {
                        BasicAclEntry processableAcl = (BasicAclEntry) acls[i];

                        // See if principal has any of the required permissions
                        for (int y = 0; y < requirePermission.length; y++) {
                            if (processableAcl.isPermitted(requirePermission[y])) {
                                if (logger.isDebugEnabled()) {
                                    logger.debug("Principal DOES have permission to return object: " + returnedObject
                                        + " due to ACL: " + processableAcl.toString());
                                }

                                return returnedObject;
                            }
                        }
                    }
                }

                // No permissions match
                throw new AccessDeniedException(messages.getMessage(
                        "BasicAclEntryAfterInvocationProvider.insufficientPermission",
                        new Object[] {authentication.getName(), returnedObject},
                        "Authentication {0} has ACL permissions to the domain object, "
                        + "but not the required ACL permission to the domain object {1}", LocaleContextHolder.getLocale()));
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

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
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
     * Allow setting permissions with String literals instead of integers as {@link #setRequirePermission(int[])}
     *
     * @param requiredPermissions Permission literals
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
