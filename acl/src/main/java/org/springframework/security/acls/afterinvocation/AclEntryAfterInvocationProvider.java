/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.acls.afterinvocation;

import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;

/**
 * Given a domain object instance returned from a secure object invocation, ensures the
 * principal has appropriate permission as defined by the {@link AclService}.
 * <p>
 * The <code>AclService</code> is used to retrieve the access control list (ACL)
 * permissions associated with a domain object instance for the current
 * <code>Authentication</code> object.
 * <p>
 * This after invocation provider will fire if any {@link ConfigAttribute#getAttribute()}
 * matches the {@link #processConfigAttribute}. The provider will then lookup the ACLs
 * from the <tt>AclService</tt> and ensure the principal is
 * {@link org.springframework.security.acls.model.Acl#isGranted(List, List, boolean)
 * Acl.isGranted(List, List, boolean)} when presenting the {@link #requirePermission}
 * array to that method.
 * <p>
 * Often users will set up an <code>AclEntryAfterInvocationProvider</code> with a
 * {@link #processConfigAttribute} of <code>AFTER_ACL_READ</code> and a
 * {@link #requirePermission} of <code>BasePermission.READ</code>. These are also the
 * defaults.
 * <p>
 * If the principal does not have sufficient permissions, an
 * <code>AccessDeniedException</code> will be thrown.
 * <p>
 * If the provided <tt>returnedObject</tt> is <code>null</code>, permission will always be
 * granted and <code>null</code> will be returned.
 * <p>
 * All comparisons and prefixes are case sensitive.
 */
public class AclEntryAfterInvocationProvider extends AbstractAclProvider implements MessageSourceAware {

	protected static final Log logger = LogFactory.getLog(AclEntryAfterInvocationProvider.class);

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	public AclEntryAfterInvocationProvider(AclService aclService, List<Permission> requirePermission) {
		this(aclService, "AFTER_ACL_READ", requirePermission);
	}

	public AclEntryAfterInvocationProvider(AclService aclService, String processConfigAttribute,
			List<Permission> requirePermission) {
		super(aclService, processConfigAttribute, requirePermission);
	}

	@Override
	public Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> config,
			Object returnedObject) throws AccessDeniedException {

		if (returnedObject == null) {
			// AclManager interface contract prohibits nulls
			// As they have permission to null/nothing, grant access
			logger.debug("Return object is null, skipping");
			return null;
		}

		if (!getProcessDomainObjectClass().isAssignableFrom(returnedObject.getClass())) {
			logger.debug("Return object is not applicable for this provider, skipping");
			return returnedObject;
		}

		for (ConfigAttribute attr : config) {
			if (!this.supports(attr)) {
				continue;
			}

			// Need to make an access decision on this invocation
			if (hasPermission(authentication, returnedObject)) {
				return returnedObject;
			}

			logger.debug("Denying access");
			throw new AccessDeniedException(this.messages.getMessage("AclEntryAfterInvocationProvider.noPermission",
					new Object[] { authentication.getName(), returnedObject },
					"Authentication {0} has NO permissions to the domain object {1}"));
		}

		return returnedObject;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

}
