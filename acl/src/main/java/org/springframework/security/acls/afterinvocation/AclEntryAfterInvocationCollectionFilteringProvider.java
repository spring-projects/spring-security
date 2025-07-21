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

import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;

/**
 * <p>
 * Given a <code>Collection</code> of domain object instances returned from a secure
 * object invocation, remove any <code>Collection</code> elements the principal does not
 * have appropriate permission to access as defined by the {@link AclService}.
 * <p>
 * The <code>AclService</code> is used to retrieve the access control list (ACL)
 * permissions associated with each <code>Collection</code> domain object instance element
 * for the current <code>Authentication</code> object.
 * <p>
 * This after invocation provider will fire if any {@link ConfigAttribute#getAttribute()}
 * matches the {@link #processConfigAttribute}. The provider will then lookup the ACLs
 * from the <code>AclService</code> and ensure the principal is
 * {@link org.springframework.security.acls.model.Acl#isGranted(List, List, boolean)
 * Acl.isGranted()} when presenting the {@link #requirePermission} array to that method.
 * <p>
 * If the principal does not have permission, that element will not be included in the
 * returned <code>Collection</code>.
 * <p>
 * Often users will setup a <code>BasicAclEntryAfterInvocationProvider</code> with a
 * {@link #processConfigAttribute} of <code>AFTER_ACL_COLLECTION_READ</code> and a
 * {@link #requirePermission} of <code>BasePermission.READ</code>. These are also the
 * defaults.
 * <p>
 * If the provided <code>returnObject</code> is <code>null</code>, a <code>null</code>
 * <code>Collection</code> will be returned. If the provided <code>returnObject</code> is
 * not a <code>Collection</code>, an {@link AuthorizationServiceException} will be thrown.
 * <p>
 * All comparisons and prefixes are case sensitive.
 *
 * @author Ben Alex
 * @author Paulo Neves
 * @deprecated please use {@link AclPermissionEvaluator} instead. Spring Method Security
 * annotations may also prove useful, for example
 * {@code @PostFilter("hasPermission(filterObject, read)")}
 */
@Deprecated
public class AclEntryAfterInvocationCollectionFilteringProvider extends AbstractAclProvider {

	protected static final Log logger = LogFactory.getLog(AclEntryAfterInvocationCollectionFilteringProvider.class);

	public AclEntryAfterInvocationCollectionFilteringProvider(AclService aclService,
			List<Permission> requirePermission) {
		super(aclService, "AFTER_ACL_COLLECTION_READ", requirePermission);
	}

	@Override
	@SuppressWarnings("unchecked")
	public Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> config,
			Object returnedObject) throws AccessDeniedException {
		if (returnedObject == null) {
			logger.debug("Return object is null, skipping");
			return null;
		}

		for (ConfigAttribute attr : config) {
			if (!this.supports(attr)) {
				continue;
			}

			// Need to process the Collection for this invocation
			Filterer filterer = getFilterer(returnedObject);

			// Locate unauthorised Collection elements
			for (Object domainObject : filterer) {
				// Ignore nulls or entries which aren't instances of the configured domain
				// object class
				if (domainObject == null || !getProcessDomainObjectClass().isAssignableFrom(domainObject.getClass())) {
					continue;
				}
				if (!hasPermission(authentication, domainObject)) {
					filterer.remove(domainObject);
					logger.debug(LogMessage.of(() -> "Principal is NOT authorised for element: " + domainObject));
				}
			}
			return filterer.getFilteredObject();
		}
		return returnedObject;
	}

	private Filterer getFilterer(Object returnedObject) {
		if (returnedObject instanceof Collection) {
			return new CollectionFilterer((Collection) returnedObject);
		}
		if (returnedObject.getClass().isArray()) {
			return new ArrayFilterer((Object[]) returnedObject);
		}
		throw new AuthorizationServiceException("A Collection or an array (or null) was required as the "
				+ "returnedObject, but the returnedObject was: " + returnedObject);
	}

}
