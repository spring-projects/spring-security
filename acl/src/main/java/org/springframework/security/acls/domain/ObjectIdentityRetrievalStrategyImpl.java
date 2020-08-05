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

package org.springframework.security.acls.domain;

import java.io.Serializable;

import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityGenerator;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;

/**
 * Basic implementation of {@link ObjectIdentityRetrievalStrategy} and
 * <tt>ObjectIdentityGenerator</tt> that uses the constructors of
 * {@link ObjectIdentityImpl} to create the {@link ObjectIdentity}.
 *
 * @author Ben Alex
 */
public class ObjectIdentityRetrievalStrategyImpl implements ObjectIdentityRetrievalStrategy, ObjectIdentityGenerator {

	// ~ Methods
	// ========================================================================================================

	public ObjectIdentity getObjectIdentity(Object domainObject) {
		return new ObjectIdentityImpl(domainObject);
	}

	public ObjectIdentity createObjectIdentity(Serializable id, String type) {
		return new ObjectIdentityImpl(type, id);
	}

}
