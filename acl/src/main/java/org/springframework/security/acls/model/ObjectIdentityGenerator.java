/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.acls.model;

import java.io.Serializable;

/**
 * Strategy which creates an {@link ObjectIdentity} from an object identifier (such as a
 * primary key) and type information.
 * <p>
 * Differs from {@link ObjectIdentityRetrievalStrategy} in that it is used in situations
 * when the actual object instance isn't available.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface ObjectIdentityGenerator {

	/**
	 *
	 * @param id the identifier of the domain object, not null
	 * @param type the type of the object (often a class name), not null
	 * @return the identity constructed using the supplied identifier and type
	 * information.
	 */
	ObjectIdentity createObjectIdentity(Serializable id, String type);

}
