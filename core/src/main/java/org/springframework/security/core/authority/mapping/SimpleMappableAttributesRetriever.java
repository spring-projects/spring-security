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
package org.springframework.security.core.authority.mapping;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * This class implements the MappableAttributesRetriever interface by just returning a
 * list of mappable attributes as previously set using the corresponding setter method.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class SimpleMappableAttributesRetriever implements MappableAttributesRetriever {

	private Set<String> mappableAttributes = null;

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.core.authority.mapping.MappableAttributesRetriever
	 * #getMappableAttributes()
	 */
	public Set<String> getMappableAttributes() {
		return this.mappableAttributes;
	}

	public void setMappableAttributes(Set<String> aMappableRoles) {
		this.mappableAttributes = new HashSet<>();
		this.mappableAttributes.addAll(aMappableRoles);
		this.mappableAttributes = Collections.unmodifiableSet(this.mappableAttributes);
	}

}
