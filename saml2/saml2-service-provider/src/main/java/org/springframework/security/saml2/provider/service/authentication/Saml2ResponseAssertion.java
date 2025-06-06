/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication;

import java.io.Serial;
import java.util.List;
import java.util.Map;

import org.springframework.util.Assert;

/**
 * An OpenSAML-based implementation of {@link Saml2ResponseAssertionAccessor}
 *
 * @author Josh Cummings
 * @since 7.0
 */
public class Saml2ResponseAssertion implements Saml2ResponseAssertionAccessor {

	@Serial
	private static final long serialVersionUID = -7505233045395024212L;

	private final String responseValue;

	private final String nameId;

	private final List<String> sessionIndexes;

	private final Map<String, List<Object>> attributes;

	Saml2ResponseAssertion(String responseValue, String nameId, List<String> sessionIndexes,
			Map<String, List<Object>> attributes) {
		Assert.notNull(responseValue, "response value cannot be null");
		Assert.notNull(nameId, "nameId cannot be null");
		Assert.notNull(sessionIndexes, "sessionIndexes cannot be null");
		Assert.notNull(attributes, "attributes cannot be null");
		this.responseValue = responseValue;
		this.nameId = nameId;
		this.sessionIndexes = sessionIndexes;
		this.attributes = attributes;
	}

	public static Builder withResponseValue(String responseValue) {
		return new Builder(responseValue);
	}

	@Override
	public String getNameId() {
		return this.nameId;
	}

	@Override
	public List<String> getSessionIndexes() {
		return this.sessionIndexes;
	}

	@Override
	public Map<String, List<Object>> getAttributes() {
		return this.attributes;
	}

	@Override
	public String getResponseValue() {
		return this.responseValue;
	}

	public static final class Builder {

		private final String responseValue;

		private String nameId;

		private List<String> sessionIndexes = List.of();

		private Map<String, List<Object>> attributes = Map.of();

		Builder(String responseValue) {
			this.responseValue = responseValue;
		}

		public Builder nameId(String nameId) {
			this.nameId = nameId;
			return this;
		}

		public Builder sessionIndexes(List<String> sessionIndexes) {
			this.sessionIndexes = sessionIndexes;
			return this;
		}

		public Builder attributes(Map<String, List<Object>> attributes) {
			this.attributes = attributes;
			return this;
		}

		public Saml2ResponseAssertion build() {
			return new Saml2ResponseAssertion(this.responseValue, this.nameId, this.sessionIndexes, this.attributes);
		}

	}

}
