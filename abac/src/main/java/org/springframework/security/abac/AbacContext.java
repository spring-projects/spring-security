/*
 * Copyright 2017-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.abac;

/**
 * Plain java bean for the ABAC (Attribute-Based Control List) content
 *
 * @author Renato Soppelsa
 * @since 5.0
 */
public class AbacContext {
	private Object subject;
	private Object resource;
	private Object action;
	private Object environment;

	public AbacContext(Object subject, Object resource, Object action, Object environment) {
		this.subject = subject;
		this.resource = resource;
		this.action = action;
		this.environment = environment;
	}


	public Object getSubject() {
		return subject;
	}

	public void setSubject(Object subject) {
		this.subject = subject;
	}

	public Object getResource() {
		return resource;
	}

	public void setResource(Object resource) {
		this.resource = resource;
	}

	public Object getAction() {
		return action;
	}

	public void setAction(Object action) {
		this.action = action;
	}

	public Object getEnvironment() {
		return environment;
	}

	public void setEnvironment(Object environment) {
		this.environment = environment;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		AbacContext that = (AbacContext) o;

		if (subject != null ? !subject.equals(that.subject) : that.subject != null) return false;
		if (resource != null ? !resource.equals(that.resource) : that.resource != null) return false;
		if (action != null ? !action.equals(that.action) : that.action != null) return false;
		return environment != null ? environment.equals(that.environment) : that.environment == null;
	}

	@Override
	public int hashCode() {
		int result = subject != null ? subject.hashCode() : 0;
		result = 31 * result + (resource != null ? resource.hashCode() : 0);
		result = 31 * result + (action != null ? action.hashCode() : 0);
		result = 31 * result + (environment != null ? environment.hashCode() : 0);
		return result;
	}
}
