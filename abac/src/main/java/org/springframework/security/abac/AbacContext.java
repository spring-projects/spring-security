package org.springframework.security.abac;

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
