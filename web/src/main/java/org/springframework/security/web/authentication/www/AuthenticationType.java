package org.springframework.security.web.authentication.www;

/**
 * This class represents a supported Authentication type, which can be `Basic`, `Digest` etc.
 * 
 * @author Sergey Bespalov
 * 
 * @see AuthenticationTypeParser
 */
public class AuthenticationType {

	private final String name;

	public AuthenticationType(String name) {
		if (name == null) {
			throw new NullPointerException("Authentication type name can not be null.");
		}

		this.name = name;
	}

	public String getName() {
		return name;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AuthenticationType)) {
			return false;
		}
		AuthenticationType other = (AuthenticationType) obj;
		return name.equals(other.name);
	}

	@Override
	public String toString() {
		return name;
	}

}
