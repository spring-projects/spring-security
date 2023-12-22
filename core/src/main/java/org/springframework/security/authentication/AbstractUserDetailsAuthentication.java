package org.springframework.security.authentication;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.TypedAuthentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.List;

/**
 * Base class for {@link TypedAuthentication} objects, where a {@link UserDetails} is the
 * Principal.
 * <p>
 * Implementations which use this class should be immutable.
 * <p>
 * Based on {@link AbstractAuthenticationToken}.
 *
 * @param <C> The type the Credentials are bound to.
 * @param <D> The type the Details are bound to.
 * @author Peter Eastham
 */
public abstract class AbstractUserDetailsAuthentication<C, D>
		implements TypedAuthentication<C, D, UserDetails>, CredentialsContainer {

	private final List<? extends GrantedAuthority> authorities;

	private final UserDetails principal;

	private D details;

	private boolean authenticated = false;

	/**
	 * Creates a token based on a supplied <tt>UserDetails</tt> Object.
	 *
	 * @param principal a nonnull <tt>UserDetails</tt> for the principal.
	 * @throws IllegalArgumentException if {@code principal.getAuthorities()} is null, or
	 *                                  any Authorities in it are null.
	 */
	public AbstractUserDetailsAuthentication(UserDetails principal) {
		Assert.notNull(principal, "Principal Provided cannot be null");
		Assert.notNull(principal.getAuthorities(), "Principal Authorities cannot be null");
		for (GrantedAuthority a : principal.getAuthorities()) {
			Assert.notNull(a, "Authorities collection cannot contain any null elements");
		}
		this.authorities = List.copyOf(principal.getAuthorities());
		this.principal = principal;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getName() {
		return getPrincipal().getUsername();
	}

	@Override
	public boolean isAuthenticated() {
		return this.authenticated;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		this.authenticated = authenticated;
	}

	@Override
	public D getDetails() {
		return this.details;
	}

	public void setDetails(D details) {
		this.details = details;
	}

	@Override
	public UserDetails getPrincipal() {
		return this.principal;
	}

	/**
	 * Checks the {@code credentials}, {@code principal} and {@code details} objects,
	 * invoking the {@code eraseCredentials} method on any which implement
	 * {@link CredentialsContainer}.
	 */
	@Override
	public void eraseCredentials() {
		eraseSecret(getCredentials());
		eraseSecret(this.principal);
		eraseSecret(this.details);
	}

	private void eraseSecret(Object secret) {
		if (secret instanceof CredentialsContainer cc) {
			cc.eraseCredentials();
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AbstractUserDetailsAuthentication<?, ?> test)) {
			return false;
		}
		if (!this.authorities.equals(test.getAuthorities())) {
			return false;
		}
		if ((this.details == null) && (test.getDetails() != null)) {
			return false;
		}
		if ((this.details != null) && (test.getDetails() == null)) {
			return false;
		}
		if ((this.details != null) && (!this.details.equals(test.getDetails()))) {
			return false;
		}
		if ((this.getCredentials() == null) && (test.getCredentials() != null)) {
			return false;
		}
		if ((this.getCredentials() != null) && !this.getCredentials().equals(test.getCredentials())) {
			return false;
		}
		if (this.getPrincipal() == null && test.getPrincipal() != null) {
			return false;
		}
		if (this.getPrincipal() != null && !this.getPrincipal().equals(test.getPrincipal())) {
			return false;
		}
		return this.isAuthenticated() == test.isAuthenticated();
	}

	@Override
	public int hashCode() {
		int code = 31;
		for (GrantedAuthority authority : this.authorities) {
			code ^= authority.hashCode();
		}
		if (this.getPrincipal() != null) {
			code ^= this.getPrincipal().hashCode();
		}
		if (this.getCredentials() != null) {
			code ^= this.getCredentials().hashCode();
		}
		if (this.getDetails() != null) {
			code ^= this.getDetails().hashCode();
		}
		if (this.isAuthenticated()) {
			code ^= -37;
		}
		return code;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getClass().getSimpleName()).append(" [");
		sb.append("Principal=").append(getPrincipal()).append(", ");
		sb.append("Credentials=[PROTECTED], ");
		sb.append("Authenticated=").append(isAuthenticated()).append(", ");
		sb.append("Details=").append(getDetails()).append(", ");
		sb.append("Granted Authorities=").append(this.authenticated);
		sb.append("]");
		return sb.toString();
	}

}
