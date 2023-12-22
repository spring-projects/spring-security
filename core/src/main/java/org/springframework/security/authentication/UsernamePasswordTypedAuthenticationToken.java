package org.springframework.security.authentication;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * A {@link AbstractUserDetailsAuthentication} implementation that is designed for simple
 * presentation of a username and password.
 * <p>
 *
 * @param <D> The Details Object the Token can map to.
 * @author Peter Eastham
 */
public class UsernamePasswordTypedAuthenticationToken<D> extends AbstractUserDetailsAuthentication<String, D> {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private String credentials;

	/**
	 * Creates a token based on a supplied <tt>UserDetails</tt> instance and
	 * <tt>String</tt> Object.
	 *
	 * @param principal a nonnull <tt>UserDetails</tt> for the principal.
	 * @throws IllegalArgumentException if {@code principal.getAuthorities()} is null, or
	 *                                  any Authorities in it are null.
	 */
	private UsernamePasswordTypedAuthenticationToken(UserDetails principal, String credentials, boolean authenticated) {
		super(principal);
		this.credentials = credentials;
		super.setAuthenticated(authenticated);
	}

	/**
	 * Factory method that support creation of an unauthenticated
	 * <code>UsernamePasswordTypedAuthenticationToken</code>
	 *
	 * @param principal   Nonnull UserDetails object to set to the Principal
	 * @param credentials Nullable String which represents the User's Password
	 * @param <D>         The Type assigned to the <code>TypedAuthentication::getDetails</code>
	 *                    method.
	 * @return <code>UsernamePasswordTypedAuthenticationToken</code> with false
	 * isAuthenticated() result.
	 */
	public static <D> UsernamePasswordTypedAuthenticationToken<D> unauthenticated(UserDetails principal,
			String credentials) {
		return new UsernamePasswordTypedAuthenticationToken<>(principal, credentials, false);
	}

	/**
	 * Factory method that support creation of an unauthenticated
	 * <code>UsernamePasswordTypedAuthenticationToken</code>
	 *
	 * @param principal   Nonnull UserDetails object to set to the Principal
	 * @param credentials Nullable String which represents the User's Password
	 * @param <D>         The Type assigned to the <code>TypedAuthentication::getDetails</code>
	 *                    method.
	 * @return <code>UsernamePasswordTypedAuthenticationToken</code> with true
	 * isAuthenticated() result.
	 */
	public static <D> UsernamePasswordTypedAuthenticationToken<D> authenticated(UserDetails principal,
			String credentials) {
		return new UsernamePasswordTypedAuthenticationToken<>(principal, credentials, true);
	}

	@Override
	public String getCredentials() {
		return this.credentials;
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated,
				"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		super.setAuthenticated(false);
	}

}
