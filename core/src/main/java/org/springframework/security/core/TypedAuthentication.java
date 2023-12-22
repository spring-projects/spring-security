package org.springframework.security.core;

/**
 * Provided as a wrapper for {@link Authentication}
 *
 * @author Peter Eastham
 * @see Authentication
 */
public interface TypedAuthentication<C, D, P> extends Authentication {

	@Override
	C getCredentials();

	@Override
	D getDetails();

	@Override
	P getPrincipal();

}
