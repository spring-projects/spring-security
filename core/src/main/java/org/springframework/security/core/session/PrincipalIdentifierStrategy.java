package org.springframework.security.core.session;

/**
 * Strategy for determining whether two principals represent the same identity.
 *
 * @since 7.0
 */
@FunctionalInterface
public interface PrincipalIdentifierStrategy {

	/**
	 * Returns true if the two principals should be treated as the same logical user.
	 */
	boolean matches(Object existingPrincipal, Object incomingPrincipal);

}
