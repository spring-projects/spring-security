package org.springframework.security.access.expression;

import org.springframework.security.core.Authentication;

/**
 * Standard interface for expression root objects used with expression-based security.
 *
 * @author Andrei Stefan
 * @author Luke Taylor
 * @since 3.1.1
 */
public interface SecurityExpressionOperations {

	/**
	 * Gets the {@link Authentication} used for evaluating the expressions
	 * @return the {@link Authentication} for evaluating the expressions
	 */
	Authentication getAuthentication();

	/**
	 * Determines if the {@link #getAuthentication()} has a particular authority within
	 * {@link Authentication#getAuthorities()}.
	 * @param authority the authority to test (i.e. "ROLE_USER")
	 * @return true if the authority is found, else false
	 */
	boolean hasAuthority(String authority);

	/**
	 * Determines if the {@link #getAuthentication()} has any of the specified authorities
	 * within {@link Authentication#getAuthorities()}.
	 * @param authorities the authorities to test (i.e. "ROLE_USER", "ROLE_ADMIN")
	 * @return true if any of the authorities is found, else false
	 */
	boolean hasAnyAuthority(String... authorities);

	/**
	 * <p>
	 * Determines if the {@link #getAuthentication()} has a particular authority within
	 * {@link Authentication#getAuthorities()}.
	 * </p>
	 * <p>
	 * This is similar to {@link #hasAuthority(String)} except that this method implies
	 * that the String passed in is a role. For example, if "USER" is passed in the
	 * implementation may convert it to use "ROLE_USER" instead. The way in which the role
	 * is converted may depend on the implementation settings.
	 * </p>
	 *
	 * @param authority the authority to test (i.e. "USER")
	 * @return true if the authority is found, else false
	 */
	boolean hasRole(String role);

	/**
	 * <p>
	 * Determines if the {@link #getAuthentication()} has any of the specified authorities
	 * within {@link Authentication#getAuthorities()}.
	 * </p>
	 * <p>
	 * This is a similar to hasAnyAuthority except that this method implies
	 * that the String passed in is a role. For example, if "USER" is passed in the
	 * implementation may convert it to use "ROLE_USER" instead. The way in which the role
	 * is converted may depend on the implementation settings.
	 * </p>
	 *
	 * @param authorities the authorities to test (i.e. "USER", "ADMIN")
	 * @return true if any of the authorities is found, else false
	 */
	boolean hasAnyRole(String... roles);

	/**
	 * Always grants access.
	 * @return true
	 */
	boolean permitAll();

	/**
	 * Always denies access
	 * @return false
	 */
	boolean denyAll();

	/**
	 * Determines if the {@link #getAuthentication()} is anonymous
	 * @return true if the user is anonymous, else false
	 */
	boolean isAnonymous();

	/**
	 * Determines ifthe {@link #getAuthentication()} is authenticated
	 * @return true if the {@link #getAuthentication()} is authenticated, else false
	 */
	boolean isAuthenticated();

	/**
	 * Determines if the {@link #getAuthentication()} was authenticated using remember me
	 * @return true if the {@link #getAuthentication()} authenticated using remember me,
	 * else false
	 */
	boolean isRememberMe();

	/**
	 * Determines if the {@link #getAuthentication()} authenticated without the use of
	 * remember me
	 * @return true if the {@link #getAuthentication()} authenticated without the use of
	 * remember me, else false
	 */
	boolean isFullyAuthenticated();

	/**
	 * Determines if the {@link #getAuthentication()} has permission to access the target
	 * given the permission
	 * @param target the target domain object to check permission on
	 * @param permission the permission to check on the domain object (i.e. "read",
	 * "write", etc).
	 * @return true if permission is granted to the {@link #getAuthentication()}, else
	 * false
	 */
	boolean hasPermission(Object target, Object permission);

	/**
	 * Determines if the {@link #getAuthentication()} has permission to access the domain
	 * object with a given id, type, and permission.
	 * @param targetId the identifier of the domain object to determine access
	 * @param targetType the type (i.e. com.example.domain.Message)
	 * @param permission the perission to check on the domain object (i.e. "read",
	 * "write", etc)
	 * @return true if permission is granted to the {@link #getAuthentication()}, else
	 * false
	 */
	boolean hasPermission(Object targetId, String targetType, Object permission);

}
