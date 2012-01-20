package org.springframework.security.access.expression;

public interface SecurityExpressionOperations {

	public abstract boolean hasAuthority(String authority);

	public abstract boolean hasAnyAuthority(String... authorities);

	public abstract boolean hasRole(String role);

	public abstract boolean hasAnyRole(String... roles);

	public abstract boolean permitAll();

	public abstract boolean denyAll();

	public abstract boolean isAnonymous();

	public abstract boolean isAuthenticated();

	public abstract boolean isRememberMe();

	public abstract boolean isFullyAuthenticated();

	public abstract boolean hasPermission(Object target, Object permission);

	public abstract boolean hasPermission(Object targetId, String targetType,
			Object permission);

}