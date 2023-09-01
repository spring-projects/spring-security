package org.springframework.security.oauth2.core;


import org.springframework.security.authorization.AuthorityAuthorizationManager;

import java.util.Arrays;

public class ScopeAuthorizationManagerFactory {

	public static <T> AuthorityAuthorizationManager<T> hasScope(String scope) {
		return AuthorityAuthorizationManager.hasAuthority("SCOPE_" + scope);
	}

	public static <T> AuthorityAuthorizationManager<T> hasAnyScope(String... scopes) {
		String[] mappedScopes = Arrays.stream(scopes).map(s -> "SCOPE_" + s).toArray(String[]::new);
		return AuthorityAuthorizationManager.hasAnyAuthority(mappedScopes);
	}
}
