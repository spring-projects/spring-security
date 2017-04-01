package org.springframework.security.abac;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.*;

public class AbacAuthenticationWrapper implements Authentication {

	private Authentication authentication;
	private Set<String> stringAuthorities;

	public AbacAuthenticationWrapper(Authentication authentication) {
		this.authentication = authentication;
		stringAuthorities = new HashSet<String>();
		for(GrantedAuthority authority: getAuthorities()) {
			stringAuthorities.add(authority.getAuthority());
		}
	}

	public Set<String> getAuths(){
		return stringAuthorities;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authentication.getAuthorities();
	}


	@Override
	public Object getCredentials() {
		return authentication.getCredentials();
	}

	@Override
	public Object getDetails() {
		return authentication.getDetails();
	}

	@Override
	public Object getPrincipal() {
		return authentication.getPrincipal();
	}

	@Override
	public boolean isAuthenticated() {
		return authentication.isAuthenticated();
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		authentication.setAuthenticated(isAuthenticated);
	}

	@Override
	public boolean equals(Object another) {
		return authentication.equals(another);
	}

	@Override
	public String toString() {
		return authentication.toString();
	}

	@Override
	public int hashCode() {
		return authentication.hashCode();
	}

	@Override
	public String getName() {
		return authentication.getName();
	}
}
