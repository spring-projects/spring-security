package org.springframework.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.util.Assert;

public class GrantedAuthoritiesContainerImpl implements MutableGrantedAuthoritiesContainer {
	private List authorities;

	public void setGrantedAuthorities(GrantedAuthority[] newAuthorities) {
		this.authorities = new ArrayList(newAuthorities.length);
		authorities.addAll(Arrays.asList(newAuthorities));
	}

	public GrantedAuthority[] getGrantedAuthorities() {
		Assert.notNull(authorities, "Granted authorities have not been set");
		return (GrantedAuthority[]) authorities.toArray(new GrantedAuthority[authorities.size()]);
	}
	
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Authorities: ").append(authorities);
		return sb.toString();
	}
}
