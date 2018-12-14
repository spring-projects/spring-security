package org.springframework.security.web.authentication.supply;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.www.AuthenticationType;

/**
 * @author Sergey Bespalov
 *
 */
public class AuthenticationSupplierMap implements AuthenticationSupplierRegistry {

	private Map<AuthenticationType, AuthenticationSupplier<?>> authenticationSupplierMap = new ConcurrentHashMap<>();

	public AuthenticationSupplierMap(Set<AuthenticationSupplier<?>> authenticationSuppliers) {
		super();
		authenticationSuppliers.stream().forEach(s -> authenticationSupplierMap.put(s.getAuthenticationType(), s));
	}

	@Override
	public <T extends Authentication> AuthenticationSupplier<T> lookupSupplierByAuthenticationType(
			AuthenticationType authenticationType) {
		return (AuthenticationSupplier<T>) authenticationSupplierMap.get(authenticationType);
	}

}
