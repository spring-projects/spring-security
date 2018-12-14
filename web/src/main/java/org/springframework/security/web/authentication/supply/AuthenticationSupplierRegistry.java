package org.springframework.security.web.authentication.supply;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.www.AuthenticationType;

/**
 * @author Sergey Bespalov
 *
 */
public interface AuthenticationSupplierRegistry {

	public <T extends Authentication> AuthenticationSupplier<T> lookupSupplierByAuthenticationType(AuthenticationType authenticationType);

}
