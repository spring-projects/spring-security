package org.springframework.security.web.authentication.supply;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.AuthenticationType;

/**
 * Used in {@link GenericAuthenticationFilter} to provide requested
 * {@link Authentication} object, which is further used by
 * {@link AuthenticationManager} to authenticate user.
 * 
 * @author Sergey Bespalov
 *
 * @see GenericAuthenticationFilter
 * @see AuthenticationSupplierRegistry
 */
public interface AuthenticationSupplier<T extends Authentication> extends AuthenticationEntryPoint {

	/**
	 * Supplies requested {@link Authentication}.
	 * 
	 * @param request
	 * @return
	 * @throws AuthenticationException
	 */
	T supply(HttpServletRequest request) throws AuthenticationException;

	/**
	 * Provides supported {@link AuthenticationType}. 
	 * 
	 * @return
	 */
	AuthenticationType getAuthenticationType();

}
