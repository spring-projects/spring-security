package org.springframework.security.web.authentication.supply;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.AuthenticationType;

/**
 * This class decorates a underlying {@link AuthenticationSupplier} with common
 * logic needed for {@link AbstractAuthenticationToken}.
 *
 * @author Sergey Bespalov
 *
 * @param <T>
 */
public class AuthenticationTokenSupplier<T extends AbstractAuthenticationToken> implements AuthenticationSupplier<T> {

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private final AuthenticationSupplier<T> delegate;

	public AuthenticationTokenSupplier(AuthenticationSupplier<T> delegate) {
		super();
		this.delegate = delegate;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	@Override
	public T supply(HttpServletRequest request) throws AuthenticationException {
		T authentication = delegate.supply(request);

		Object authenticationDetails = getAuthenticationDetailsSource().buildDetails(request);
		authentication.setDetails(authenticationDetails);

		return authentication;
	}

	public AuthenticationType getAuthenticationType() {
		return delegate.getAuthenticationType();
	}

	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		delegate.commence(request, response, authException);
	}

}
