package org.springframework.security.web.authentication.www;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.supply.AuthenticationSupplier;

/**
 * @author Sergey Bespalov
 *
 */
public class BasicAuthenticationSupplier extends BasicAuthenticationEntryPoint
		implements AuthenticationSupplier<UsernamePasswordAuthenticationToken> {

	public static final String AUTHENTICATION_TYPE_BASIC_NAME = "Basic";
	public static final AuthenticationType AUTHENTICATION_TYPE_BASIC = new AuthenticationType(AUTHENTICATION_TYPE_BASIC_NAME);
	
	private String credentialsCharset = "UTF-8";

	@Override
	public UsernamePasswordAuthenticationToken supply(HttpServletRequest request) throws AuthenticationException {
		String header = request.getHeader(AuthenticationTypeParser.AUTHORIZATION_HEADER_NAME);

		if (header == null || !header.contains(AUTHENTICATION_TYPE_BASIC_NAME)) {
			throw new AuthenticationCredentialsNotFoundException(
					String.format("%s authentication header required.", AUTHENTICATION_TYPE_BASIC_NAME));
		}

		byte[] base64Token = header.substring(6).getBytes();
		byte[] decoded;
		try {
			decoded = Base64.getDecoder().decode(base64Token);
		} catch (IllegalArgumentException e) {
			throw new BadCredentialsException("Failed to decode basic authentication token");
		}

		String token;
		try {
			token = new String(decoded, getCredentialsCharset(request));
		} catch (UnsupportedEncodingException e) {
			throw new InternalAuthenticationServiceException(e.getMessage(), e);
		}

		String[] tokens = token.split(":");
		if (tokens.length != 2) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}
		return new UsernamePasswordAuthenticationToken(tokens[0], tokens[1]);
	}

	private String getCredentialsCharset(HttpServletRequest request) {
		return credentialsCharset;
	}

	@Override
	public AuthenticationType getAuthenticationType() {
		return AUTHENTICATION_TYPE_BASIC;
	}

}
