package org.springframework.security.web.authentication.www;

import javax.servlet.http.HttpServletRequest;

/**
 * This class targets to parse Authentication type from `Authorization` HTTP header.
 * <br>
 * Supported `Authorization` header syntax:
 * <pre>
 * Authorization: &#60;type&#62; &#60;credentials&#62;
 * </pre>
 *
 * @author Sergey Bespalov
 *
 */
public class AuthenticationTypeParser {

	public static final String AUTHORIZATION_HEADER_NAME = "Authorization";

	public AuthenticationType parseAuthenticationType(HttpServletRequest request) {
		String header = request.getHeader(AUTHORIZATION_HEADER_NAME);
		if (header == null) {
			return null;
		}

		header = header.trim();
		String authenticationType = header.substring(0, header.indexOf(" ") + 1);

		return new AuthenticationType(authenticationType.trim());
	}

}
