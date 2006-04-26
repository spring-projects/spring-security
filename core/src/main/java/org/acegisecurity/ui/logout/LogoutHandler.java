package org.acegisecurity.ui.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.Authentication;

/**
 * Indicates a class that is able to participate in logout handling.
 * 
 * <p>
 * Called by {@link LogoutFilter}.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public interface LogoutHandler {
	
	/**
	 * Causes a logout to be completed. The method must complete successfully.
	 * 
	 * @param request the HTTP request
	 * @param response the HTTP resonse
	 * @param authentication the current principal details
	 */
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication);
}
