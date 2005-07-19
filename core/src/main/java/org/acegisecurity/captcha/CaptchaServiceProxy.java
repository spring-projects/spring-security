package net.sf.acegisecurity.captcha;

import javax.servlet.ServletRequest;

/**
 * Provide a common interface for captcha validation.
 * 
 * @author marc antoine Garrigue
 * @version $Id$
 */
public interface CaptchaServiceProxy {

	/**
	 * @return true if the request is validated by the back end captcha service.
	 */
	boolean validateRequest(ServletRequest request);
}
