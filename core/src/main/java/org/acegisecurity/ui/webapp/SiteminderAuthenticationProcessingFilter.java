package net.sf.acegisecurity.ui.webapp;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.ui.WebAuthenticationDetails;

/**
 * Extends Acegi's AuthenticationProcessingFilter to use Siteminder's headers for identification.
 * 
 * <P>
 * Provides the ability set all source key names and also provides form-based authentication as a backup.
 * </P>
 *
 * <P>
 * You must set the Siteminder header keys, otherwise Siteminder checks will be skipped (there
 * are no defaults).  If the <I>Siteminder</I> check is unsuccessful or if the headers are not
 * defined/found in the HTTP request, then the <I>form</I> parameters will be checked (see below).
 * This allows applications to  function even when their Siteminder infrastructure
 * is unavailable, as is often the case during development.  If you do not wish to use backup
 * form-based authentication, then set the form parameter keys to null/blank. 
 * </P>
 * 
 * <P>
 * <B>Siteminder</B> must present at least one HTTP <I>header</I> to this filter - typically
 * containing a unique identifier such a username, an employee number or a national ID.
 * This makes sense because Siteminder has already <I>authenticated</I> the user prior to
 * getting to this filter, so we're really only using it for identification and not authentication.
 * Set the <code>siteminderUsernameHeaderKey</code> value to tell the filter where to greb the "username"
 * value.  You'll typically also set the <code>siteminderPasswordHeaderKey</code> to the same header key.
 * Just remember to modify your AuthenticationDAO so that it can handle identity-only requests! 
 * </P>
 * 
 * <P>
 * <B>Forms</B> must present two <I>parameters</I> to this filter: a username and a password.
 * If not specified, the parameter names to use are defaulted to the static fields
 * {@link #ACEGI_SECURITY_FORM_USERNAME_KEY} and {@link #ACEGI_SECURITY_FORM_PASSWORD_KEY}.
 * </P>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead, configure <code>web.xml</code> 
 * to use the {@link net.sf.acegisecurity.util.FilterChainProxy} and include this filter.
 * </P>
 * 
 * @author <a href="mailto:scott@mccrory.us">Scott McCrory</a>
 * @author Ben Alex
 * @since 0.9.0
 * @version CVS $Id$
 */
public class SiteminderAuthenticationProcessingFilter extends AuthenticationProcessingFilter {

	/**
	 * Siteminder username header key.
	 */
	private String siteminderUsernameHeaderKey = null;

	/**
	 * Siteminder password header key.
	 */
	private String siteminderPasswordHeaderKey = null;

	/**
	 * Form username request key.
	 */
	private String formUsernameParameterKey = null;

	/**
	 * Form password request key.
	 */
	private String formPasswordParameterKey = null;

	/**
	 * Basic constructor.
	 */
	public SiteminderAuthenticationProcessingFilter() {
		super();
	}

	/***
		* This filter by default responds to <code>/j_acegi_security_check</code>.
		*
		* @return the default
		*/
	public String getDefaultFilterProcessesUrl() {
		return "/j_acegi_security_check";
	}

	public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {

		String username = null;
		String password = null;

		// Check the Siteminder headers for authentication info
		if (siteminderUsernameHeaderKey != null
			&& siteminderUsernameHeaderKey.length() > 0
			&& siteminderPasswordHeaderKey != null
			&& siteminderPasswordHeaderKey.length() > 0) {

			username = request.getHeader(siteminderUsernameHeaderKey);
			password = request.getHeader(siteminderPasswordHeaderKey);

		}

		// If the Siteminder authentication info wasn't available, then get it from the form parameters
		if (username == null || username.length() == 0 || password == null || password.length() == 0) {

			//System.out.println("Siteminder headers not found for authentication");

			if (formUsernameParameterKey != null && formUsernameParameterKey.length() > 0) {
				username = request.getParameter(formUsernameParameterKey);
			}
			else {
				username = request.getParameter(ACEGI_SECURITY_FORM_USERNAME_KEY);
			}

			password = obtainPassword(request);

		}

		// If either are null, set them to blank to avoid a NPE.
		if (username == null) {
			username = "";
		}
		if (password == null) {
			password = "";
		}

		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		// Place the last username attempted into HttpSession for views
		request.getSession().setAttribute(ACEGI_SECURITY_LAST_USERNAME_KEY, username);

		return this.getAuthenticationManager().authenticate(authRequest);
	}

	public void init(FilterConfig filterConfig) throws ServletException {
	}

	/***
		* Provided so that subclasses may configure what is put into the
		* authentication request's details property. The default implementation
		* simply constructs {@link WebAuthenticationDetails}.
		*
		* @param request that an authentication request is being created for
		* @param authRequest the authentication request object that should have
		*        its details set
		*/
	protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
		authRequest.setDetails(new WebAuthenticationDetails(request));
	}

	/***
		* Enables subclasses to override the composition of the password, such as
		* by including additional values and a separator.
		* 
		* <p>
		* This might be used for example if a postcode/zipcode was required in
		* addition to the password. A delimiter such as a pipe (|) should be used
		* to separate the password and extended value(s). The
		* <code>AuthenticationDao</code> will need to generate the expected
		* password in a corresponding manner.
		* </p>
		*
		* @param request so that request attributes can be retrieved
		*
		* @return the password that will be presented in the
		*         <code>Authentication</code> request token to the
		*         <code>AuthenticationManager</code>
		*/
	protected String obtainPassword(HttpServletRequest request) {

		if (formPasswordParameterKey != null && formPasswordParameterKey.length() > 0) {
			return request.getParameter(formPasswordParameterKey);
		}
		else {
			return request.getParameter(ACEGI_SECURITY_FORM_PASSWORD_KEY);
		}

	}

	/**
	 * Returns the form password parameter key.
	 * 
	 * @return The form password parameter key.
	 */
	public String getFormPasswordParameterKey() {
		return formPasswordParameterKey;
	}

	/**
	 * Returns the form username parameter key.
	 * 
	 * @return The form username parameter key.
	 */
	public String getFormUsernameParameterKey() {
		return formUsernameParameterKey;
	}

	/**
	 * Returns the Siteminder password header key.
	 * 
	 * @return The Siteminder password header key.
	 */
	public String getSiteminderPasswordHeaderKey() {
		return siteminderPasswordHeaderKey;
	}

	/**
	 * Returns the Siteminder username header key.
	 * 
	 * @return The Siteminder username header key.
	 */
	public String getSiteminderUsernameHeaderKey() {
		return siteminderUsernameHeaderKey;
	}

	/**
	 * Sets the form password parameter key.
	 * 
	 * @param key The form password parameter key.
	 */
	public void setFormPasswordParameterKey(final String key) {
		this.formPasswordParameterKey = key;
	}

	/**
	 * Sets the form username parameter key.
	 * 
	 * @param key The form username parameter key.
	 */
	public void setFormUsernameParameterKey(final String key) {
		this.formUsernameParameterKey = key;
	}

	/**
	 * Sets the Siteminder password header key.
	 * 
	 * @param key The Siteminder password header key.
	 */
	public void setSiteminderPasswordHeaderKey(final String key) {
		this.siteminderPasswordHeaderKey = key;
	}

	/**
	 * Sets the Siteminder username header key.
	 * 
	 * @param key The Siteminder username header key.
	 */
	public void setSiteminderUsernameHeaderKey(final String key) {
		this.siteminderUsernameHeaderKey = key;
	}

}
