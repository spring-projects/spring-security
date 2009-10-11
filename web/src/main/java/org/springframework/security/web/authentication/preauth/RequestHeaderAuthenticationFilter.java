package org.springframework.security.web.authentication.preauth;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;

/**
 * A simple pre-authenticated filter which obtains the username from a request header, for use with systems such as
 * CA Siteminder.
 * <p>
 * As with most pre-authenticated scenarios, it is essential that the external authentication system is set up
 * correctly as this filter does no authentication whatsoever. All the protection is assumed to be provided externally
 * and if this filter is included inappropriately in a configuration, it would be possible  to assume the
 * identity of a user merely by setting the correct header name. This also means it should not generally be used
 * in combination with other Spring Security authentication mechanisms such as form login, as this would imply there
 * was a means of bypassing the external system which would be risky.
 * <p>
 * The property <tt>principalRequestHeader</tt> is the name of the request header that contains the username. It
 * defaults to "SM_USER" for compatibility with Siteminder.
 * <p>
 * If the header is missing from the request, <tt>getPreAuthenticatedPrincipal</tt> will throw an exception. You
 * can override this behaviour by setting the <tt>exceptionIfMissingHeader</tt> property.
 *
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class RequestHeaderAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {
    private String principalRequestHeader = "SM_USER";
    private String credentialsRequestHeader;
    private boolean exceptionIfHeaderMissing = true;

    /**
     * Read and returns the header named by <tt>principalRequestHeader</tt> from the request.
     *
     * @throws PreAuthenticatedCredentialsNotFoundException if the header is missing and <tt>exceptionIfHeaderMissing</tt>
     *          is set to <tt>true</tt>.
     */
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String principal = request.getHeader(principalRequestHeader);

        if (principal == null && exceptionIfHeaderMissing) {
            throw new PreAuthenticatedCredentialsNotFoundException(principalRequestHeader
                    + " header not found in request.");
        }

        return principal;
    }

    /**
     * Credentials aren't usually applicable, but if a <tt>credentialsRequestHeader</tt> is set, this
     * will be read and used as the credentials value. Otherwise a dummy value will be used.
     */
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        if (credentialsRequestHeader != null) {
            String credentials = request.getHeader(credentialsRequestHeader);

            return credentials;
        }

        return "N/A";
    }

    public void setPrincipalRequestHeader(String principalRequestHeader) {
        Assert.hasText(principalRequestHeader, "principalRequestHeader must not be empty or null");
        this.principalRequestHeader = principalRequestHeader;
    }

    public void setCredentialsRequestHeader(String credentialsRequestHeader) {
        Assert.hasText(credentialsRequestHeader, "credentialsRequestHeader must not be empty or null");
        this.credentialsRequestHeader = credentialsRequestHeader;
    }

    /**
     * Defines whether an exception should be raised if the principal header is missing. Defaults to <tt>true</tt>.
     *
     * @param exceptionIfHeaderMissing set to <tt>false</tt> to override the default behaviour and allow
     *          the request to proceed if no header is found.
     */
    public void setExceptionIfHeaderMissing(boolean exceptionIfHeaderMissing) {
        this.exceptionIfHeaderMissing = exceptionIfHeaderMissing;
    }
}
