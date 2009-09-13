package org.springframework.security.web.savedrequest;

/**
 * Encapsulates the functionality required of a cached request, in order for an authentication mechanism (typically
 * form-based login) to redirect to the original URL.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public interface SavedRequest extends java.io.Serializable {

    /**
     * @return the URL for the saved request, allowing a redirect to be performed.
     */
    String getRedirectUrl();
}
