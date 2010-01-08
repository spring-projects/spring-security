package org.springframework.security.web.savedrequest;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.Cookie;

/**
 * Encapsulates the functionality required of a cached request for both an authentication mechanism (typically
 * form-based login) to redirect to the original URL and for a <tt>RequestCache</tt> to build a wrapped request,
 * reproducing the original request data.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface SavedRequest extends java.io.Serializable {

    /**
     * @return the URL for the saved request, allowing a redirect to be performed.
     */
    String getRedirectUrl();

    List<Cookie> getCookies();

    String getMethod();

    List<String> getHeaderValues(String name);

    Collection<String> getHeaderNames();

    List<Locale> getLocales();

    String[] getParameterValues(String name);

    Map<String,String[]> getParameterMap();
}
