/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.wrapper;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.ui.savedrequest.Enumerator;
import org.springframework.security.ui.savedrequest.FastHttpDateFormat;
import org.springframework.security.ui.savedrequest.SavedRequest;
import org.springframework.security.util.PortResolver;


/**
 * Provides request parameters, headers and cookies from either an original request or a saved request.
 *
 * <p>Note that not all request parameters in the original request are emulated by this wrapper.
 * Nevertheless, the important data from the original request is emulated and this should prove
 * adequate for most purposes (in particular standard HTTP GET and POST operations).</p>
 *
 * <p>Added into a request by {@link org.springframework.security.wrapper.SecurityContextHolderAwareRequestFilter}.</p>
 *
 *
 * @see SecurityContextHolderAwareRequestFilter
 *
 * @author Andrey Grebnev
 * @author Ben Alex
 * @version $Id$
 */
public class SavedRequestAwareWrapper extends SecurityContextHolderAwareRequestWrapper {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(SavedRequestAwareWrapper.class);
    protected static final TimeZone GMT_ZONE = TimeZone.getTimeZone("GMT");

    /** The default Locale if none are specified. */
    protected static Locale defaultLocale = Locale.getDefault();

    //~ Instance fields ================================================================================================

    protected SavedRequest savedRequest = null;

    /**
     * The set of SimpleDateFormat formats to use in getDateHeader(). Notice that because SimpleDateFormat is
     * not thread-safe, we can't declare formats[] as a static variable.
     */
    protected SimpleDateFormat[] formats = new SimpleDateFormat[3];

    //~ Constructors ===================================================================================================

    public SavedRequestAwareWrapper(HttpServletRequest request, PortResolver portResolver, String rolePrefix) {
        super(request, portResolver, rolePrefix);

        HttpSession session = request.getSession(false);

        if (session == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Wrapper not replaced; no session available for SavedRequest extraction");
            }

            return;
        }

        SavedRequest saved = (SavedRequest) session.getAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);

        if ((saved != null) && saved.doesRequestMatch(request, portResolver)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Wrapper replaced; SavedRequest was: " + saved);
            }

            savedRequest = saved;
            session.removeAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);

            formats[0] = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
            formats[1] = new SimpleDateFormat("EEEEEE, dd-MMM-yy HH:mm:ss zzz", Locale.US);
            formats[2] = new SimpleDateFormat("EEE MMMM d HH:mm:ss yyyy", Locale.US);

            formats[0].setTimeZone(GMT_ZONE);
            formats[1].setTimeZone(GMT_ZONE);
            formats[2].setTimeZone(GMT_ZONE);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Wrapper not replaced; SavedRequest was: " + saved);
            }
        }
    }

    //~ Methods ========================================================================================================

    @Override
    public Cookie[] getCookies() {
        if (savedRequest == null) {
            return super.getCookies();
        } else {
            List<Cookie> cookies = savedRequest.getCookies();

            return cookies.toArray(new Cookie[cookies.size()]);
        }
    }

    @Override
    public long getDateHeader(String name) {
        if (savedRequest == null) {
            return super.getDateHeader(name);
        } else {
            String value = getHeader(name);

            if (value == null) {
                return -1L;
            }

            // Attempt to convert the date header in a variety of formats
            long result = FastHttpDateFormat.parseDate(value, formats);

            if (result != -1L) {
                return result;
            }

            throw new IllegalArgumentException(value);
        }
    }

    @Override
    public String getHeader(String name) {
        if (savedRequest == null) {
            return super.getHeader(name);
        } else {
            String header = null;
            Iterator<String> iterator = savedRequest.getHeaderValues(name);

            while (iterator.hasNext()) {
                header = iterator.next();

                break;
            }

            return header;
        }
    }

    @Override
    public Enumeration getHeaderNames() {
        if (savedRequest == null) {
            return super.getHeaderNames();
        } else {
            return new Enumerator<String>(savedRequest.getHeaderNames());
        }
    }

    @Override
    public Enumeration getHeaders(String name) {
        if (savedRequest == null) {
            return super.getHeaders(name);
        } else {
            return new Enumerator<String>(savedRequest.getHeaderValues(name));
        }
    }

    @Override
    public int getIntHeader(String name) {
        if (savedRequest == null) {
            return super.getIntHeader(name);
        } else {
            String value = getHeader(name);

            if (value == null) {
                return -1;
            } else {
                return Integer.parseInt(value);
            }
        }
    }

    @Override
    public Locale getLocale() {
        if (savedRequest == null) {
            return super.getLocale();
        } else {
            Locale locale = null;
            Iterator<Locale> iterator = savedRequest.getLocales();

            while (iterator.hasNext()) {
                locale = (Locale) iterator.next();

                break;
            }

            if (locale == null) {
                return defaultLocale;
            } else {
                return locale;
            }
        }
    }

    @Override
    public Enumeration getLocales() {
        if (savedRequest == null) {
            return super.getLocales();
        }

        Iterator<Locale> iterator = savedRequest.getLocales();

        if (iterator.hasNext()) {
            return new Enumerator<Locale>(iterator);
        }
        // Fall back to default locale
        ArrayList<Locale> results = new ArrayList<Locale>(1);
        results.add(defaultLocale);

        return new Enumerator<Locale>(results.iterator());
    }

    @Override
    public String getMethod() {
        if (savedRequest == null) {
            return super.getMethod();
        } else {
            return savedRequest.getMethod();
        }
    }

    /**
     * If the parameter is available from the wrapped request then either
     * <ol>
     * <li>There is no saved request (it a normal request)</li>
     * <li>There is a saved request, but the request has been forwarded/included to a URL with parameters, either
     * supplementing or overriding the saved request values.</li>
     * </ol>
     * In both cases the value from the wrapped request should be used.
     * <p>
     * If the value from the wrapped request is null, an attempt will be made to retrieve the parameter
     * from the SavedRequest, if available..
     */
    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);

        if (value != null || savedRequest == null) {
            return value;
        }

        String[] values = savedRequest.getParameterValues(name);
        if (values == null || values.length == 0) {
            return null;
        }

        return values[0];
    }

    @Override
    public Map getParameterMap() {
        if (savedRequest == null) {
            return super.getParameterMap();
        }

        Set<String> names = getCombinedParameterNames();
        Map<String, String[]> parameterMap = new HashMap<String, String[]>(names.size());

        for (String name : names) {
            parameterMap.put(name, getParameterValues(name));
        }

        return parameterMap;
    }

    private Set<String> getCombinedParameterNames() {
        Set<String> names = new HashSet<String>();
        names.addAll(super.getParameterMap().keySet());

        if (savedRequest != null) {
            names.addAll(savedRequest.getParameterMap().keySet());
        }

        return names;
    }

    @Override
    public Enumeration getParameterNames() {
        return new Enumerator(getCombinedParameterNames());
    }

    @Override
    public String[] getParameterValues(String name) {
        if (savedRequest == null) {
            return super.getParameterValues(name);
        }

        String[] savedRequestParams = savedRequest.getParameterValues(name);
        String[] wrappedRequestParams = super.getParameterValues(name);

        if (savedRequestParams == null) {
            return wrappedRequestParams;
        }

        if (wrappedRequestParams == null) {
            return savedRequestParams;
        }

        // We have parameters in both saved and wrapped requests so have to merge them
        List<String> wrappedParamsList = Arrays.asList(wrappedRequestParams);
        List<String> combinedParams = new ArrayList<String>(wrappedParamsList);

        // We want to add all parameters of the saved request *apart from* duplicates of those already added
        for (int i = 0; i < savedRequestParams.length; i++) {
            if (!wrappedParamsList.contains(savedRequestParams[i])) {
                combinedParams.add(savedRequestParams[i]);
            }
        }

        return combinedParams.toArray(new String[combinedParams.size()]);
    }
}
