/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.ui.webapp;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ui.AbstractIntegrationFilter;

import java.util.Iterator;
import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


/**
 * Populates a {@link net.sf.acegisecurity.context.SecureContext} from the
 * <code>HttpSession</code>.
 * 
 * <P>
 * The filter will inspect the <code>HttpSession</code> for an attribute with
 * the name indicated by {@link #ACEGI_SECURITY_AUTHENTICATION_KEY}. If that
 * attribute contains an instance of {@link Authentication}, it will be placed
 * into the <code>ContextHolder</code>.
 * </p>
 * 
 * <P>
 * This filter is normally used in conjunction with {@link
 * AuthenticationProcessingFilter}, which populates the
 * <code>HttpSession</code> with an <code>Authentication</code> object based
 * on a form login. Similarly, the {@link
 * net.sf.acegisecurity.ui.basicauth.BasicProcessingFilter} will populate the
 * <code>HttpSession</code> based on a BASIC authentication request.
 * Alternatively, users may elect to use their own approach for populating the
 * <code>HttpSession</code>.
 * </p>
 * 
 * <p>
 * As with other <code>AbstractIntegrationFilter</code>s, this filter will
 * ensure the <code>ContextHolder</code> is populated with the
 * <code>Authentication</code> object for the duration of the HTTP request,
 * and is unbound from the <code>ContextHolder</code> at the completion of the
 * request.
 * </p>
 * 
 * <P>
 * The filter can also copy the <code>Authentication</code> object to any
 * number of additional <code>HttpSession</code> attributes. To use this
 * capability, provide <code>String</code>s indicating the additional
 * attribute name(s) to {@link #setAdditionalAttributes(List)}.
 * </p>
 * 
 * <p>
 * See {@link AbstractIntegrationFilter} for further information.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class HttpSessionIntegrationFilter extends AbstractIntegrationFilter {
    //~ Static fields/initializers =============================================

    public static final String ACEGI_SECURITY_AUTHENTICATION_KEY = "ACEGI_SECURITY_AUTHENTICATION";

    //~ Instance fields ========================================================

    private List additionalAttributes = null;

    //~ Methods ================================================================

    public void setAdditionalAttributes(List additionalAttributes) {
        validateList(additionalAttributes);
        this.additionalAttributes = additionalAttributes;
    }

    public List getAdditionalAttributes() {
        return additionalAttributes;
    }

    public void commitToContainer(ServletRequest request,
        Authentication authentication) {
        if (request instanceof HttpServletRequest
            && ((HttpServletRequest) request).isRequestedSessionIdValid()) {
            HttpSession httpSession = ((HttpServletRequest) request).getSession(false);

            if (httpSession != null) {
                httpSession.setAttribute(ACEGI_SECURITY_AUTHENTICATION_KEY,
                    authentication);
                updateOtherLocations(httpSession, authentication);
            }
        }
    }

    public Object extractFromContainer(ServletRequest request) {
        if (request instanceof HttpServletRequest) {
            HttpSession httpSession = null;

            try {
                httpSession = ((HttpServletRequest) request).getSession(false);
            } catch (IllegalStateException ignored) {}

            if (httpSession != null) {
                Object authObject = httpSession.getAttribute(ACEGI_SECURITY_AUTHENTICATION_KEY);

                if (authObject instanceof Authentication) {
                    updateOtherLocations(httpSession,
                        (Authentication) authObject);

                    return authObject;
                }
            }
        }

        return null;
    }

    private void updateOtherLocations(HttpSession session,
        Authentication authentication) {
        if (additionalAttributes == null) {
            return;
        }

        Iterator iter = additionalAttributes.iterator();

        while (iter.hasNext()) {
            String attribute = (String) iter.next();
            session.setAttribute(attribute, authentication);
        }
    }

    private void validateList(List newAdditionalAttributes) {
        if (newAdditionalAttributes != null) {
            Iterator iter = newAdditionalAttributes.iterator();

            while (iter.hasNext()) {
                Object objectToTest = iter.next();

                if (!(objectToTest instanceof String)) {
                    throw new IllegalArgumentException(
                        "List of additional attributes can only contains Strings!");
                }
            }
        }
    }
}
