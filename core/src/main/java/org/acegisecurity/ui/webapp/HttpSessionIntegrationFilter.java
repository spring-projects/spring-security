/* Copyright 2004 Acegi Technology Pty Limited
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
 * on a form login. Alternatively, users may elect to use their own approach
 * for populating the <code>HttpSession</code>.
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

    //~ Methods ================================================================

    public Object extractFromContainer(ServletRequest request) {
        if (request instanceof HttpServletRequest) {
            HttpSession httpSession = ((HttpServletRequest) request).getSession();

            if (httpSession != null) {
                Object authObject = httpSession.getAttribute(ACEGI_SECURITY_AUTHENTICATION_KEY);

                if (authObject instanceof Authentication) {
                    return authObject;
                }
            }
        }

        return null;
    }
}
