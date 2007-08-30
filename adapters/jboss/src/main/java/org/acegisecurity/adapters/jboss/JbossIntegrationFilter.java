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

package org.acegisecurity.adapters.jboss;

import org.acegisecurity.Authentication;

import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.context.HttpSessionContextIntegrationFilter;
import org.acegisecurity.context.SecurityContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

import java.security.Principal;

import java.util.Iterator;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import javax.security.auth.Subject;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Populates a {@link SecurityContext} from JBoss' <code>java:comp/env/security/subject</code>.
 * <p>This filter <b>never</b> preserves the <code>Authentication</code> on the <code>ContextHolder</code> -
 * it is replaced every request.</p>
 * <p>See {@link HttpSessionContextIntegrationFilter} for further information.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JbossIntegrationFilter implements Filter {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(JbossIntegrationFilter.class);

    //~ Methods ========================================================================================================

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     */
    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        Object principal = extractFromContainer(request);

        if ((principal != null) && principal instanceof Authentication) {
            SecurityContextHolder.getContext().setAuthentication((Authentication) principal);

            if (logger.isDebugEnabled()) {
                logger.debug("ContextHolder updated with Authentication from container: '" + principal + "'");
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("ContextHolder not set with new Authentication as Principal was: '" + principal + "'");
            }
        }

        chain.doFilter(request, response);
    }

    private Object extractFromContainer(ServletRequest request) {
        Subject subject = null;

        try {
            Context lc = this.getLookupContext();

            if (lc == null) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Could not obtain a Context to perform lookup");
                }

                return null;
            }

            Object result = lc.lookup("java:comp/env/security/subject");

            if (result instanceof Subject) {
                subject = (Subject) result;
            }
        } catch (NamingException ne) {
            if (logger.isWarnEnabled()) {
                logger.warn("Lookup on Subject failed " + ne.getLocalizedMessage());
            }
        }

        if ((subject != null) && (subject.getPrincipals() != null)) {
            Iterator principals = subject.getPrincipals().iterator();

            while (principals.hasNext()) {
                Principal p = (Principal) principals.next();

                if (p instanceof Authentication) {
                    return p;
                }
            }
        }

        return null;
    }

    /**
     * Provided so that unit tests can override.
     *
     * @return a <code>Context</code> that can be used for lookup
     *
     * @throws NamingException DOCUMENT ME!
     */
    protected Context getLookupContext() throws NamingException {
        return new InitialContext();
    }

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     *
     * @param arg0 ignored
     *
     * @throws ServletException ignored
     */
    public void init(FilterConfig arg0) throws ServletException {}
}
