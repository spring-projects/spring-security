package org.springframework.security.web.context;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainOrder;
import org.springframework.security.web.SpringSecurityFilter;

/**
 * Populates the {@link SecurityContextHolder} with information obtained from
 * the configured {@link SecurityContextRepository} prior to the request and stores it back in the repository
 * once the request has completed. By default it uses an {@link HttpSessionSecurityContextRepository}. See this
 * class for information <tt>HttpSession</tt> related configuration options.
 * <p>
 * This filter will only execute once per request, to resolve servlet container (specifically Weblogic)
 * incompatibilities.
 * <p>
 * This filter MUST be executed BEFORE any authentication processing mechanisms. Authentication processing mechanisms
 * (e.g. BASIC, CAS processing filters etc) expect the <code>SecurityContextHolder</code> to contain a valid
 * <code>SecurityContext</code> by the time they execute.
 * <p>
 * This is essentially a refactoring of the old <tt>HttpSessionContextIntegrationFilter</tt> to delegate
 * the storage issues to a separate strategy, allowing for more customization in the way the security context is
 * maintained between requests.
 * <p>
 * The <tt>forceEagerSessionCreation</tt> property can be used to ensure that a session is always available before
 * the filter chain executes (the default is <code>false</code>, as this is resource intensive and not recommended).
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class SecurityContextPersistenceFilter extends SpringSecurityFilter {

    static final String FILTER_APPLIED = "__spring_security_scpf_applied";

    private SecurityContextRepository repo = new HttpSessionSecurityContextRepository();

    private boolean forceEagerSessionCreation = false;

    @Override
    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (request.getAttribute(FILTER_APPLIED) != null) {
            // ensure that filter is only applied once per request
            chain.doFilter(request, response);
            return;
        }

        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

        if (forceEagerSessionCreation) {
            HttpSession session = request.getSession();
            logger.debug("Eagerly created session: " + session.getId());
        }

        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContext contextBeforeChainExecution = repo.loadContext(holder);

        try {
            SecurityContextHolder.setContext(contextBeforeChainExecution);

            chain.doFilter(holder.getRequest(), holder.getResponse());

        } finally {
            SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
            // Crucial removal of SecurityContextHolder contents - do this before anything else.
            SecurityContextHolder.clearContext();
            repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
            request.removeAttribute(FILTER_APPLIED);

            if (logger.isDebugEnabled()) {
                logger.debug("SecurityContextHolder now cleared, as request processing completed");
            }
        }
    }

    public void setSecurityContextRepository(SecurityContextRepository repo) {
        this.repo = repo;
    }

    public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
        this.forceEagerSessionCreation = forceEagerSessionCreation;
    }

    public int getOrder() {
        return FilterChainOrder.SECURITY_CONTEXT_FILTER;
    }
}
