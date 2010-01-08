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

package org.springframework.security.web.context;

import javax.servlet.ServletException;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

/**
 * Populates the {@link SecurityContextHolder} with information obtained from
 * the <code>HttpSession</code>.
 * <p/>
 * <p/>
 * The <code>HttpSession</code> will be queried to retrieve the
 * <code>SecurityContext</code> that should be stored against the
 * <code>SecurityContextHolder</code> for the duration of the web request. At
 * the end of the web request, any updates made to the
 * <code>SecurityContextHolder</code> will be persisted back to the
 * <code>HttpSession</code> by this filter.
 * </p>
 * <p/>
 * If a valid <code>SecurityContext</code> cannot be obtained from the
 * <code>HttpSession</code> for whatever reason, a fresh
 * <code>SecurityContext</code> will be created and used instead. The created
 * object will be of the instance defined by the {@link #setContextClass(Class)}
 * method (which defaults to {@link org.springframework.security.core.context.SecurityContextImpl}.
 * </p>
 * <p/>
 * No <code>HttpSession</code> will be created by this filter if one does not
 * already exist. If at the end of the web request the <code>HttpSession</code>
 * does not exist, a <code>HttpSession</code> will <b>only</b> be created if
 * the current contents of the <code>SecurityContextHolder</code> are not
 * {@link java.lang.Object#equals(java.lang.Object)} to a <code>new</code>
 * instance of {@link #setContextClass(Class)}. This avoids needless
 * <code>HttpSession</code> creation, but automates the storage of changes
 * made to the <code>SecurityContextHolder</code>. There is one exception to
 * this rule, that is if the {@link #forceEagerSessionCreation} property is
 * <code>true</code>, in which case sessions will always be created
 * irrespective of normal session-minimisation logic (the default is
 * <code>false</code>, as this is resource intensive and not recommended).
 * </p>
 * <p/>
 * This filter will only execute once per request, to resolve servlet container
 * (specifically Weblogic) incompatibilities.
 * </p>
 * <p/>
 * If for whatever reason no <code>HttpSession</code> should <b>ever</b> be
 * created (eg this filter is only being used with Basic authentication or
 * similar clients that will never present the same <code>jsessionid</code>
 * etc), the {@link #setAllowSessionCreation(boolean)} should be set to
 * <code>false</code>. Only do this if you really need to conserve server
 * memory and ensure all classes using the <code>SecurityContextHolder</code>
 * are designed to have no persistence of the <code>SecurityContext</code>
 * between web requests. Please note that if {@link #forceEagerSessionCreation}
 * is <code>true</code>, the <code>allowSessionCreation</code> must also be
 * <code>true</code> (setting it to <code>false</code> will cause a startup
 * time error).
 * </p>
 * <p/>
 * This filter MUST be executed BEFORE any authentication processing mechanisms.
 * Authentication processing mechanisms (eg BASIC, CAS processing filters etc)
 * expect the <code>SecurityContextHolder</code> to contain a valid
 * <code>SecurityContext</code> by the time they execute.
 * </p>
 *
 * @author Ben Alex
 * @author Patrick Burleson
 * @author Luke Taylor
 * @author Martin Algesten
 *
 * @deprecated Use SecurityContextPersistenceFilter instead.
 *
 */
public class HttpSessionContextIntegrationFilter extends SecurityContextPersistenceFilter implements InitializingBean {
    //~ Static fields/initializers =====================================================================================
    public static final String SPRING_SECURITY_CONTEXT_KEY = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

    //~ Instance fields ================================================================================================

    private Class<? extends SecurityContext> contextClass = SecurityContextImpl.class;

    /**
     * Indicates if this filter can create a <code>HttpSession</code> if
     * needed (sessions are always created sparingly, but setting this value to
     * <code>false</code> will prohibit sessions from ever being created).
     * Defaults to <code>true</code>. Do not set to <code>false</code> if
     * you are have set {@link #forceEagerSessionCreation} to <code>true</code>,
     * as the properties would be in conflict.
     */
    private boolean allowSessionCreation = true;

    /**
     * Indicates if this filter is required to create a <code>HttpSession</code>
     * for every request before proceeding through the filter chain, even if the
     * <code>HttpSession</code> would not ordinarily have been created. By
     * default this is <code>false</code>, which is entirely appropriate for
     * most circumstances as you do not want a <code>HttpSession</code>
     * created unless the filter actually needs one. It is envisaged the main
     * situation in which this property would be set to <code>true</code> is
     * if using other filters that depend on a <code>HttpSession</code>
     * already existing, such as those which need to obtain a session ID. This
     * is only required in specialised cases, so leave it set to
     * <code>false</code> unless you have an actual requirement and are
     * conscious of the session creation overhead.
     */
    private boolean forceEagerSessionCreation = false;

    /**
     * Indicates whether the <code>SecurityContext</code> will be cloned from
     * the <code>HttpSession</code>. The default is to simply reference (ie
     * the default is <code>false</code>). The default may cause issues if
     * concurrent threads need to have a different security identity from other
     * threads being concurrently processed that share the same
     * <code>HttpSession</code>. In most normal environments this does not
     * represent an issue, as changes to the security identity in one thread is
     * allowed to affect the security identitiy in other threads associated with
     * the same <code>HttpSession</code>. For unusual cases where this is not
     * permitted, change this value to <code>true</code> and ensure the
     * {@link #contextClass} is set to a <code>SecurityContext</code> that
     * implements {@link Cloneable} and overrides the <code>clone()</code>
     * method.
     */
    private boolean cloneFromHttpSession = false;

 //   private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    private HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();

    public HttpSessionContextIntegrationFilter() throws ServletException {
        super.setSecurityContextRepository(repo);
    }

    public boolean isCloneFromHttpSession() {
        return cloneFromHttpSession;
    }

    public void setCloneFromHttpSession(boolean cloneFromHttpSession) {
        this.cloneFromHttpSession = cloneFromHttpSession;
        repo.setCloneFromHttpSession(cloneFromHttpSession);
    }

    public boolean isAllowSessionCreation() {
      return allowSessionCreation;
    }

    public void setAllowSessionCreation(boolean allowSessionCreation) {
      this.allowSessionCreation = allowSessionCreation;
      repo.setAllowSessionCreation(allowSessionCreation);
    }

    protected Class<? extends SecurityContext> getContextClass() {
      return contextClass;
    }

    @SuppressWarnings("unchecked")
    public void setContextClass(Class secureContext) {
      this.contextClass = secureContext;
      repo.setSecurityContextClass(secureContext);
    }

    public boolean isForceEagerSessionCreation() {
      return forceEagerSessionCreation;
    }

    public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
      this.forceEagerSessionCreation = forceEagerSessionCreation;
      super.setForceEagerSessionCreation(forceEagerSessionCreation);
    }

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() {
        if (forceEagerSessionCreation && !allowSessionCreation) {
            throw new IllegalArgumentException(
                    "If using forceEagerSessionCreation, you must set allowSessionCreation to also be true");
        }
    }
}
