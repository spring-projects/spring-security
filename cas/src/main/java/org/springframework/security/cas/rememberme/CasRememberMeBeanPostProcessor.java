package org.springframework.security.cas.rememberme;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter;

/**
 * This class loads automatically the appropriate beans if the user has defined a simplified security context configuration with
 * &lt;http&gt;.
 * <p>
 * In the <code>AuthenticatedVoter</code> bean, the <code>AuthenticationTrustResolverImpl</code> bean is replaced by a
 * {@link CasRememberMeAuthenticationTrustResolverImpl} bean. In the <code>ExceptionTranslationFilter</code> bean, the
 * <code>AccessDeniedHandlerImpl</code> bean is replaced by a {@link CasRememberMeAccessDeniedHandlerImpl} bean.
 * <p>
 * By default, this class could be defined in Spring context with a minimal configuration (just the current CAS entry point) :
 * 
 * <pre>
 * &lt;bean id="casRememberMeBeanPostProcessor" class="org.springframework.security.cas.rememberme.CasRememberMeBeanPostProcessor"&gt;
 *   &lt;property name="casAuthenticationEntryPoint" ref="myCasEntryPoint" /&gt;
 * &lt;/bean&gt;
 * </pre>
 * 
 * However, the <code>CasRememberMeAuthenticationTrustResolverImpl</code> and the <code>CasRememberMeAccessDeniedHandlerImpl</code> could be
 * specified instead of the entry point to allow maximum configuration options :
 * 
 * <pre>
 * &lt;bean id="casRememberMeBeanPostProcessor" class="org.springframework.security.cas.rememberme.CasRememberMeBeanPostProcessor"&gt;
 *   &lt;property name="casRememberMeAuthenticationTrustResolverImpl" ref="myCasRmeAuthenticationTrustResolverImpl" /&gt;
 *   &lt;property name="casRememberMeAccessDeniedHandlerImpl" ref="myCasRmeAccessDeniedHandlerImpl" /&gt;
 * &lt;/bean&gt;
 * </pre>
 * 
 * @author Jerome Leleu
 * @since 3.1.1
 */
public class CasRememberMeBeanPostProcessor implements BeanPostProcessor {
    
    private static final Log logger = LogFactory.getLog(CasRememberMeBeanPostProcessor.class);
    
    private CasRememberMeAuthenticationTrustResolverImpl casRememberMeAuthenticationTrustResolverImpl = new CasRememberMeAuthenticationTrustResolverImpl();
    
    private CasRememberMeAccessDeniedHandlerImpl casRememberMeAccessDeniedHandlerImpl = new CasRememberMeAccessDeniedHandlerImpl();
    
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }
    
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof AuthenticatedVoter) {
            AuthenticatedVoter authenticatedVoter = (AuthenticatedVoter) bean;
            authenticatedVoter.setAuthenticationTrustResolver(casRememberMeAuthenticationTrustResolverImpl);
            logger.info("Replace AuthenticationTrustResolverImpl by CasRememberMeAuthenticationTrustResolverImpl("
                        + casRememberMeAuthenticationTrustResolverImpl + ") in AuthenticatedVoter (" + beanName + ")");
        } else if (bean instanceof ExceptionTranslationFilter) {
            ExceptionTranslationFilter exceptionTranslationFilter = (ExceptionTranslationFilter) bean;
            exceptionTranslationFilter.setAccessDeniedHandler(casRememberMeAccessDeniedHandlerImpl);
            logger.info("Replace AccessDeniedHandlerImpl by CasRememberMeAccessDeniedHandlerImpl("
                        + casRememberMeAccessDeniedHandlerImpl + ") in ExceptionTranslationFilter (" + beanName + ")");
        }
        return bean;
    }
    
    /**
     * This setter is not a real one as it doesn't set a private property, instead it updates the entry point of the
     * casRememberMeAccessDeniedHandlerImpl bean property. It avoids complicated configuration by allowing just to specify the entry point.
     * 
     * @param casAuthenticationEntryPoint
     */
    public void setCasAuthenticationEntryPoint(CasAuthenticationEntryPoint casAuthenticationEntryPoint) {
        casRememberMeAccessDeniedHandlerImpl.setCasAuthenticationEntryPoint(casAuthenticationEntryPoint);
    }
    
    public CasRememberMeAuthenticationTrustResolverImpl getCasRememberMeAuthenticationTrustResolverImpl() {
        return casRememberMeAuthenticationTrustResolverImpl;
    }
    
    public void setCasRememberMeAuthenticationTrustResolverImpl(CasRememberMeAuthenticationTrustResolverImpl casRememberMeAuthenticationTrustResolverImpl) {
        this.casRememberMeAuthenticationTrustResolverImpl = casRememberMeAuthenticationTrustResolverImpl;
    }
    
    public CasRememberMeAccessDeniedHandlerImpl getCasRememberMeAccessDeniedHandlerImpl() {
        return casRememberMeAccessDeniedHandlerImpl;
    }
    
    public void setCasRememberMeAccessDeniedHandlerImpl(CasRememberMeAccessDeniedHandlerImpl casRememberMeAccessDeniedHandlerImpl) {
        this.casRememberMeAccessDeniedHandlerImpl = casRememberMeAccessDeniedHandlerImpl;
    }
}
