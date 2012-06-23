package org.springframework.security.cas.rememberme;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.util.Assert;

/**
 * This class loads automatically the appropriate beans if the user has defined a simplified security context configuration with
 * &lt;http&gt;.<br />
 * In the AuthenticatedVoter bean, the AuthenticationTrustResolver bean is replaced by a {@link CasRememberMeAuthenticationTrustResolver}
 * bean.<br />
 * In the ExceptionTranslationFilter bean, the AccessDeniedHandlerImpl bean is replaced by a {@link CasRememberMeAccessDeniedHandlerImpl}
 * bean.<br />
 * The CasAuthenticationEntryPoint bean has to be specified for this class, it's the default CAS entry point : it's cloned with renew=true
 * parameter to be used in the {@link CasRememberMeAccessDeniedHandlerImpl} bean.
 * 
 * @author Jerome Leleu
 */
public class CasRememberMeBeanPostProcessor implements BeanPostProcessor, InitializingBean {
    
    private static final Log logger = LogFactory.getLog(CasRememberMeBeanPostProcessor.class);
    
    private CasRememberMeAuthenticationTrustResolverImpl casRememberMeAuthenticationTrustResolverImpl = new CasRememberMeAuthenticationTrustResolverImpl();
    
    private CasRememberMeAccessDeniedHandlerImpl casRememberMeAccessDeniedHandlerImpl = new CasRememberMeAccessDeniedHandlerImpl();
    
    private CasAuthenticationEntryPoint casAuthenticationEntryPoint = null;
    
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }
    
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof AuthenticatedVoter) {
            AuthenticatedVoter authenticatedVoter = (AuthenticatedVoter) bean;
            authenticatedVoter.setAuthenticationTrustResolver(casRememberMeAuthenticationTrustResolverImpl);
            logger
                .info("Replace AuthenticationTrustResolverImpl by CasRememberMeAuthenticationTrustResolverImpl in AuthenticatedVoter");
        } else if (bean instanceof ExceptionTranslationFilter) {
            ExceptionTranslationFilter exceptionTranslationFilter = (ExceptionTranslationFilter) bean;
            exceptionTranslationFilter.setAccessDeniedHandler(casRememberMeAccessDeniedHandlerImpl);
            logger
                .info("Replace AccessDeniedHandlerImpl by CasRememberMeAccessDeniedHandlerImpl in ExceptionTranslationFilter");
        }
        return bean;
    }
    
    public CasAuthenticationEntryPoint getCasAuthenticationEntryPoint() {
        return casAuthenticationEntryPoint;
    }
    
    public void setCasAuthenticationEntryPoint(CasAuthenticationEntryPoint casAuthenticationEntryPoint) {
        this.casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        this.casAuthenticationEntryPoint.setLoginUrl(casAuthenticationEntryPoint.getLoginUrl());
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService(casAuthenticationEntryPoint.getServiceProperties().getService());
        // use renew parameter when redirecting to CAS server as it will be used to "override" a previous CAS remember me authentication
        serviceProperties.setSendRenew(true);
        this.casAuthenticationEntryPoint.setServiceProperties(serviceProperties);
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
    
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.casAuthenticationEntryPoint, "casAuthenticationEntryPoint must be specified");
        // if no RequestCache defined, use default
        if (casRememberMeAccessDeniedHandlerImpl.getRequestCache() == null) {
            casRememberMeAccessDeniedHandlerImpl.setRequestCache(new HttpSessionRequestCache());
        }
        casRememberMeAccessDeniedHandlerImpl.setCasAuthenticationEntryPoint(casAuthenticationEntryPoint);
    }
}
