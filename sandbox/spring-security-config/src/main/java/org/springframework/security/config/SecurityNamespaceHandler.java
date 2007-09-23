/**
 * 
 */
package org.springframework.security.config;

import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * {@link org.springframework.beans.factory.xml.NamespaceHandler} for the '<code>security</code>' namespace.
 * @author vpuri
 * 
 * @since 
 */
public class SecurityNamespaceHandler extends NamespaceHandlerSupport {

	/**
	 * Register the {@link BeanDefinitionParser BeanDefinitionParsers} for the
	 * '<code>context-integration</code>', ' and '<code></code>' elements.
	 */
	public void init() {
		registerBeanDefinitionParser("principal-repository", new PrincipalRepositoryBeanDefinitionParser());
		registerBeanDefinitionParser("session-context-integration", new ContextIntegrationBeanDefinitionParser());
		registerBeanDefinitionParser("authentication-repository", new AuthenticationRepositoryBeanDefinitionParser());
		registerBeanDefinitionParser("authentication-mechanism", new AuthenticationMechanismBeanDefinitionParser());
		registerBeanDefinitionParser("authentication-remember-me-services", new RememberMeServicesBeanDefinitionParser());
		registerBeanDefinitionParser("authentication-remember-me-filter", new RememberMeFilterBeanDefinitionParser());
		registerBeanDefinitionParser("logout-support", new LogoutFilterBeanDefinitionParser());
		registerBeanDefinitionParser("exception-translation", new ExceptionTranslationFilterBeanDefinitionParser());
		registerBeanDefinitionParser("authentication-form", new AuthenticationProcessingFilterBeanDefinitionParser());
		registerBeanDefinitionParser("authorization-manager", new AuthorizationManagerBeanDefinitionParser());
		registerBeanDefinitionParser("authorization-http-url", new FilterSecurityInterceptorBeanDefinitionParser());
		registerBeanDefinitionParser("authorization-joinpoint", new AuthorizationMethodBeanDefinitionParser());
		registerBeanDefinitionParser("autoconfig", new AutoConfigBeanDefinitionParser());
	}

}
