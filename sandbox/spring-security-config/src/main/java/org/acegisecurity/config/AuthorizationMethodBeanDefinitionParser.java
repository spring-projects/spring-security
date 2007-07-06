package org.acegisecurity.config;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.acegisecurity.annotation.SecurityAnnotationAttributes;
import org.acegisecurity.intercept.method.MethodDefinitionAttributes;
import org.acegisecurity.intercept.method.MethodDefinitionMap;
import org.acegisecurity.intercept.method.MethodDefinitionSource;
import org.acegisecurity.intercept.method.MethodDefinitionSourceMapping;
import org.acegisecurity.intercept.method.aopalliance.MethodDefinitionSourceAdvisor;
import org.acegisecurity.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.acegisecurity.intercept.method.aspectj.AspectJSecurityInterceptor;
import org.acegisecurity.runas.RunAsManagerImpl;
import org.acegisecurity.util.BeanDefinitionParserUtils;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.metadata.commons.CommonsAttributes;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * 
 * @author Vishal Puri
 * 
 */

public class AuthorizationMethodBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {
	// ~ static initializers
	// ================================================================================================

	public static final String ASPECTJ_ATTRIBUTE = "aspectj";

	public static final String SPRING_AOP_ATTRIBUTE = "springAop";

	public static final String SOURCE_ATTRIBUTE = "source";

	public static final String SOURCE_BEAN_REF = "sourceBeanId";

	public static final String ATTRIBUTE = "attribute";

	private static final String CONFIGURATION_ATTRIBUTE = "configuration-attribute";

	private static final String TYPE_ATTRIBUTE = "type";

	// ~ Method
	// ================================================================================================

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		// <security:authorization-joinpoint aspectj="false|true"
		// springAop="true|false">
		// one attribute allowed, aspectj or springAop
		Assert.isTrue(!(element.hasAttribute(SPRING_AOP_ATTRIBUTE) && element.hasAttribute(ASPECTJ_ATTRIBUTE)),
				"only one attribute (springAop or aspectj) is allowed");

		Element urlMappingEle = DomUtils.getChildElementByTagName(element, "url-mapping");

		String sourceBeanId = urlMappingEle.getAttribute(SOURCE_BEAN_REF);
		boolean isSourceBeanIdDefined = StringUtils.hasLength(sourceBeanId);

		if (!isValidConfiguration(urlMappingEle, isSourceBeanIdDefined)) {
			throw new IllegalArgumentException(
					" 'custom' value provided by 'source' attribute need to be selected when referring to a bean by 'sourceBeanId' attribute ");
		}

		if ((element.hasAttribute(ASPECTJ_ATTRIBUTE)) && element.getAttribute(ASPECTJ_ATTRIBUTE).equals("true")) {
			// create AspectJSecurityInterceptor
			if (isSourceBeanIdDefined)
				return createMethodSecurityInterceptor(AspectJSecurityInterceptor.class, new RuntimeBeanReference(
						sourceBeanId));

			return createMethodSecurityInterceptor(AspectJSecurityInterceptor.class, createObjectDefinitionSource(
					parserContext, urlMappingEle));
		}
		else if ((element.hasAttribute(SPRING_AOP_ATTRIBUTE))
				&& element.getAttribute(SPRING_AOP_ATTRIBUTE).equals("true")) {
			// create MethodSecurityInterceptor and
			// MethodDefinitionSourceAdvisor
			if (isSourceBeanIdDefined)
				return createMethodSecurityInterceptor(MethodSecurityInterceptor.class, new RuntimeBeanReference(
						sourceBeanId));

			return createMethodSecurityInterceptor(MethodSecurityInterceptor.class, createObjectDefinitionSource(
					parserContext, urlMappingEle));
		}
		return null;
	}

	/**
	 * @param parserContext
	 * @param firstChild
	 * @param sourceValue
	 * @throws BeanDefinitionStoreException
	 */
	private MethodDefinitionSource createObjectDefinitionSource(ParserContext parserContext, Element element)
			throws BeanDefinitionStoreException {
		String sourceValue = element.getAttribute(SOURCE_ATTRIBUTE);
		if (sourceValue.equals("xml")) {
			// create MethodDefinitionSourceEditor
			Element methodPattern = DomUtils.getChildElementByTagName(element, "method-pattern");
			String methodToProtect = methodPattern.getAttribute(TYPE_ATTRIBUTE);

			MethodDefinitionSourceMapping mapping = new MethodDefinitionSourceMapping();
			MethodDefinitionMap source = new MethodDefinitionMap();
			List<MethodDefinitionSourceMapping> mappings = new ArrayList<MethodDefinitionSourceMapping>();

			mapping.setMethodName(methodToProtect);

			List configAttributes = DomUtils.getChildElementsByTagName(methodPattern, CONFIGURATION_ATTRIBUTE);

			for (Iterator iter = configAttributes.iterator(); iter.hasNext();) {
				Element configAttribute = (Element) iter.next();
				String configAttributeValue = configAttribute.getAttribute(ATTRIBUTE);
				mapping.addConfigAttribute(configAttributeValue);
			}
			mappings.add(mapping);
			source.setMappings(mappings);
			return source;
		}
		else if (sourceValue.equals("annotations")) {
			BeanDefinitionParserUtils.registerBeanDefinition(parserContext, new RootBeanDefinition(
					DefaultAdvisorAutoProxyCreator.class));

			MethodDefinitionAttributes source = new MethodDefinitionAttributes();
			SecurityAnnotationAttributes attributes = new SecurityAnnotationAttributes();
			source.setAttributes(attributes);
			return source;
		}
		else if (sourceValue.equals("attributes")) {
			// create CommonsAttributes
			CommonsAttributes attributes = new CommonsAttributes();
			// objectDefinitionSource and inject attributes
			MethodDefinitionAttributes source = new MethodDefinitionAttributes();
			source.setAttributes(attributes);

			// register DefaultAdvisorAutoProxyCreator with parseContext
			BeanDefinitionParserUtils.registerBeanDefinition(parserContext, new RootBeanDefinition(
					DefaultAdvisorAutoProxyCreator.class));

			// register MethodDefinitionSourceAdvisor autowire="constructor"
			registerMethodDefinitionSourceAdvisor(parserContext);
			return source;
		}
		return null;
	}

	/**
	 * @param parserContext
	 * @throws BeanDefinitionStoreException
	 */
	private void registerMethodDefinitionSourceAdvisor(ParserContext parserContext) throws BeanDefinitionStoreException {
		RootBeanDefinition methodSecurityAdvisor = new RootBeanDefinition(MethodDefinitionSourceAdvisor.class);
		methodSecurityAdvisor.setAutowireMode(AbstractBeanDefinition.AUTOWIRE_CONSTRUCTOR);
		BeanDefinitionParserUtils.registerBeanDefinition(parserContext, methodSecurityAdvisor);
	}

	/**
	 * Creates BeanDefinition for MethodSecurityInterceptor
	 * MethodSecurityInterceptor autodetects 'authenticationManager' and
	 * 'accessDecisionManager'
	 * @param name
	 * 
	 * @return
	 */
	private RootBeanDefinition createMethodSecurityInterceptor(Class interceptorType, Object object) {
		Assert.notNull(object, "objectDefinitionSource required");
		RootBeanDefinition securityInterceptor = new RootBeanDefinition(interceptorType);
		if (RuntimeBeanReference.class.isAssignableFrom(object.getClass())) {
			RuntimeBeanReference source = (RuntimeBeanReference) object;
			securityInterceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", source);
		}
		else if (MethodDefinitionSource.class.isAssignableFrom(object.getClass())) {
			MethodDefinitionSource source = (MethodDefinitionSource) object;
			securityInterceptor.getPropertyValues().addPropertyValue("objectDefinitionSource", source);
		}
		securityInterceptor.getPropertyValues().addPropertyValue("validateConfigAttributes", Boolean.FALSE);
		RootBeanDefinition runAsManager = createRunAsManager();
		securityInterceptor.getPropertyValues().addPropertyValue("runAsManager", runAsManager);
		return securityInterceptor;
	}

	private RootBeanDefinition createRunAsManager() {
		RootBeanDefinition runAsManager = new RootBeanDefinition(RunAsManagerImpl.class);
		runAsManager.getPropertyValues().addPropertyValue("key", "my_run_as_password");
		return runAsManager;
	}

	/**
	 * Checks if 'custom' option is picked for 'source' attribute when
	 * 'sourceBeanId' attribute is provided.
	 * <p>
	 * The valid configuration example:<br/> &lt;security:url-mapping
	 * source="custom" sourceBeanId="referenceToObjectDefinitionSource"/&gt;
	 * </p>
	 * @param urlMappingElement
	 * @return boolean Returns 'true' if configuration is accepted otherwise
	 * returns 'false'
	 */
	private boolean isValidConfiguration(Element urlMappingElement, boolean isRefDefined) {
		Assert.notNull(urlMappingElement, "invalid tag - expected 'url-mapping' ");
		Assert.isTrue(urlMappingElement.getLocalName().equals("url-mapping"), "invalid tag - expected 'url-mapping' ");
		if (isRefDefined && (urlMappingElement.getAttribute(SOURCE_ATTRIBUTE).compareTo("custom") != 0)) {
			return false;
		}
		return true;
	}
}
