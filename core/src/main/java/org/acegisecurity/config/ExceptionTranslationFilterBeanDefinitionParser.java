/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.ui.AccessDeniedHandlerImpl;
import org.acegisecurity.ui.ExceptionTranslationFilter;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Basically accessDeniedUrl is optional, we if unspecified impl will
 * auto-detect any AccessDeniedHandler in ctx and use it; alternately if there
 * are > 1 such handlers, we can nominate the one to use via
 * accessDeniedBeanRef;
 * 
 * @author vpuri
 * @since
 */
public class ExceptionTranslationFilterBeanDefinitionParser extends AbstractBeanDefinitionParser {

	private static final String ACCESS_DENIED = "access-denied";

	private static final String ACCESS_DENIED_REF = "accessDeniedBeanRef";

	private static final String ACCESS_DENIED_URL = "accessDeniedUrl";
	
	private static final String ENTRY_POINT = "entry-point";
	
	private static final String ENTRY_POINT_REF ="entryPointBeanRef";

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		RootBeanDefinition exceptionFilterDef = new RootBeanDefinition(ExceptionTranslationFilter.class);

		// add handler
		Element accessDeniedElement = DomUtils.getChildElementByTagName(element, ACCESS_DENIED);
		setAccessDeniedHandlerProperty(parserContext, exceptionFilterDef, accessDeniedElement);
		
		Element entryPointElement = DomUtils.getChildElementByTagName(element, ENTRY_POINT);
		setEntryPointProperty(exceptionFilterDef, entryPointElement);
		
		return exceptionFilterDef;
	}

	private void setEntryPointProperty(RootBeanDefinition exceptionFilterDef, Element entryPointElement) {
		if (entryPointElement != null) {
			setBeanReferenceOrInnerBeanDefinitions(exceptionFilterDef, entryPointElement, "authenticationEntryPoint",
					entryPointElement.getAttribute(ENTRY_POINT_REF));
		}
	}

	/**
	 * 
	 * @param parserContext
	 * @param repositoryBeanDef
	 * @param element
	 */
	private void setAccessDeniedHandlerProperty(ParserContext parserContext, RootBeanDefinition exceptionFilterDef,
			Element accessDeniedElement) {
		if (accessDeniedElement != null) {
			setBeanReferenceOrInnerBeanDefinitions(exceptionFilterDef, accessDeniedElement, "accessDeniedHandler",
					accessDeniedElement.getAttribute(ACCESS_DENIED_REF));
		}
		else {
			// register BFPP to check if handler exist in application context,
			// if > 1 throw error saying ref should be specified as there are
			// more than one
			RootBeanDefinition accessDeniedHandlerLocatorBeanDef = new RootBeanDefinition(
					AccessDeniedHandlerBeanDefinitionLocator.class);
			parserContext.getReaderContext().registerWithGeneratedName(accessDeniedHandlerLocatorBeanDef);
		}
	}

	/**
	 * 
	 * @param repositoryBeanDef
	 * @param element
	 * @param property
	 * @param reference
	 */
	private void setBeanReferenceOrInnerBeanDefinitions(RootBeanDefinition exceptionFilterDef,
			Element element, String property, String beanRef) {
		// check for encoderBeanRef attribute
		if (StringUtils.hasLength(beanRef)) {
			exceptionFilterDef.getPropertyValues().addPropertyValue(property,
					new RuntimeBeanReference(beanRef));
		}
		else {
			doSetInnerBeanDefinitions(exceptionFilterDef, element, property);
		}
	}

	/**
	 * 
	 * @param repositoryBeanDef
	 * @param element
	 * @param property
	 */
	private void doSetInnerBeanDefinitions(RootBeanDefinition exceptionFilterDef, Element accessDeniedElement,
			String property) {
		RootBeanDefinition accessDeniedHandlerBeanDef = new RootBeanDefinition(AccessDeniedHandlerImpl.class);
		setPropertyIfAvailable(accessDeniedElement, ACCESS_DENIED_URL, "errorPage", accessDeniedHandlerBeanDef);
		exceptionFilterDef.getPropertyValues().addPropertyValue(property, accessDeniedHandlerBeanDef);

	}

	private void setPropertyIfAvailable(Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			definition.getPropertyValues().addPropertyValue(property, propertyValue);
		}
	}
}
