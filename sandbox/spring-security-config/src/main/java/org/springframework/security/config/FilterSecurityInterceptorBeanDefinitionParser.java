package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.security.intercept.web.FilterInvocationDefinitionDecorator;
import org.springframework.security.intercept.web.FilterInvocationDefinitionSourceMapping;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.intercept.web.PathBasedFilterInvocationDefinitionMap;
import org.springframework.security.intercept.web.RegExpBasedFilterInvocationDefinitionMap;
import org.springframework.security.util.BeanDefinitionParserUtils;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.Assert;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * @author Vishal Puri
 * 
 */
public class FilterSecurityInterceptorBeanDefinitionParser extends AbstractBeanDefinitionParser {
	// ~ static initializers
	// ================================================================================================

	private static final String OBJECT_DEFINITION_SOURCE_PROPERTY = "objectDefinitionSource";

	private static final String OBJECT_DEFINITION_SOURCE_REF_ATTRIBUTE = "sourceBeanId";

	private static final String PATH_ATTRIBUTE = "path";

	private static final String REG_EX_ATTRIBUTE = "regularExpression";

	private static final String CONFIGURATION_ATTRIB_ATTRIBUTE = "attribute";

	// ~ Methods
	// ================================================================================================

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		return createBeanDefinitionForFilterSecurityInterceptor(element, parserContext);
	}

	protected static RootBeanDefinition createBeanDefinitionForFilterSecurityInterceptor(Element element,
			ParserContext parserContext) {
		RootBeanDefinition filterInvocationInterceptor = new RootBeanDefinition(FilterSecurityInterceptor.class);

		RootBeanDefinition accessDecisionManager = AuthorizationManagerBeanDefinitionParser
				.createAccessDecisionManagerAffirmativeBased();
		filterInvocationInterceptor.getPropertyValues()
				.addPropertyValue("accessDecisionManager", accessDecisionManager);

		FilterInvocationDefinitionDecorator source = new FilterInvocationDefinitionDecorator();
		FilterInvocationDefinitionSourceMapping mapping = new FilterInvocationDefinitionSourceMapping();
		List<FilterInvocationDefinitionSourceMapping> mappings = new ArrayList<FilterInvocationDefinitionSourceMapping>();

		Element firstChild = DomUtils.getChildElementByTagName(element, "url-mapping");
		// if 'url-mapping' element is defined
		if (firstChild != null) {

			if (BeanDefinitionParserUtils.setPropertyIfAvailable(firstChild, OBJECT_DEFINITION_SOURCE_REF_ATTRIBUTE,
					OBJECT_DEFINITION_SOURCE_PROPERTY, true/* RuntimeBeanReference */, filterInvocationInterceptor)) {
				return filterInvocationInterceptor;
			}

			// get 'uri-pattern' or 'path' attribute. not both can be specified
			// together
			List uriPatternElements = DomUtils.getChildElementsByTagName(firstChild, "uri-pattern");
			boolean patternToMatchCreated = false;

			Node patternAttribute = null;

			String url = "";

			boolean isPathFound = false;
			for (Iterator it = uriPatternElements.iterator(); it.hasNext();) {
				Element uriPattern = (Element) it.next();

				/* path or pattern - only one attribute is allowed */
				NamedNodeMap map = uriPattern.getAttributes();

				Assert.isTrue(map.getLength() == 1,
						"only 'path' or 'regularExperssion' attribute allowed with 'uri-pattern' tag");

				// check if typecreated variable is false then create a type and
				// store it somewhere and set typecreated variable to true
				if (!patternToMatchCreated) {
					// should only be one attribute "path" or
					// "regularExpression"
					patternAttribute = map.item(0);
					// set this variable to true
					patternToMatchCreated = true;
					// get the attributes and set the decoratd type
					// appropriately
					if (uriPattern.hasAttribute(PATH_ATTRIBUTE)) {
						isPathFound = true;
						url = uriPattern.getAttribute(PATH_ATTRIBUTE);
						source.setDecorated(new PathBasedFilterInvocationDefinitionMap());
					}
					else if (uriPattern.hasAttribute(REG_EX_ATTRIBUTE)) {
						url = uriPattern.getAttribute(REG_EX_ATTRIBUTE);
						source.setDecorated(new RegExpBasedFilterInvocationDefinitionMap());
					}
				}
				else {
					// type created already so check if it matches with the
					// current element
					// if it matches get the one attribute "path" or
					// "regularExpression" and apply as property
					uriPattern.getAttribute(patternAttribute.getLocalName());
					Assert
							.hasLength(uriPattern.getAttribute(patternAttribute.getLocalName()),
									" ALL uri-pattern tags in the url-mapping must be of the same  type (ie cannot mix a regular expression and Ant Path)");

					if (isPathFound) {
						url = uriPattern.getAttribute(PATH_ATTRIBUTE);
					}
					else {
						url = uriPattern.getAttribute(REG_EX_ATTRIBUTE);
					}

				}
				mapping.setUrl(url);
				// get child elements 'configuration-attribute'
				List configAttributes = DomUtils.getChildElementsByTagName(uriPattern, "configuration-attribute");

				for (Iterator iter = configAttributes.iterator(); iter.hasNext();) {
					Element configAttribute = (Element) iter.next();
					String configAttributeValue = configAttribute.getAttribute(CONFIGURATION_ATTRIB_ATTRIBUTE);
					mapping.addConfigAttribute(configAttributeValue);
				}

			}

		}
		// default properties
		else {
			String url1 = "/acegilogin.jsp";
			String value1 = "IS_AUTHENTICATED_ANONYMOUSLY";

			String url2 = "/**";
			String value2 = "IS_AUTHENTICATED_REMEMBERED";

			mapping.setUrl(url1);
			mapping.addConfigAttribute(value1);

			mapping.setUrl(url2);
			mapping.addConfigAttribute(value2);
		}

		mappings.add(mapping);
		source.setMappings(mappings);
		filterInvocationInterceptor.getPropertyValues().addPropertyValue(OBJECT_DEFINITION_SOURCE_PROPERTY,
				source.getDecorated());
		return filterInvocationInterceptor;
	}

}
