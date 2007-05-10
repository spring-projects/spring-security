/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.providers.dao.DaoAuthenticationProvider;
import org.acegisecurity.providers.dao.salt.ReflectionSaltSource;
import org.acegisecurity.providers.dao.salt.SystemWideSaltSource;
import org.acegisecurity.providers.encoding.Md5PasswordEncoder;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author vpuri
 * 
 */
public class AuthenticationRepositoryBeanDefinitionParser extends AbstractBeanDefinitionParser   {

	// ~~ Instance Variables

	private static final String REPOSITORY_BEAN_REF = "repositoryBeanRef";

	private static final String USER_DETAILS_SERVICE = "userDetailsService";

	private static final String SALT_SOURCE_ELEMENT = "salt-source";

	private static final String SALT_SOURCE_REF = "saltSourceBeanRef";

	private static final String SYSTEM_WIDE_SALT_SOURCE = "system-wide";

	private static final String REFLECTION_SALT_SOURCE = "reflection";
	
	private static final String PASSWORD_ENCODER_ELEMENT = "password-encoder";
	
	private static final String PASSWORD_ENCODER_REF = "encoderBeanRef";
	
	private static final String PASSWORD_ENCODER = "encoder";
	
	public static final String AUTOWIRE_AUTODETECT_VALUE = "autodetect";
	
	
	
	// ~~ Methods
	/**
	 * TODO: Document Me !!!
	 */
	public AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		Assert.notNull(parserContext, "ParserContext must not be null");
		
		RootBeanDefinition repositoryBeanDef = new RootBeanDefinition(DaoAuthenticationProvider.class);
		
		// if repositoryBeanRef is specified use its referred bean
		String userDetailsRef = element.getAttribute(REPOSITORY_BEAN_REF);
		if (StringUtils.hasLength(userDetailsRef)) {
			repositoryBeanDef.getPropertyValues().addPropertyValue(USER_DETAILS_SERVICE,
					new RuntimeBeanReference(userDetailsRef));
		}
		else {
			// autodetect userDetailsService from App Context ? or we could even create this UserDetailsService BD with autodetection of dataSource hahaha Magic !!!
			//repositoryBeanDef.getPropertyValues().addPropertyValue(USER_DETAILS_SERVICE,		new RuntimeBeanReference(USER_DETAILS_SERVICE));
			repositoryBeanDef.setAutowireMode(AbstractBeanDefinition.AUTOWIRE_AUTODETECT);
		}
		//	check if saltSource is defined
		Element saltSourceEle = DomUtils.getChildElementByTagName(element, SALT_SOURCE_ELEMENT);
		setSaltSourceProperty(repositoryBeanDef, saltSourceEle);
		
		Element passwordEncoderEle = DomUtils.getChildElementByTagName(element, PASSWORD_ENCODER_ELEMENT);
		setPasswordEncoderProperty(repositoryBeanDef, passwordEncoderEle);
		
		return repositoryBeanDef;
	}
	
	/**
	 * 
	 * @param repositoryBeanDef
	 * @param element
	 */
	private void setSaltSourceProperty(RootBeanDefinition repositoryBeanDef, Element element) {
		if(element != null) {
			setBeanReferenceOrInnerBeanDefinitions(repositoryBeanDef, element, "saltSource",element.getAttribute(SALT_SOURCE_REF) );
		} 
	}
	
	/**
	 * 
	 * @param repositoryBeanDef
	 * @param element
	 */
	private void setPasswordEncoderProperty(RootBeanDefinition repositoryBeanDef, Element element) {
		if(element != null) {
			setBeanReferenceOrInnerBeanDefinitions(repositoryBeanDef, element, "passwordEncoder",element.getAttribute(PASSWORD_ENCODER_REF) );
		} 
	}
	/**
	 * 
	 * @param repositoryBeanDef
	 * @param element
	 * @param property
	 * @param reference
	 */
	private void setBeanReferenceOrInnerBeanDefinitions(RootBeanDefinition repositoryBeanDef, Element element ,String property, String reference) {		
			// check for encoderBeanRef attribute
			if (StringUtils.hasLength(reference)) {
				repositoryBeanDef.getPropertyValues().addPropertyValue(property, new RuntimeBeanReference(reference));
			}
			else {
				doSetInnerBeanDefinitions(repositoryBeanDef, element);
			}
	}

	/**
	 * 
	 * @param repositoryBeanDef
	 * @param element
	 */
	private void doSetInnerBeanDefinitions(RootBeanDefinition repositoryBeanDef, Element element) {
		NodeList children = element.getChildNodes();
		for (int i = 0, n = children.getLength(); i < n; i++) {
			Node node = children.item(i);

			if (node.getNodeType() == Node.ELEMENT_NODE) {
				Element childElement = (Element) node;
				RootBeanDefinition innerBeanDefinition = null;

				if (SYSTEM_WIDE_SALT_SOURCE.equals(node.getLocalName())) {
					innerBeanDefinition = createSystemWideSaltSource(childElement);
					repositoryBeanDef.getPropertyValues().addPropertyValue("saltSource", innerBeanDefinition);
				}
				else if (REFLECTION_SALT_SOURCE.equals(node.getLocalName())) {
					innerBeanDefinition = createReflectionSaltSource(childElement);
					repositoryBeanDef.getPropertyValues().addPropertyValue("saltSource", innerBeanDefinition);
				}
				if (PASSWORD_ENCODER.equals(node.getLocalName())) {
					RootBeanDefinition passwordEncoderInnerBeanDefinition = createPasswordEncoder(childElement);
					repositoryBeanDef.getPropertyValues().addPropertyValue("passwordEncoder", passwordEncoderInnerBeanDefinition);
				}
			}
		}
	}
	
	/**
	 * 
	 * @param childElement
	 * @return
	 */
	private RootBeanDefinition createPasswordEncoder(Element childElement) {
		String attributeValue = childElement.getAttribute("method");
		RootBeanDefinition definition = null;
		// TODO: add other encoders support
		if(attributeValue.equals("md5")){
			 definition = new RootBeanDefinition(Md5PasswordEncoder.class);
		}
		return definition;
	}
	
	/**
	 * 
	 * @param saltSourceTypeElement
	 * @return
	 */
	private RootBeanDefinition createReflectionSaltSource(Element saltSourceTypeElement) {
		RootBeanDefinition definition = new RootBeanDefinition(ReflectionSaltSource.class);
		definition.getPropertyValues().addPropertyValue("userPropertyToUse", saltSourceTypeElement.getAttribute("userPropertyToUse"));
		return definition;
	}
	
	/**
	 * 
	 * @param saltSourceTypeElement
	 * @return
	 */
	private RootBeanDefinition createSystemWideSaltSource( Element saltSourceTypeElement) {
		RootBeanDefinition definition = new RootBeanDefinition(SystemWideSaltSource.class);
		definition.getPropertyValues().addPropertyValue("systemWideSalt", saltSourceTypeElement.getAttribute("systemWideSalt"));
		return definition;
	}

	
}


