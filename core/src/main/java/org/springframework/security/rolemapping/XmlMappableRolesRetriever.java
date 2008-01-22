package org.springframework.security.rolemapping;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaxen.JaxenException;
import org.jaxen.dom.DOMXPath;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * This implementation for the MappableRolesRetriever interface retrieves the
 * list of mappable roles from an XML file.
 * 
 * This class is defined as abstract because it is too generic to be used
 * directly. As this class is usually used to read very specific XML files (e.g.
 * web.xml, ejb-jar.xml), subclasses should usually define the actual
 * XPath-expression to use, and define a more specifically named setter for the
 * XML InputStream (e.g. setWebXmlInputStream).
 */
public abstract class XmlMappableRolesRetriever implements MappableRolesRetriever, InitializingBean {
	private static final Log LOG = LogFactory.getLog(XmlMappableRolesRetriever.class);

	private String[] mappableRoles = null;

	private InputStream xmlInputStream = null;

	private String xpathExpression = null;

	private boolean closeInputStream = true;

	/**
	 * Check whether all required properties have been set.
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(xmlInputStream, "An XML InputStream must be set");
		Assert.notNull(xpathExpression, "An XPath expression must be set");
		mappableRoles = getMappableRoles(xmlInputStream);
	}

	public String[] getMappableRoles() {
		String[] copy = new String[mappableRoles.length];
		System.arraycopy(mappableRoles, 0, copy, 0, copy.length);
		return copy;
	}

	/**
	 * Get the mappable roles from the specified XML document.
	 */
	private String[] getMappableRoles(InputStream aStream) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Reading mappable roles from XML document");
		}
		try {
			Document doc = getDocument(aStream);
			String[] roles = getMappableRoles(doc);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Mappable roles from XML document: " + ArrayUtils.toString(roles));
			}
			return roles;
		} finally {
			if (closeInputStream) {
				try {
					aStream.close();
				} catch (Exception e) {
					LOG.debug("Input stream could not be closed", e);
				}
			}
		}

	}

	/**
	 * @return Document for the specified InputStream
	 */
	private Document getDocument(InputStream aStream) {
		Document doc;
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setValidating(false);
			DocumentBuilder db = factory.newDocumentBuilder();
			db.setEntityResolver(new MyEntityResolver());
			doc = db.parse(new IgnoreCloseInputStream(aStream));
			return doc;
		} catch (FactoryConfigurationError e) {
			throw new RuntimeException("Unable to parse document object", e);
		} catch (ParserConfigurationException e) {
			throw new RuntimeException("Unable to parse document object", e);
		} catch (SAXException e) {
			throw new RuntimeException("Unable to parse document object", e);
		} catch (IOException e) {
			throw new RuntimeException("Unable to parse document object", e);
		}
	}

	/**
	 * @param doc
	 *            The Document from which to read the list of roles
	 * @return String[] the list of roles.
	 * @throws JaxenException
	 */
	private String[] getMappableRoles(Document doc) {
		try {
			DOMXPath xpath = new DOMXPath(xpathExpression);
			List roleElements = xpath.selectNodes(doc);
			String[] roles = new String[roleElements.size()];
			for (int i = 0; i < roles.length; i++) {
				roles[i] = ((Node) roleElements.get(i)).getNodeValue();
			}
			return roles;
		} catch (JaxenException e) {
			throw new RuntimeException("Unable to retrieve mappable roles", e);
		} catch (DOMException e) {
			throw new RuntimeException("Unable to retrieve mappable roles", e);
		}
	}

	/**
	 * Subclasses should provide this method with a more specific name (e.g.
	 * indicating the type of XML file the subclass expects, like
	 * setWebXmlInputStream).
	 */
	protected void setXmlInputStream(InputStream aStream) {
		this.xmlInputStream = aStream;
	}

	/**
	 * Subclasses usually want to set an XPath expression by themselves (e.g.
	 * not user-configurable). However subclasses may provide configuration
	 * options to for example choose from a list of predefined XPath expressions
	 * (e.g. to support multiple versions of the same type of XML file), as such
	 * we provide a setter instead of mandatory constructor argument.
	 */
	protected void setXpathExpression(String anXpathExpression) {
		xpathExpression = anXpathExpression;
	}

	/**
	 * Define whether the provided InputStream must be closed after reading it.
	 */
	public void setCloseInputStream(boolean b) {
		closeInputStream = b;
	}

	/**
	 * We do not need to resolve external entities, so just return an empty
	 * String.
	 */
	private static final class MyEntityResolver implements EntityResolver {
		public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
			return new InputSource(new StringReader(""));
		}
	}

	public static final class IgnoreCloseInputStream extends FilterInputStream {
		public IgnoreCloseInputStream(InputStream stream) {
			super(stream);
		}

		public void close() throws IOException {
			// do nothing
		}
	}
}
