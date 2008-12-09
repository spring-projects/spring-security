package org.springframework.security.authoritymapping;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;

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
 * This implementation for the MappableAttributesRetriever interface retrieves the
 * list of mappable attributes from an XML file.
 * <p>
 * This class is defined as abstract because it is too generic to be used
 * directly. As this class is usually used to read very specific XML files (e.g.
 * web.xml, ejb-jar.xml), subclasses should usually define the actual
 * XPath-expression to use, and define a more specifically named setter for the
 * XML InputStream (e.g. setWebXmlInputStream).
 *
 * @author Ruud Senden
 * @since 2.0
 */
public abstract class XmlMappableAttributesRetriever implements MappableAttributesRetriever, InitializingBean {
    private static final Log logger = LogFactory.getLog(XmlMappableAttributesRetriever.class);

    private Set<String> mappableAttributes = null;

    private InputStream xmlInputStream = null;

    private String xpathExpression = null;

    private boolean closeInputStream = true;

    /**
     * Check whether all required properties have been set.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(xmlInputStream, "An XML InputStream must be set");
        Assert.notNull(xpathExpression, "An XPath expression must be set");
        mappableAttributes = Collections.unmodifiableSet(getMappableAttributes(xmlInputStream));
    }

    public Set<String> getMappableAttributes() {
        return mappableAttributes;
    }

    /**
     * Get the mappable roles from the specified XML document.
     */
    private Set<String> getMappableAttributes(InputStream aStream) {
        if (logger.isDebugEnabled()) {
            logger.debug("Reading mappable attributes from XML document");
        }
        try {
            Document doc = getDocument(aStream);
            Set<String> roles = getMappableAttributes(doc);
            if (logger.isDebugEnabled()) {
                logger.debug("Mappable attributes from XML document: " + roles);
            }
            return roles;
        } finally {
            if (closeInputStream) {
                try {
                    aStream.close();
                } catch (Exception e) {
                    logger.debug("Input stream could not be closed", e);
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
     * @param doc The Document from which to read the list of roles
     * @return String[] the list of roles.
     * @throws JaxenException
     */
    @SuppressWarnings("unchecked")
    private Set<String> getMappableAttributes(Document doc) {
        try {
            DOMXPath xpath = new DOMXPath(xpathExpression);
            List<Node> roleElements = xpath.selectNodes(doc);
            Set<String> roles = new HashSet<String>(roleElements.size());

            for (Node n : roleElements) {
                roles.add(n.getNodeValue());
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
