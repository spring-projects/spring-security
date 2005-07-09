package net.sf.acegisecurity.util;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.Assert;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A utility to translate a web.xml file into a set of acegi security spring beans.
 *
 * Also produces a new "acegified" web.xml file with the necessary filters installed
 * and the security elements defined by the servlet DTD removed.
 *
 * <p>
 * This class wraps the XSL transform which actually does most of the work.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class WebXmlToAcegiSecurityConverter {
    private static final String WEB_TO_SPRING_XSL_FILE = "web-to-spring.xsl";
    private static final String NEW_WEB_XSLT_FILE = "acegi-web.xsl";

    private Transformer acegiSecurityTransformer, newWebXmlTransformer;
    private DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

    /**
     * The name of the spring-beans file which the beans will be stored in.
     * This is required when writing the new web.xml content.
     */
    private String acegiOutputFileName = "applicationContext-acegi-security.xml";

    /** The web.xml content to be converted */
    private DOMSource xmlSource;
    /** The results of the conversion */
    private String newWebXml, acegiBeansXml;

    public WebXmlToAcegiSecurityConverter() throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();

        acegiSecurityTransformer = tf.newTransformer(createTransformerSource(WEB_TO_SPRING_XSL_FILE));
        newWebXmlTransformer = tf.newTransformer(createTransformerSource(NEW_WEB_XSLT_FILE));
    }

    private Source createTransformerSource(String fileName) throws IOException {
        ClassPathResource resource = new ClassPathResource(fileName);
        return new StreamSource(resource.getInputStream());
    }

    /**
     * Performs the transformations on the input source.
     * Creates new web.xml content and a set of acegi-security Spring beans which can be
     * accessed through the appropriate getter methods.
     */
    public void doConversion() throws IOException, TransformerException {
        Assert.notNull(xmlSource, "The XML input must be set, either as a Node or an InputStream");

        // Create the modified web.xml file
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        newWebXmlTransformer.setParameter("acegi-security-context-file", acegiOutputFileName);
//        newWebXmlTransformer.setParameter("cas-proxy-url", "http://localhost:8433/cas/proxy");        
        newWebXmlTransformer.transform(xmlSource, new StreamResult(output));
        newWebXml = output.toString();
        output.reset();

        acegiSecurityTransformer.transform(xmlSource, new StreamResult(output));
        acegiBeansXml = output.toString();
    }

    /** set the input as an InputStream */
    public void setInput(InputStream xmlIn) throws Exception {
        DocumentBuilder db = dbf.newDocumentBuilder();
        setInput(db.parse(xmlIn));
    }

    /** set the input as an XML node */
    public void setInput(Node webXml) {
        this.xmlSource = new DOMSource(webXml);
    }

    public String getAcegiOutputFileName() {
        return acegiOutputFileName;
    }

    public void setAcegiOutputFileName(String acegiOutputFileName) {
        this.acegiOutputFileName = acegiOutputFileName;
    }

    /** Returns the converted web.xml content */
    public String getNewWebXml() {
        return newWebXml;
    }

    /**
     * Returns the created spring-beans xml content which should be used in
     * the application context file.
     */
    public String getAcegiBeansXml() {
        return acegiBeansXml;
    }

}
