/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* $Id$ */

package org.asciidoctor.gradle;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.ErrorListener;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.URIResolver;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.fop.ResourceEventProducer;
import org.apache.fop.apps.FOPException;
import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.render.awt.viewer.Renderable;

/**
 * Class for handling files input from command line
 * either with XML and XSLT files (and optionally xsl
 * parameters) or FO File input alone.
 */
public class InputHandler implements ErrorListener, Renderable {

    /** original source file */
    protected File sourcefile;
    private File stylesheet;  // for XML/XSLT usage
    private Vector xsltParams; // for XML/XSLT usage
    private EntityResolver entityResolver = null;
    private URIResolver uriResolver = null;

    /** the logger */
    protected Log log = LogFactory.getLog(InputHandler.class);

    /**
     * Constructor for XML->XSLT->FO input
     *
     * @param xmlfile XML file
     * @param xsltfile XSLT file
     * @param params Vector of command-line parameters (name, value,
     *      name, value, ...) for XSL stylesheet, null if none
     */
    public InputHandler(File xmlfile, File xsltfile, Vector params) {
        if(!xsltfile.exists()) {
            throw new RuntimeException("Couldn't find "+ xsltfile);
        }
        sourcefile  = xmlfile;
        stylesheet = xsltfile;
        xsltParams = params;
    }

    /**
     * Constructor for FO input
     * @param fofile the file to read the FO document.
     */
    public InputHandler(File fofile) {
        sourcefile = fofile;
    }

    /**
     * Generate a document, given an initialized Fop object
     * @param userAgent the user agent
     * @param outputFormat the output format to generate (MIME type, see MimeConstants)
     * @param out the output stream to write the generated output to (may be null if not applicable)
     * @throws FOPException in case of an error during processing
     */
    public void renderTo(FOUserAgent userAgent, String outputFormat, OutputStream out)
                throws FOPException {

        FopFactory factory = userAgent.getFactory();
        Fop fop;
        if (out != null) {
            fop = factory.newFop(outputFormat, userAgent, out);
        } else {
            fop = factory.newFop(outputFormat, userAgent);
        }

        // if base URL was not explicitly set in FOUserAgent, obtain here
        if (fop.getUserAgent().getBaseURL() == null && sourcefile != null) {
            String baseURL = null;

            try {
                baseURL = new File(sourcefile.getAbsolutePath())
                        .getParentFile().toURI().toURL().toExternalForm();
            } catch (Exception e) {
                baseURL = "";
            }
            fop.getUserAgent().setBaseURL(baseURL);
        }

        // Resulting SAX events (the generated FO) must be piped through to FOP
        Result res = new SAXResult(fop.getDefaultHandler());

        transformTo(res);
    }

    /** {@inheritDoc} */
    public void renderTo(FOUserAgent userAgent, String outputFormat) throws FOPException {
        renderTo(userAgent, outputFormat, null);
    }

    /**
     * In contrast to render(Fop) this method only performs the XSLT stage and saves the
     * intermediate XSL-FO file to the output file.
     * @param out OutputStream to write the transformation result to.
     * @throws FOPException in case of an error during processing
     */
    public void transformTo(OutputStream out) throws FOPException {
        Result res = new StreamResult(out);
        transformTo(res);
    }

    /**
     * Creates a Source for the main input file. Processes XInclude if
     * available in the XML parser.
     *
     * @return the Source for the main input file
     */
    protected Source createMainSource() {
        Source source;
        InputStream in;
        String uri;
        if (this.sourcefile != null) {
            try {
                in = new java.io.FileInputStream(this.sourcefile);
                uri = this.sourcefile.toURI().toASCIIString();
            } catch (FileNotFoundException e) {
                //handled elsewhere
                return new StreamSource(this.sourcefile);
            }
        } else {
            in = System.in;
            uri = null;
        }
        try {
            InputSource is = new InputSource(in);
            is.setSystemId(uri);
            XMLReader xr = getXMLReader();
            if (entityResolver != null) {
                xr.setEntityResolver(entityResolver);
            }
            source = new SAXSource(xr, is);
        } catch (SAXException e) {
            if (this.sourcefile != null) {
                source = new StreamSource(this.sourcefile);
            } else {
                source = new StreamSource(in, uri);
            }
        } catch (ParserConfigurationException e) {
            if (this.sourcefile != null) {
                source = new StreamSource(this.sourcefile);
            } else {
                source = new StreamSource(in, uri);
            }
        }
        return source;
    }

    /**
     * Creates a catalog resolver and uses it for XML parsing and XSLT URI resolution.
     * Tries the Apache Commons Resolver, and if unsuccessful,
     * tries the same built into Java 6.
     * @param userAgent the user agent instance
     */
    public void createCatalogResolver(FOUserAgent userAgent) {
        String[] classNames = new String[] {
                "org.apache.xml.resolver.tools.CatalogResolver",
                "com.sun.org.apache.xml.internal.resolver.tools.CatalogResolver"};
        ResourceEventProducer eventProducer
            = ResourceEventProducer.Provider.get(userAgent.getEventBroadcaster());
        Class resolverClass = null;
        for (int i = 0; i < classNames.length && resolverClass == null; ++i) {
            try {
                resolverClass = Class.forName(classNames[i]);
            } catch (ClassNotFoundException e) {
                // No worries
            }
        }
        if (resolverClass == null) {
            eventProducer.catalogResolverNotFound(this);
            return;
        }
        try {
            entityResolver = (EntityResolver) resolverClass.newInstance();
            uriResolver = (URIResolver) resolverClass.newInstance();
        } catch (InstantiationException e) {
            log.error("Error creating the catalog resolver: " + e.getMessage());
            eventProducer.catalogResolverNotCreated(this, e.getMessage());
        } catch (IllegalAccessException e) {
            log.error("Error creating the catalog resolver: " + e.getMessage());
            eventProducer.catalogResolverNotCreated(this, e.getMessage());
        }
    }

    /**
     * Creates a Source for the selected stylesheet.
     *
     * @return the Source for the selected stylesheet or null if there's no stylesheet
     */
    protected Source createXSLTSource() {
        Source xslt = null;
        if (this.stylesheet != null) {
            if (entityResolver != null) {
                try {
                    InputSource is = new InputSource(this.stylesheet.getPath());
                    XMLReader xr = getXMLReader();
                    xr.setEntityResolver(entityResolver);
                    xslt = new SAXSource(xr, is);
                } catch (SAXException e) {
                    // return StreamSource
                } catch (ParserConfigurationException e) {
                    // return StreamSource
                }
            }
            if (xslt == null) {
                xslt = new StreamSource(this.stylesheet);
            }
        }
        return xslt;
    }

    private XMLReader getXMLReader() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://xml.org/sax/features/namespaces", true);
        spf.setFeature("http://apache.org/xml/features/xinclude", true);
        XMLReader xr = spf.newSAXParser().getXMLReader();
        return xr;
    }

    /**
     * Transforms the input document to the input format expected by FOP using XSLT.
     * @param result the Result object where the result of the XSL transformation is sent to
     * @throws FOPException in case of an error during processing
     */
    protected void transformTo(Result result) throws FOPException {
        try {
            // Setup XSLT
            System.setProperty("javax.xml.transform.TransformerFactory", "org.apache.xalan.processor.TransformerFactoryImpl");
            TransformerFactory factory = TransformerFactory.newInstance();
            if (uriResolver != null) {
                factory.setURIResolver(uriResolver);
            }
            factory.setErrorListener(this);
            Transformer transformer;

            Source xsltSource = createXSLTSource();
            if (xsltSource == null) {   // FO Input
                transformer = factory.newTransformer();
            } else {    // XML/XSLT input
                transformer = factory.newTransformer(xsltSource);

                // Set the value of parameters, if any, defined for stylesheet
                if (xsltParams != null) {
                    for (int i = 0; i < xsltParams.size(); i += 2) {
                        transformer.setParameter((String) xsltParams.elementAt(i),
                            (String) xsltParams.elementAt(i + 1));
                    }
                }
            }
            transformer.setErrorListener(this);

            // Create a SAXSource from the input Source file
            Source src = createMainSource();

            // Start XSLT transformation and FOP processing
            transformer.transform(src, result);

        } catch (Exception e) {
            throw new FOPException(e);
        }
    }

    // --- Implementation of the ErrorListener interface ---

    /**
     * {@inheritDoc}
     */
    public void warning(TransformerException exc) {
        log.warn(exc.getLocalizedMessage());
    }

    /**
     * {@inheritDoc}
     */
    public void error(TransformerException exc) {
        log.error(exc.toString());
    }

    /**
     * {@inheritDoc}
     */
    public void fatalError(TransformerException exc)
            throws TransformerException {
        throw exc;
    }

}