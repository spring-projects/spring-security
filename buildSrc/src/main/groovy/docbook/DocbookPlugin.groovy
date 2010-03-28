package docbook;

import org.gradle.api.Plugin;
import org.gradle.api.GradleException;
import org.gradle.api.DefaultTask;
import org.gradle.api.Task;
import org.gradle.api.Project;
import org.gradle.api.Action;
import org.gradle.api.tasks.*;
import org.gradle.api.file.FileCollection;

import org.xml.sax.XMLReader;
import org.xml.sax.InputSource;
import org.apache.xml.resolver.CatalogManager;
import org.apache.xml.resolver.tools.CatalogResolver;

import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.*;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import java.net.*;

import org.apache.fop.apps.*;

import com.icl.saxon.TransformerFactoryImpl;

/**
 * Gradle Docbook plugin implementation.
 * <p>
 * Creates three tasks: docbookHtml, docbookHtmlSingle and docbookPdf. Each task takes a single File on
 * which it operates.
 */
class DocbookPlugin implements Plugin<Project> {
    public void apply(Project project) {
        // Add the plugin tasks to the project
        Task docbookHtml = project.tasks.add('docbookHtml', DocbookHtml.class);
        docbookHtml.setDescription('Generates chunked docbook html output');

        Task docbookHtmlSingle = project.tasks.add('docbookHtmlSingle', Docbook.class);
        docbookHtmlSingle.setDescription('Generates single page docbook html output')
        docbookHtmlSingle.suffix = '-single'

        Task docbookFoPdf = project.tasks.add("docbookFoPdf", DocbookFoPdf.class);
        docbookFoPdf.setDescription('Generates PDF output');
        docbookFoPdf.extension = 'fo'
    }
}

/**
 */
public class Docbook extends DefaultTask {

    @Input
    String extension = 'html';

    @Input
    String suffix = '';

    @Input
    boolean XIncludeAware = true;

    @Input
    boolean highlightingEnabled = true;

    String admonGraphicsPath;

    @InputDirectory
    File sourceDirectory = new File(project.getProjectDir(), "src/docbook");

    @Input
    String sourceFileName;

    @InputFile
    File stylesheet;

    @OutputDirectory
    File docsDir = new File(project.getBuildDir(), "docs");

    @TaskAction
    public final void transform() {
        SAXParserFactory factory = new org.apache.xerces.jaxp.SAXParserFactoryImpl();
        factory.setXIncludeAware(XIncludeAware);
        docsDir.mkdirs();

        File srcFile = new File(sourceDirectory, sourceFileName);
        String outputFilename = srcFile.getName().substring(0, srcFile.getName().length() - 4) + suffix + '.' + extension;

        File outputFile = new File(getDocsDir(), outputFilename);

        Result result = new StreamResult(outputFile.getAbsolutePath());
        CatalogResolver resolver = new CatalogResolver(createCatalogManager());
        InputSource inputSource = new InputSource(srcFile.getAbsolutePath());

        XMLReader reader = factory.newSAXParser().getXMLReader();
        reader.setEntityResolver(resolver);
        TransformerFactory transformerFactory = new TransformerFactoryImpl();
        transformerFactory.setURIResolver(resolver);
        URL url = stylesheet.toURL();
        Source source = new StreamSource(url.openStream(), url.toExternalForm());
        Transformer transformer = transformerFactory.newTransformer(source);

        if (highlightingEnabled) {
            File highlightingDir = new File(getProject().getBuildDir(), "highlighting");
            if (!highlightingDir.exists()) {
                highlightingDir.mkdirs();
                extractHighlightFiles(highlightingDir);
            }

            transformer.setParameter("highlight.xslthl.config", new File(highlightingDir, "xslthl-config.xml").toURI().toURL());

            if (admonGraphicsPath != null) {
                transformer.setParameter("admon.graphics", "1");
                transformer.setParameter("admon.graphics.path", admonGraphicsPath);
            }
        }

        preTransform(transformer, srcFile, outputFile);

        transformer.transform(new SAXSource(reader, inputSource), result);

        postTransform(outputFile);
    }

    private void extractHighlightFiles(File toDir) {
        URLClassLoader cl = (URLClassLoader) getClass().getClassLoader();
        URL[] urls = cl.getURLs();
        URL docbookZip = null;

        for (URL url : urls) {
            if (url.toString().contains("docbook-xsl-")) {
                docbookZip = url;
                break;
            }
        }

        if (docbookZip == null) {
            throw new GradleException("Docbook zip file not found");
        }

        ZipFile zipFile = new ZipFile(new File(docbookZip.toURI()));

        Enumeration e = zipFile.entries();
        while (e.hasMoreElements()) {
            ZipEntry ze = (ZipEntry) e.nextElement();
            if (ze.getName().matches(".*/highlighting/.*\\.xml")) {
                String filename = ze.getName().substring(ze.getName().lastIndexOf("/highlighting/") + 14);
                copyFile(zipFile.getInputStream(ze), new File(toDir, filename));
            }
        }
    }

    private void copyFile(InputStream source, File destFile) {
        destFile.createNewFile();
        FileOutputStream to = null;
        try {
            to = new FileOutputStream(destFile);
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = source.read(buffer)) > 0) {
                to.write(buffer, 0, bytesRead);
            }
        } finally {
            if (source != null) {
                source.close();
            }
            if (to != null) {
                to.close();
            }
        }
    }

    protected void preTransform(Transformer transformer, File sourceFile, File outputFile) {
    }

    protected void postTransform(File outputFile) {
    }

    private CatalogManager createCatalogManager() {
        CatalogManager manager = new CatalogManager();
        manager.setIgnoreMissingProperties(true);
        ClassLoader classLoader = this.getClass().getClassLoader();
        StringBuilder builder = new StringBuilder();
        String docbookCatalogName = "docbook/catalog.xml";
        URL docbookCatalog = classLoader.getResource(docbookCatalogName);

        if (docbookCatalog == null) {
            throw new IllegalStateException("Docbook catalog " + docbookCatalogName + " could not be found in " + classLoader);
        }

        builder.append(docbookCatalog.toExternalForm());

        Enumeration enumeration = classLoader.getResources("/catalog.xml");
        while (enumeration.hasMoreElements()) {
            builder.append(';');
            URL resource = (URL) enumeration.nextElement();
            builder.append(resource.toExternalForm());
        }
        String catalogFiles = builder.toString();
        manager.setCatalogFiles(catalogFiles);
        return manager;
    }
}

/**
 */
class DocbookHtml extends Docbook {

    @Override
    protected void preTransform(Transformer transformer, File sourceFile, File outputFile) {
        String rootFilename = outputFile.getName();
        rootFilename = rootFilename.substring(0, rootFilename.lastIndexOf('.'));
        transformer.setParameter("root.filename", rootFilename);
        transformer.setParameter("base.dir", outputFile.getParent() + File.separator);
    }
}

/**
 */
class DocbookFoPdf extends Docbook {

    /**
     * <a href="http://xmlgraphics.apache.org/fop/0.95/embedding.html#render">From the FOP usage guide</a>
     */
    @Override
    protected void postTransform(File foFile) {
        FopFactory fopFactory = FopFactory.newInstance();

        OutputStream out  = null;
        final File pdfFile = getPdfOutputFile(foFile);
        logger.debug("Transforming 'fo' file "+ foFile + " to PDF: " + pdfFile);

        try {
            out = new BufferedOutputStream(new FileOutputStream(pdfFile));

            Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, out);

            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer();

            Source src = new StreamSource(foFile);

            Result res = new SAXResult(fop.getDefaultHandler());

            transformer.transform(src, res);
        } finally {
            if (out != null) {
                out.close();
            }
        }

        if (!foFile.delete()) {
            logger.warn("Failed to delete 'fo' file " + foFile);
        }
    }

    private File getPdfOutputFile(File foFile) {
        String name = foFile.getAbsolutePath();
        return new File(name.substring(0, name.length() - 2) + "pdf");
    }
}
