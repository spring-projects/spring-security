/*
 * Copyright 2012-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.asciidoctor.gradle

import org.asciidoctor.gradle.*


import org.apache.commons.io.IOUtils
import org.asciidoctor.Asciidoctor
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.InvalidUserDataException
import org.gradle.api.tasks.*

import javax.xml.transform.*
import javax.xml.transform.stream.*
import javax.xml.transform.sax.*
import org.apache.fop.apps.FopFactory
import org.apache.fop.apps.Fop
import org.apache.fop.apps.MimeConstants


class AsciidoctorTask extends DefaultTask {
    @InputFile File sourceDocument
    @Input Map options = [:]

    @Optional @OutputDirectory File outputDir
    @Optional @Input List<String> backends

    AsciidoctorTask() {
        sourceDocument = project.file("src/asciidoctor/index.adoc")
        outputDir = project.file("${project.buildDir}/asciidoctor")
        backends = [AsciidoctorBackend.HTML5.id]
    }

    @TaskAction
    void render() {

        Asciidoctor asciidoctor = Asciidoctor.Factory.create()

        for(backend in backends) {
            boolean isPdf = backend == AsciidoctorBackend.PDF.id
            String asciidoctorBackend = isPdf ? AsciidoctorBackend.DOCBOOK.id : backend

            File distDir = new File("${outputDir}/dist/$backend")
            File workingDir = new File("${outputDir}/work/$backend")

            [workingDir,distDir]*.mkdirs()

            try {
                asciidoctor.renderFile(sourceDocument, mergedOptions(options, isPdf ? workingDir : distDir, asciidoctorBackend))

                if(isPdf) {
                    generatePdf(workingDir,distDir)
                } else {
                    project.copy {
                        from "${sourceDocument.parent}/images"
                        into "${distDir}/images/"
                    }
                }
            } catch (Exception e) {
                throw new GradleException('Error running Asciidoctor on single source '+asciidoctorBackend, e)
            }
        }
    }

    private void generatePdf(File workingDir, File distDir) {
        String docbookXmlUrl = 'http://maven-us.nuxeo.org/nexus/content/repositories/public/docbook/docbook-xml/4.5/docbook-xml-4.5.jar'
        String docbookXslUrl = 'http://downloads.sourceforge.net/project/docbook/docbook-xsl-ns/1.78.1/docbook-xsl-ns-1.78.1.zip'

        File docbookXmlFile = downloadFile(docbookXmlUrl)
        File docbookXslFile = downloadFile(docbookXslUrl)

        project.copy {
            from "src/asciidoctor/images"
            into "${workingDir}/images/"
        }

        project.copy {
            from project.zipTree(docbookXmlFile)
            into "$workingDir/docbook"
        }

        project.copy {
            from(project.zipTree(docbookXslFile)) {
                eachFile { details ->
                    details.path = details.path.substring(details.relativePath.segments[0].length())
                }
            }
            into "$workingDir/docbook/"
        }

        unzipDockbookXsl(workingDir)

        def outputUri = workingDir.toURI().toASCIIString()

        Vector params = new Vector()
        params.add("highlight.xslthl.config")
        params.add(outputUri + "docbook-xsl/xslthl-config.xml")
        params.add("admon.graphics.path")
        params.add(outputUri + "docbook/images/")
        params.add("callout.graphics.path")
        params.add(outputUri + "docbook/images/callouts/")
        params.add("img.src.path")
        params.add(outputUri)
        params.add("fop-output-format")
        params.add("application/pdf")
        params.add("fop-version")
        params.add("1.1")

        File outputFile = new File("${distDir}/", sourceDocument.name.replaceAll("\\..*", ".pdf"))
        File docbookFile = new File("$workingDir/",sourceDocument.name.replaceAll("\\..*", ".xml"))
        File xsltFile = new File("${workingDir}/docbook-xsl/fo-pdf.xsl")

        InputHandler handler = new InputHandler(docbookFile, xsltFile, params)

        FopFactory fopFactory = FopFactory.newInstance(); // Reuse the FopFactory if possible!
        fopFactory.setUserConfig(new File("${workingDir}/docbook-xsl/fop-config.xml"))
        // do the following for each new rendering run
        def foUserAgent = fopFactory.newFOUserAgent();

        handler.createCatalogResolver(foUserAgent)

        def out = new java.io.BufferedOutputStream(
            new java.io.FileOutputStream(outputFile));

        foUserAgent.setOutputFile(outputFile);

        try {
            handler.renderTo(foUserAgent, MimeConstants.MIME_PDF, out)
        } finally {
            IOUtils.closeQuietly(out)
        }
    }

    private void unzipDockbookXsl(def installDir) {
        def docbookXslResourceName = 'docbook-xsl.zip'
        def docbookXslInputStream = this.class.classLoader.getResourceAsStream(docbookXslResourceName)
        if (docbookXslInputStream == null) {
            throw new GradleException("could not find ${docbookXslResourceName} on the classpath");
        }
        // the file is a jar:file - write it to disk first
        File docbookXslOutputFile = new File("${installDir}/downloads/${docbookXslResourceName}")
        docbookXslOutputFile.parentFile.mkdirs()
        IOUtils.copy(docbookXslInputStream, new FileOutputStream(docbookXslOutputFile))
        project.copy {
            from project.zipTree(docbookXslOutputFile)
            into "${installDir}/"
        }
    }

    private File downloadFile(String url) {
        def home = System.getProperty("user.home")
        File destinationFile = new File("${home}/.fopdf/downloads", url.split("/")[-1])
        destinationFile.parentFile.mkdirs()

        if(!destinationFile.exists()) {
            logger.info("Downloading " + url + " to "+ destinationFile + "...")
            destinationFile.bytes = new URL(url).bytes
        }
        destinationFile
    }

    private static Map<String, Object> mergedOptions(Map options, File outputDir, String backend) {
        Map<String, Object> mergedOptions = [:]
        mergedOptions.putAll(options)
        mergedOptions.in_place = false
        mergedOptions.safe = 0i
        mergedOptions.to_dir = outputDir.absolutePath
        Map attributes = mergedOptions.get('attributes', [:])
        attributes.backend = backend

        // Issue #14 force GString -> String as jruby will fail
        // to find an exact match when invoking Asciidoctor
        for (entry in mergedOptions) {
            if (entry.value instanceof CharSequence) {
                mergedOptions[entry.key] = entry.value.toString()
            }
        }
        for (entry in attributes) {
            if (entry.value instanceof CharSequence) {
                attributes[entry.key] = entry.value.toString()
            }
        }
        mergedOptions
    }
}