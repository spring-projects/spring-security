<?xml version="1.0" encoding="UTF-8"?>

<!--
    XSL to manipulate trang's output XSD file. Contributed by Brian Ewins.

    $Id$ 
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" version="1.0">
    <xsl:output method="xml" indent="yes"/>

    <xsl:variable name="elts-to-inline">
        <xsl:text>,intercept-url,form-login,x509,password-encoder,http-basic,logout,concurrent-session-control,remember-me,anonymous,port-mappings,password-compare,salt-source,filter-chain,protect-pointcut,</xsl:text>
    </xsl:variable>

    <xsl:template match="xs:element">
        <xsl:choose>
            <xsl:when test="contains($elts-to-inline, concat(',',substring-after(current()/@ref, ':'),','))">
                <xsl:variable name="node" select="."/>
                <xsl:for-each select="/xs:schema/xs:element[@name=substring-after(current()/@ref, ':')]">
                    <xsl:copy>
                        <xsl:apply-templates select="$node/@*[local-name() != 'ref']"/>
                        <xsl:apply-templates select="@*|*"/>                
                    </xsl:copy>
                </xsl:for-each>                
            </xsl:when>
            <!-- Ignore global elements which have been inlined -->
            <xsl:when test="contains($elts-to-inline, concat(',',@name,','))">
            </xsl:when>
            
            <xsl:otherwise>
                <xsl:copy>
                    <xsl:apply-templates select="@*|*"/>
                </xsl:copy>
            </xsl:otherwise>            
        </xsl:choose>
    </xsl:template>

    <!-- Copy any non-element content -->
    <xsl:template match="text()|@*|*">
        <xsl:copy>
            <xsl:apply-templates select="text()|@*|*"/>
        </xsl:copy>
    </xsl:template>
 
</xsl:stylesheet>