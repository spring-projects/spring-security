<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:variable name="src-xref-base">http://static.springframework.org/spring-security/site/xref/</xsl:variable>
  <xsl:variable name="ref-man-base">http://static.springframework.org/spring-security/site/reference/html/</xsl:variable>  

  <xsl:template match="index">
    <html>
      <body>
        <h1>Class and Interface Index</h1>
        <xsl:apply-templates />
      </body>
    </html>  
  </xsl:template>

  <xsl:template match="class">
    <h3><xsl:value-of select="@name"/></h3>
    <xsl:if test="@src-xref">
      <p><xsl:element name="a"><xsl:attribute name="href"><xsl:value-of select="concat($src-xref-base, @src-xref)"/></xsl:attribute>Source</xsl:element></p>
    </xsl:if>
    <xsl:for-each select="link">
      <p><xsl:element name="a"><xsl:attribute name="href"><xsl:value-of select="concat($ref-man-base, @href)"/></xsl:attribute><xsl:value-of select="@title"/></xsl:element></p>
    </xsl:for-each>
  </xsl:template>
  


</xsl:stylesheet>
