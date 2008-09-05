<?xml version="1.0" encoding="utf-8"?>

<xsl:stylesheet 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0" xmlns:db="http://docbook.org/ns/docbook">
  <xsl:output method="text"/>

  <xsl:template match="db:interfacename|db:classname">
    <xsl:variable name="classname" select="."/> 
    <xsl:for-each select="ancestor::*[@xml:id][1]">
      <xsl:variable name="title" select="db:info/db:title|db:title"/>
      <xsl:value-of select="concat($classname, ':', @xml:id, ':', $title,';')"/>
    </xsl:for-each>
  </xsl:template> 

  <xsl:template match="text()|@*|*">
    <xsl:apply-templates/>
  </xsl:template>

</xsl:stylesheet>