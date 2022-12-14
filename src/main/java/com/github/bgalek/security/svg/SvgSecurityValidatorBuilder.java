package com.github.bgalek.security.svg;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static com.github.bgalek.security.svg.SvgAttributes.DEFAULT_SVG_ATTRIBUTES;
import static com.github.bgalek.security.svg.SvgElements.DEFAULT_SVG_ELEMENTS;

public class SvgSecurityValidatorBuilder {
    private String[] elements = DEFAULT_SVG_ELEMENTS;
    private String[] attributes = DEFAULT_SVG_ATTRIBUTES;
    private DocumentBuilder xmlParser;

    SvgSecurityValidatorBuilder() {
    }

    public SvgSecurityValidatorBuilder withAdditionalElements(List<String> additionalElements) {
        this.elements = Stream.concat(Arrays.stream(DEFAULT_SVG_ELEMENTS), additionalElements.stream()).distinct().toArray(String[]::new);
        return this;
    }

    public SvgSecurityValidatorBuilder withAdditionalAttributes(List<String> additionalAttributes) {
        this.attributes = Stream.concat(Arrays.stream(DEFAULT_SVG_ATTRIBUTES), additionalAttributes.stream()).distinct().toArray(String[]::new);
        return this;
    }

    public SvgSecurityValidatorBuilder withSyntaxValidation() {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            documentBuilderFactory.setNamespaceAware(true);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/namespaces", false);
            documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            this.xmlParser = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
        return this;
    }

    public SvgSecurityValidator build() {
        return new SvgSecurityValidator(elements, attributes, xmlParser);
    }
}