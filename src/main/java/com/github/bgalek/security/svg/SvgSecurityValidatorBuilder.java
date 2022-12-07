package com.github.bgalek.security.svg;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static com.github.bgalek.security.svg.SvgAttributes.DEFAULT_SVG_ATTRIBUTES;
import static com.github.bgalek.security.svg.SvgElements.DEFAULT_SVG_ELEMENTS;

public class SvgSecurityValidatorBuilder {
    private String[] elements = DEFAULT_SVG_ELEMENTS;
    private String[] attributes = DEFAULT_SVG_ATTRIBUTES;

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

    public SvgSecurityValidator build() {
        return new SvgSecurityValidator(elements, attributes);
    }
}