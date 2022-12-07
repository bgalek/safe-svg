package com.github.bgalek.security.svg;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.owasp.html.CssSchema;
import org.owasp.html.HtmlChangeListener;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * SVG Safe is a very simple and lightweight library that helps
 * to validate SVG files in security manners.
 * It will help you in detecting malicious content inside uploaded SVGs.
 *
 * @author Bartosz Gałek
 * @see <a href="https://github.com/bgalek/safe-svg">safe-svg</a>
 */
public class SvgSecurityValidator implements XssDetector {

    private static final Pattern JAVASCRIPT_PROTOCOL_IN_CSS_URL = Pattern.compile("url\\(.?javascript");

    private final String[] svgElements;
    private final String[] svgAttributes;

    /**
     * Use builder SvgSecurityValidator.builder()
     */
    @Deprecated
    public SvgSecurityValidator() {
        this.svgElements = SvgElements.DEFAULT_SVG_ELEMENTS;
        this.svgAttributes = SvgAttributes.DEFAULT_SVG_ATTRIBUTES;
    }

    SvgSecurityValidator(String[] elements, String[] attributes) {
        this.svgElements = elements;
        this.svgAttributes = attributes;
    }

    public static SvgSecurityValidatorBuilder builder() {
        return new SvgSecurityValidatorBuilder();
    }

    /**
     * This is the main method that handles svg file validation
     *
     * @param input svg file content to validate
     * @return {@link ValidationResult}
     * @since 1.0
     */
    @Override
    public ValidationResult validate(String input) {
        Set<String> offendingElements = getOffendingElements(input);
        if (offendingElements.isEmpty()) return new NegativeValidationResult();
        return new PositiveValidationResult(offendingElements);
    }

    @Override
    public ValidationResult validate(byte[] input) {
        return validate(new String(input, StandardCharsets.UTF_8));
    }

    private Set<String> getOffendingElements(String xml) {
        if (JAVASCRIPT_PROTOCOL_IN_CSS_URL.matcher(xml).find()) return Collections.singleton("style");
        PolicyFactory policy = new HtmlPolicyBuilder()
                .allowElements(this.svgElements)
                .allowStyling(CssSchema.union(CssSchema.DEFAULT, CssSchema.withProperties(SVG_SPECIFIC_STYLES)))
                .allowAttributes(this.svgAttributes).globally()
                .allowUrlProtocols("https")
                .toFactory();
        Set<String> violations = new HashSet<>();
        policy.sanitize(xml, violationsCollector(), violations);
        return violations;
    }

    private static final ImmutableMap<String, CssSchema.Property> SVG_SPECIFIC_STYLES = ImmutableMap.of(
            "enable-background", new CssSchema.Property(1, ImmutableSet.of(), ImmutableMap.of())
    );

    private static HtmlChangeListener<Set<String>> violationsCollector() {
        return new ListHtmlChangeListener();
    }

    private static class ListHtmlChangeListener implements HtmlChangeListener<Set<String>> {
        @Override
        public void discardedTag(Set<String> context, String elementName) {
            Objects.requireNonNull(context).add(elementName);
        }

        @Override
        public void discardedAttributes(Set<String> context, String tagName, String... attributeNames) {
            Objects.requireNonNull(context).addAll(Arrays.asList(attributeNames));
        }
    }
}
