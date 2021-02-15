package com.enterprisepasswordsafe.database.derived;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.immutables.value.Generated;

/**
 * Immutable implementation of {@link PasswordSummary}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutablePasswordSummary.builder()}.
 */
@Generated(from = "PasswordSummary", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutablePasswordSummary
    implements PasswordSummary {
  private final String id;
  private final String representation;

  private ImmutablePasswordSummary(String id, String representation) {
    this.id = id;
    this.representation = representation;
  }

  /**
   * @return The value of the {@code id} attribute
   */
  @Override
  public String getId() {
    return id;
  }

  /**
   * @return The value of the {@code representation} attribute
   */
  @Override
  public String getRepresentation() {
    return representation;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link PasswordSummary#getId() id} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for id
   * @return A modified copy of the {@code this} object
   */
  public final ImmutablePasswordSummary withId(String value) {
    String newValue = Objects.requireNonNull(value, "id");
    if (this.id.equals(newValue)) return this;
    return new ImmutablePasswordSummary(newValue, this.representation);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link PasswordSummary#getRepresentation() representation} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for representation
   * @return A modified copy of the {@code this} object
   */
  public final ImmutablePasswordSummary withRepresentation(String value) {
    String newValue = Objects.requireNonNull(value, "representation");
    if (this.representation.equals(newValue)) return this;
    return new ImmutablePasswordSummary(this.id, newValue);
  }

  /**
   * This instance is equal to all instances of {@code ImmutablePasswordSummary} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutablePasswordSummary
        && equalTo((ImmutablePasswordSummary) another);
  }

  private boolean equalTo(ImmutablePasswordSummary another) {
    return id.equals(another.id)
        && representation.equals(another.representation);
  }

  /**
   * Computes a hash code from attributes: {@code id}, {@code representation}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + id.hashCode();
    h += (h << 5) + representation.hashCode();
    return h;
  }

  /**
   * Prints the immutable value {@code PasswordSummary} with attribute values.
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "PasswordSummary{"
        + "id=" + id
        + ", representation=" + representation
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link PasswordSummary} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable PasswordSummary instance
   */
  public static ImmutablePasswordSummary copyOf(PasswordSummary instance) {
    if (instance instanceof ImmutablePasswordSummary) {
      return (ImmutablePasswordSummary) instance;
    }
    return ImmutablePasswordSummary.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutablePasswordSummary ImmutablePasswordSummary}.
   * <pre>
   * ImmutablePasswordSummary.builder()
   *    .id(String) // required {@link PasswordSummary#getId() id}
   *    .representation(String) // required {@link PasswordSummary#getRepresentation() representation}
   *    .build();
   * </pre>
   * @return A new ImmutablePasswordSummary builder
   */
  public static ImmutablePasswordSummary.Builder builder() {
    return new ImmutablePasswordSummary.Builder();
  }

  /**
   * Builds instances of type {@link ImmutablePasswordSummary ImmutablePasswordSummary}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "PasswordSummary", generator = "Immutables")
  public static final class Builder {
    private static final long INIT_BIT_ID = 0x1L;
    private static final long INIT_BIT_REPRESENTATION = 0x2L;
    private long initBits = 0x3L;

    private String id;
    private String representation;

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code PasswordSummary} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(PasswordSummary instance) {
      Objects.requireNonNull(instance, "instance");
      id(instance.getId());
      representation(instance.getRepresentation());
      return this;
    }

    /**
     * Initializes the value for the {@link PasswordSummary#getId() id} attribute.
     * @param id The value for id 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder id(String id) {
      this.id = Objects.requireNonNull(id, "id");
      initBits &= ~INIT_BIT_ID;
      return this;
    }

    /**
     * Initializes the value for the {@link PasswordSummary#getRepresentation() representation} attribute.
     * @param representation The value for representation 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder representation(String representation) {
      this.representation = Objects.requireNonNull(representation, "representation");
      initBits &= ~INIT_BIT_REPRESENTATION;
      return this;
    }

    /**
     * Builds a new {@link ImmutablePasswordSummary ImmutablePasswordSummary}.
     * @return An immutable instance of PasswordSummary
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutablePasswordSummary build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new ImmutablePasswordSummary(id, representation);
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_ID) != 0) attributes.add("id");
      if ((initBits & INIT_BIT_REPRESENTATION) != 0) attributes.add("representation");
      return "Cannot build PasswordSummary, some of required attributes are not set " + attributes;
    }
  }
}
