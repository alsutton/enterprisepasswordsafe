package com.enterprisepasswordsafe.database.abstraction;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.immutables.value.Generated;

/**
 * Immutable implementation of {@link ColumnSpecification}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutableColumnSpecification.builder()}.
 */
@Generated(from = "ColumnSpecification", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutableColumnSpecification
    implements ColumnSpecification {
  private final String name;
  private final ColumnSpecification.Type type;
  private final boolean uniqueOnly;
  private final boolean rejectNulls;

  private ImmutableColumnSpecification(
      String name,
      ColumnSpecification.Type type,
      boolean uniqueOnly,
      boolean rejectNulls) {
    this.name = name;
    this.type = type;
    this.uniqueOnly = uniqueOnly;
    this.rejectNulls = rejectNulls;
  }

  /**
   * @return The value of the {@code name} attribute
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * @return The value of the {@code type} attribute
   */
  @Override
  public ColumnSpecification.Type getType() {
    return type;
  }

  /**
   * @return The value of the {@code uniqueOnly} attribute
   */
  @Override
  public boolean getUniqueOnly() {
    return uniqueOnly;
  }

  /**
   * @return The value of the {@code rejectNulls} attribute
   */
  @Override
  public boolean getRejectNulls() {
    return rejectNulls;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link ColumnSpecification#getName() name} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for name
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableColumnSpecification withName(String value) {
    String newValue = Objects.requireNonNull(value, "name");
    if (this.name.equals(newValue)) return this;
    return new ImmutableColumnSpecification(newValue, this.type, this.uniqueOnly, this.rejectNulls);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link ColumnSpecification#getType() type} attribute.
   * A value equality check is used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for type
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableColumnSpecification withType(ColumnSpecification.Type value) {
    if (this.type == value) return this;
    ColumnSpecification.Type newValue = Objects.requireNonNull(value, "type");
    if (this.type.equals(newValue)) return this;
    return new ImmutableColumnSpecification(this.name, newValue, this.uniqueOnly, this.rejectNulls);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link ColumnSpecification#getUniqueOnly() uniqueOnly} attribute.
   * A value equality check is used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for uniqueOnly
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableColumnSpecification withUniqueOnly(boolean value) {
    if (this.uniqueOnly == value) return this;
    return new ImmutableColumnSpecification(this.name, this.type, value, this.rejectNulls);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link ColumnSpecification#getRejectNulls() rejectNulls} attribute.
   * A value equality check is used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for rejectNulls
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableColumnSpecification withRejectNulls(boolean value) {
    if (this.rejectNulls == value) return this;
    return new ImmutableColumnSpecification(this.name, this.type, this.uniqueOnly, value);
  }

  /**
   * This instance is equal to all instances of {@code ImmutableColumnSpecification} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutableColumnSpecification
        && equalTo((ImmutableColumnSpecification) another);
  }

  private boolean equalTo(ImmutableColumnSpecification another) {
    return name.equals(another.name)
        && type.equals(another.type)
        && uniqueOnly == another.uniqueOnly
        && rejectNulls == another.rejectNulls;
  }

  /**
   * Computes a hash code from attributes: {@code name}, {@code type}, {@code uniqueOnly}, {@code rejectNulls}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + name.hashCode();
    h += (h << 5) + type.hashCode();
    h += (h << 5) + Boolean.hashCode(uniqueOnly);
    h += (h << 5) + Boolean.hashCode(rejectNulls);
    return h;
  }

  /**
   * Prints the immutable value {@code ColumnSpecification} with attribute values.
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "ColumnSpecification{"
        + "name=" + name
        + ", type=" + type
        + ", uniqueOnly=" + uniqueOnly
        + ", rejectNulls=" + rejectNulls
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link ColumnSpecification} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable ColumnSpecification instance
   */
  public static ImmutableColumnSpecification copyOf(ColumnSpecification instance) {
    if (instance instanceof ImmutableColumnSpecification) {
      return (ImmutableColumnSpecification) instance;
    }
    return ImmutableColumnSpecification.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutableColumnSpecification ImmutableColumnSpecification}.
   * <pre>
   * ImmutableColumnSpecification.builder()
   *    .name(String) // required {@link ColumnSpecification#getName() name}
   *    .type(com.enterprisepasswordsafe.database.abstraction.ColumnSpecification.Type) // required {@link ColumnSpecification#getType() type}
   *    .uniqueOnly(boolean) // required {@link ColumnSpecification#getUniqueOnly() uniqueOnly}
   *    .rejectNulls(boolean) // required {@link ColumnSpecification#getRejectNulls() rejectNulls}
   *    .build();
   * </pre>
   * @return A new ImmutableColumnSpecification builder
   */
  public static ImmutableColumnSpecification.Builder builder() {
    return new ImmutableColumnSpecification.Builder();
  }

  /**
   * Builds instances of type {@link ImmutableColumnSpecification ImmutableColumnSpecification}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "ColumnSpecification", generator = "Immutables")
  public static final class Builder {
    private static final long INIT_BIT_NAME = 0x1L;
    private static final long INIT_BIT_TYPE = 0x2L;
    private static final long INIT_BIT_UNIQUE_ONLY = 0x4L;
    private static final long INIT_BIT_REJECT_NULLS = 0x8L;
    private long initBits = 0xfL;

    private String name;
    private ColumnSpecification.Type type;
    private boolean uniqueOnly;
    private boolean rejectNulls;

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code ColumnSpecification} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(ColumnSpecification instance) {
      Objects.requireNonNull(instance, "instance");
      name(instance.getName());
      type(instance.getType());
      uniqueOnly(instance.getUniqueOnly());
      rejectNulls(instance.getRejectNulls());
      return this;
    }

    /**
     * Initializes the value for the {@link ColumnSpecification#getName() name} attribute.
     * @param name The value for name 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder name(String name) {
      this.name = Objects.requireNonNull(name, "name");
      initBits &= ~INIT_BIT_NAME;
      return this;
    }

    /**
     * Initializes the value for the {@link ColumnSpecification#getType() type} attribute.
     * @param type The value for type 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder type(ColumnSpecification.Type type) {
      this.type = Objects.requireNonNull(type, "type");
      initBits &= ~INIT_BIT_TYPE;
      return this;
    }

    /**
     * Initializes the value for the {@link ColumnSpecification#getUniqueOnly() uniqueOnly} attribute.
     * @param uniqueOnly The value for uniqueOnly 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder uniqueOnly(boolean uniqueOnly) {
      this.uniqueOnly = uniqueOnly;
      initBits &= ~INIT_BIT_UNIQUE_ONLY;
      return this;
    }

    /**
     * Initializes the value for the {@link ColumnSpecification#getRejectNulls() rejectNulls} attribute.
     * @param rejectNulls The value for rejectNulls 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder rejectNulls(boolean rejectNulls) {
      this.rejectNulls = rejectNulls;
      initBits &= ~INIT_BIT_REJECT_NULLS;
      return this;
    }

    /**
     * Builds a new {@link ImmutableColumnSpecification ImmutableColumnSpecification}.
     * @return An immutable instance of ColumnSpecification
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutableColumnSpecification build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new ImmutableColumnSpecification(name, type, uniqueOnly, rejectNulls);
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_NAME) != 0) attributes.add("name");
      if ((initBits & INIT_BIT_TYPE) != 0) attributes.add("type");
      if ((initBits & INIT_BIT_UNIQUE_ONLY) != 0) attributes.add("uniqueOnly");
      if ((initBits & INIT_BIT_REJECT_NULLS) != 0) attributes.add("rejectNulls");
      return "Cannot build ColumnSpecification, some of required attributes are not set " + attributes;
    }
  }
}
