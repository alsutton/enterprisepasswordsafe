package com.enterprisepasswordsafe.database.derived;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.immutables.value.Generated;

/**
 * Immutable implementation of {@link HierarchyNodeSummary}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutableHierarchyNodeSummary.builder()}.
 */
@Generated(from = "HierarchyNodeSummary", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutableHierarchyNodeSummary
    implements HierarchyNodeSummary {
  private final String id;
  private final String parentage;

  private ImmutableHierarchyNodeSummary(String id, String parentage) {
    this.id = id;
    this.parentage = parentage;
  }

  /**
   * @return The value of the {@code id} attribute
   */
  @Override
  public String id() {
    return id;
  }

  /**
   * @return The value of the {@code parentage} attribute
   */
  @Override
  public String parentage() {
    return parentage;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link HierarchyNodeSummary#id() id} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for id
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableHierarchyNodeSummary withId(String value) {
    String newValue = Objects.requireNonNull(value, "id");
    if (this.id.equals(newValue)) return this;
    return new ImmutableHierarchyNodeSummary(newValue, this.parentage);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link HierarchyNodeSummary#parentage() parentage} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for parentage
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableHierarchyNodeSummary withParentage(String value) {
    String newValue = Objects.requireNonNull(value, "parentage");
    if (this.parentage.equals(newValue)) return this;
    return new ImmutableHierarchyNodeSummary(this.id, newValue);
  }

  /**
   * This instance is equal to all instances of {@code ImmutableHierarchyNodeSummary} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutableHierarchyNodeSummary
        && equalTo((ImmutableHierarchyNodeSummary) another);
  }

  private boolean equalTo(ImmutableHierarchyNodeSummary another) {
    return id.equals(another.id)
        && parentage.equals(another.parentage);
  }

  /**
   * Computes a hash code from attributes: {@code id}, {@code parentage}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + id.hashCode();
    h += (h << 5) + parentage.hashCode();
    return h;
  }

  /**
   * Prints the immutable value {@code HierarchyNodeSummary} with attribute values.
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "HierarchyNodeSummary{"
        + "id=" + id
        + ", parentage=" + parentage
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link HierarchyNodeSummary} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable HierarchyNodeSummary instance
   */
  public static ImmutableHierarchyNodeSummary copyOf(HierarchyNodeSummary instance) {
    if (instance instanceof ImmutableHierarchyNodeSummary) {
      return (ImmutableHierarchyNodeSummary) instance;
    }
    return ImmutableHierarchyNodeSummary.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutableHierarchyNodeSummary ImmutableHierarchyNodeSummary}.
   * <pre>
   * ImmutableHierarchyNodeSummary.builder()
   *    .id(String) // required {@link HierarchyNodeSummary#id() id}
   *    .parentage(String) // required {@link HierarchyNodeSummary#parentage() parentage}
   *    .build();
   * </pre>
   * @return A new ImmutableHierarchyNodeSummary builder
   */
  public static ImmutableHierarchyNodeSummary.Builder builder() {
    return new ImmutableHierarchyNodeSummary.Builder();
  }

  /**
   * Builds instances of type {@link ImmutableHierarchyNodeSummary ImmutableHierarchyNodeSummary}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "HierarchyNodeSummary", generator = "Immutables")
  public static final class Builder {
    private static final long INIT_BIT_ID = 0x1L;
    private static final long INIT_BIT_PARENTAGE = 0x2L;
    private long initBits = 0x3L;

    private String id;
    private String parentage;

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code HierarchyNodeSummary} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(HierarchyNodeSummary instance) {
      Objects.requireNonNull(instance, "instance");
      id(instance.id());
      parentage(instance.parentage());
      return this;
    }

    /**
     * Initializes the value for the {@link HierarchyNodeSummary#id() id} attribute.
     * @param id The value for id 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder id(String id) {
      this.id = Objects.requireNonNull(id, "id");
      initBits &= ~INIT_BIT_ID;
      return this;
    }

    /**
     * Initializes the value for the {@link HierarchyNodeSummary#parentage() parentage} attribute.
     * @param parentage The value for parentage 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder parentage(String parentage) {
      this.parentage = Objects.requireNonNull(parentage, "parentage");
      initBits &= ~INIT_BIT_PARENTAGE;
      return this;
    }

    /**
     * Builds a new {@link ImmutableHierarchyNodeSummary ImmutableHierarchyNodeSummary}.
     * @return An immutable instance of HierarchyNodeSummary
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutableHierarchyNodeSummary build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new ImmutableHierarchyNodeSummary(id, parentage);
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_ID) != 0) attributes.add("id");
      if ((initBits & INIT_BIT_PARENTAGE) != 0) attributes.add("parentage");
      return "Cannot build HierarchyNodeSummary, some of required attributes are not set " + attributes;
    }
  }
}
