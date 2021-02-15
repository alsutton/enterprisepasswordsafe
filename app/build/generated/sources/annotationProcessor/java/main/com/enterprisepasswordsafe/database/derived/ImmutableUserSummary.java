package com.enterprisepasswordsafe.database.derived;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.immutables.value.Generated;

/**
 * Immutable implementation of {@link AbstractUserSummary}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutableUserSummary.builder()}.
 */
@Generated(from = "AbstractUserSummary", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutableUserSummary
    extends AbstractUserSummary {
  private final String id;
  private final String name;
  private final String fullName;

  private ImmutableUserSummary(String id, String name, String fullName) {
    this.id = id;
    this.name = name;
    this.fullName = fullName;
  }

  /**
   * @return The value of the {@code id} attribute
   */
  @Override
  public String getId() {
    return id;
  }

  /**
   * @return The value of the {@code name} attribute
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * @return The value of the {@code fullName} attribute
   */
  @Override
  public String getFullName() {
    return fullName;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link AbstractUserSummary#getId() id} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for id
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableUserSummary withId(String value) {
    String newValue = Objects.requireNonNull(value, "id");
    if (this.id.equals(newValue)) return this;
    return new ImmutableUserSummary(newValue, this.name, this.fullName);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link AbstractUserSummary#getName() name} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for name
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableUserSummary withName(String value) {
    String newValue = Objects.requireNonNull(value, "name");
    if (this.name.equals(newValue)) return this;
    return new ImmutableUserSummary(this.id, newValue, this.fullName);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link AbstractUserSummary#getFullName() fullName} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for fullName
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableUserSummary withFullName(String value) {
    String newValue = Objects.requireNonNull(value, "fullName");
    if (this.fullName.equals(newValue)) return this;
    return new ImmutableUserSummary(this.id, this.name, newValue);
  }

  /**
   * This instance is equal to all instances of {@code ImmutableUserSummary} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutableUserSummary
        && equalTo((ImmutableUserSummary) another);
  }

  private boolean equalTo(ImmutableUserSummary another) {
    return id.equals(another.id)
        && name.equals(another.name)
        && fullName.equals(another.fullName);
  }

  /**
   * Computes a hash code from attributes: {@code id}, {@code name}, {@code fullName}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + id.hashCode();
    h += (h << 5) + name.hashCode();
    h += (h << 5) + fullName.hashCode();
    return h;
  }

  /**
   * Creates an immutable copy of a {@link AbstractUserSummary} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable UserSummary instance
   */
  public static ImmutableUserSummary copyOf(AbstractUserSummary instance) {
    if (instance instanceof ImmutableUserSummary) {
      return (ImmutableUserSummary) instance;
    }
    return ImmutableUserSummary.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutableUserSummary ImmutableUserSummary}.
   * <pre>
   * ImmutableUserSummary.builder()
   *    .id(String) // required {@link AbstractUserSummary#getId() id}
   *    .name(String) // required {@link AbstractUserSummary#getName() name}
   *    .fullName(String) // required {@link AbstractUserSummary#getFullName() fullName}
   *    .build();
   * </pre>
   * @return A new ImmutableUserSummary builder
   */
  public static ImmutableUserSummary.Builder builder() {
    return new ImmutableUserSummary.Builder();
  }

  /**
   * Builds instances of type {@link ImmutableUserSummary ImmutableUserSummary}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "AbstractUserSummary", generator = "Immutables")
  public static final class Builder {
    private static final long INIT_BIT_ID = 0x1L;
    private static final long INIT_BIT_NAME = 0x2L;
    private static final long INIT_BIT_FULL_NAME = 0x4L;
    private long initBits = 0x7L;

    private String id;
    private String name;
    private String fullName;

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code AbstractUserSummary} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(AbstractUserSummary instance) {
      Objects.requireNonNull(instance, "instance");
      id(instance.getId());
      name(instance.getName());
      fullName(instance.getFullName());
      return this;
    }

    /**
     * Initializes the value for the {@link AbstractUserSummary#getId() id} attribute.
     * @param id The value for id 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder id(String id) {
      this.id = Objects.requireNonNull(id, "id");
      initBits &= ~INIT_BIT_ID;
      return this;
    }

    /**
     * Initializes the value for the {@link AbstractUserSummary#getName() name} attribute.
     * @param name The value for name 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder name(String name) {
      this.name = Objects.requireNonNull(name, "name");
      initBits &= ~INIT_BIT_NAME;
      return this;
    }

    /**
     * Initializes the value for the {@link AbstractUserSummary#getFullName() fullName} attribute.
     * @param fullName The value for fullName 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder fullName(String fullName) {
      this.fullName = Objects.requireNonNull(fullName, "fullName");
      initBits &= ~INIT_BIT_FULL_NAME;
      return this;
    }

    /**
     * Builds a new {@link ImmutableUserSummary ImmutableUserSummary}.
     * @return An immutable instance of UserSummary
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutableUserSummary build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new ImmutableUserSummary(id, name, fullName);
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_ID) != 0) attributes.add("id");
      if ((initBits & INIT_BIT_NAME) != 0) attributes.add("name");
      if ((initBits & INIT_BIT_FULL_NAME) != 0) attributes.add("fullName");
      return "Cannot build UserSummary, some of required attributes are not set " + attributes;
    }
  }
}
