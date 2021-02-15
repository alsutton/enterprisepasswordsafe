package com.enterprisepasswordsafe.database.derived;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.immutables.value.Generated;

/**
 * Immutable implementation of {@link IntegrationModuleScriptSummary}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutableIntegrationModuleScriptSummary.builder()}.
 */
@Generated(from = "IntegrationModuleScriptSummary", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutableIntegrationModuleScriptSummary
    implements IntegrationModuleScriptSummary {
  private final String moduleId;
  private final String scriptId;
  private final String moduleName;
  private final boolean isActive;
  private final String name;

  private ImmutableIntegrationModuleScriptSummary(
      String moduleId,
      String scriptId,
      String moduleName,
      boolean isActive,
      String name) {
    this.moduleId = moduleId;
    this.scriptId = scriptId;
    this.moduleName = moduleName;
    this.isActive = isActive;
    this.name = name;
  }

  /**
   * @return The value of the {@code moduleId} attribute
   */
  @Override
  public String getModuleId() {
    return moduleId;
  }

  /**
   * @return The value of the {@code scriptId} attribute
   */
  @Override
  public String getScriptId() {
    return scriptId;
  }

  /**
   * @return The value of the {@code moduleName} attribute
   */
  @Override
  public String getModuleName() {
    return moduleName;
  }

  /**
   * @return The value of the {@code isActive} attribute
   */
  @Override
  public boolean isActive() {
    return isActive;
  }

  /**
   * @return The value of the {@code name} attribute
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link IntegrationModuleScriptSummary#getModuleId() moduleId} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for moduleId
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableIntegrationModuleScriptSummary withModuleId(String value) {
    String newValue = Objects.requireNonNull(value, "moduleId");
    if (this.moduleId.equals(newValue)) return this;
    return new ImmutableIntegrationModuleScriptSummary(newValue, this.scriptId, this.moduleName, this.isActive, this.name);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link IntegrationModuleScriptSummary#getScriptId() scriptId} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for scriptId
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableIntegrationModuleScriptSummary withScriptId(String value) {
    String newValue = Objects.requireNonNull(value, "scriptId");
    if (this.scriptId.equals(newValue)) return this;
    return new ImmutableIntegrationModuleScriptSummary(this.moduleId, newValue, this.moduleName, this.isActive, this.name);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link IntegrationModuleScriptSummary#getModuleName() moduleName} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for moduleName
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableIntegrationModuleScriptSummary withModuleName(String value) {
    String newValue = Objects.requireNonNull(value, "moduleName");
    if (this.moduleName.equals(newValue)) return this;
    return new ImmutableIntegrationModuleScriptSummary(this.moduleId, this.scriptId, newValue, this.isActive, this.name);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link IntegrationModuleScriptSummary#isActive() isActive} attribute.
   * A value equality check is used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for isActive
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableIntegrationModuleScriptSummary withIsActive(boolean value) {
    if (this.isActive == value) return this;
    return new ImmutableIntegrationModuleScriptSummary(this.moduleId, this.scriptId, this.moduleName, value, this.name);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link IntegrationModuleScriptSummary#getName() name} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for name
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableIntegrationModuleScriptSummary withName(String value) {
    String newValue = Objects.requireNonNull(value, "name");
    if (this.name.equals(newValue)) return this;
    return new ImmutableIntegrationModuleScriptSummary(this.moduleId, this.scriptId, this.moduleName, this.isActive, newValue);
  }

  /**
   * This instance is equal to all instances of {@code ImmutableIntegrationModuleScriptSummary} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutableIntegrationModuleScriptSummary
        && equalTo((ImmutableIntegrationModuleScriptSummary) another);
  }

  private boolean equalTo(ImmutableIntegrationModuleScriptSummary another) {
    return moduleId.equals(another.moduleId)
        && scriptId.equals(another.scriptId);
  }

  /**
   * Computes a hash code from attributes: {@code moduleId}, {@code scriptId}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + moduleId.hashCode();
    h += (h << 5) + scriptId.hashCode();
    return h;
  }

  /**
   * Prints the immutable value {@code IntegrationModuleScriptSummary} with attribute values.
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "IntegrationModuleScriptSummary{"
        + "moduleId=" + moduleId
        + ", scriptId=" + scriptId
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link IntegrationModuleScriptSummary} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable IntegrationModuleScriptSummary instance
   */
  public static ImmutableIntegrationModuleScriptSummary copyOf(IntegrationModuleScriptSummary instance) {
    if (instance instanceof ImmutableIntegrationModuleScriptSummary) {
      return (ImmutableIntegrationModuleScriptSummary) instance;
    }
    return ImmutableIntegrationModuleScriptSummary.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutableIntegrationModuleScriptSummary ImmutableIntegrationModuleScriptSummary}.
   * <pre>
   * ImmutableIntegrationModuleScriptSummary.builder()
   *    .moduleId(String) // required {@link IntegrationModuleScriptSummary#getModuleId() moduleId}
   *    .scriptId(String) // required {@link IntegrationModuleScriptSummary#getScriptId() scriptId}
   *    .moduleName(String) // required {@link IntegrationModuleScriptSummary#getModuleName() moduleName}
   *    .isActive(boolean) // required {@link IntegrationModuleScriptSummary#isActive() isActive}
   *    .name(String) // required {@link IntegrationModuleScriptSummary#getName() name}
   *    .build();
   * </pre>
   * @return A new ImmutableIntegrationModuleScriptSummary builder
   */
  public static ImmutableIntegrationModuleScriptSummary.Builder builder() {
    return new ImmutableIntegrationModuleScriptSummary.Builder();
  }

  /**
   * Builds instances of type {@link ImmutableIntegrationModuleScriptSummary ImmutableIntegrationModuleScriptSummary}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "IntegrationModuleScriptSummary", generator = "Immutables")
  public static final class Builder {
    private static final long INIT_BIT_MODULE_ID = 0x1L;
    private static final long INIT_BIT_SCRIPT_ID = 0x2L;
    private static final long INIT_BIT_MODULE_NAME = 0x4L;
    private static final long INIT_BIT_IS_ACTIVE = 0x8L;
    private static final long INIT_BIT_NAME = 0x10L;
    private long initBits = 0x1fL;

    private String moduleId;
    private String scriptId;
    private String moduleName;
    private boolean isActive;
    private String name;

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code IntegrationModuleScriptSummary} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(IntegrationModuleScriptSummary instance) {
      Objects.requireNonNull(instance, "instance");
      moduleId(instance.getModuleId());
      scriptId(instance.getScriptId());
      moduleName(instance.getModuleName());
      isActive(instance.isActive());
      name(instance.getName());
      return this;
    }

    /**
     * Initializes the value for the {@link IntegrationModuleScriptSummary#getModuleId() moduleId} attribute.
     * @param moduleId The value for moduleId 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder moduleId(String moduleId) {
      this.moduleId = Objects.requireNonNull(moduleId, "moduleId");
      initBits &= ~INIT_BIT_MODULE_ID;
      return this;
    }

    /**
     * Initializes the value for the {@link IntegrationModuleScriptSummary#getScriptId() scriptId} attribute.
     * @param scriptId The value for scriptId 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder scriptId(String scriptId) {
      this.scriptId = Objects.requireNonNull(scriptId, "scriptId");
      initBits &= ~INIT_BIT_SCRIPT_ID;
      return this;
    }

    /**
     * Initializes the value for the {@link IntegrationModuleScriptSummary#getModuleName() moduleName} attribute.
     * @param moduleName The value for moduleName 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder moduleName(String moduleName) {
      this.moduleName = Objects.requireNonNull(moduleName, "moduleName");
      initBits &= ~INIT_BIT_MODULE_NAME;
      return this;
    }

    /**
     * Initializes the value for the {@link IntegrationModuleScriptSummary#isActive() isActive} attribute.
     * @param isActive The value for isActive 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder isActive(boolean isActive) {
      this.isActive = isActive;
      initBits &= ~INIT_BIT_IS_ACTIVE;
      return this;
    }

    /**
     * Initializes the value for the {@link IntegrationModuleScriptSummary#getName() name} attribute.
     * @param name The value for name 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder name(String name) {
      this.name = Objects.requireNonNull(name, "name");
      initBits &= ~INIT_BIT_NAME;
      return this;
    }

    /**
     * Builds a new {@link ImmutableIntegrationModuleScriptSummary ImmutableIntegrationModuleScriptSummary}.
     * @return An immutable instance of IntegrationModuleScriptSummary
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutableIntegrationModuleScriptSummary build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new ImmutableIntegrationModuleScriptSummary(moduleId, scriptId, moduleName, isActive, name);
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_MODULE_ID) != 0) attributes.add("moduleId");
      if ((initBits & INIT_BIT_SCRIPT_ID) != 0) attributes.add("scriptId");
      if ((initBits & INIT_BIT_MODULE_NAME) != 0) attributes.add("moduleName");
      if ((initBits & INIT_BIT_IS_ACTIVE) != 0) attributes.add("isActive");
      if ((initBits & INIT_BIT_NAME) != 0) attributes.add("name");
      return "Cannot build IntegrationModuleScriptSummary, some of required attributes are not set " + attributes;
    }
  }
}
