package com.enterprisepasswordsafe.database.abstraction;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.immutables.value.Generated;

/**
 * Immutable implementation of {@link TableSpecification}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutableTableSpecification.builder()}.
 */
@Generated(from = "TableSpecification", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutableTableSpecification
    implements TableSpecification {
  private final String name;
  private final List<ColumnSpecification> columnSpecifications;
  private final List<IndexSpecification> indexSpecifications;

  private ImmutableTableSpecification(ImmutableTableSpecification.Builder builder) {
    this.name = builder.name;
    if (builder.columnSpecificationsIsSet()) {
      initShim.columnSpecifications(createUnmodifiableList(true, builder.columnSpecifications));
    }
    if (builder.indexSpecificationsIsSet()) {
      initShim.indexSpecifications(createUnmodifiableList(true, builder.indexSpecifications));
    }
    this.columnSpecifications = initShim.getColumnSpecifications();
    this.indexSpecifications = initShim.getIndexSpecifications();
    this.initShim = null;
  }

  private ImmutableTableSpecification(
      String name,
      List<ColumnSpecification> columnSpecifications,
      List<IndexSpecification> indexSpecifications) {
    this.name = name;
    this.columnSpecifications = columnSpecifications;
    this.indexSpecifications = indexSpecifications;
    this.initShim = null;
  }

  private static final byte STAGE_INITIALIZING = -1;
  private static final byte STAGE_UNINITIALIZED = 0;
  private static final byte STAGE_INITIALIZED = 1;
  private transient volatile InitShim initShim = new InitShim();

  @Generated(from = "TableSpecification", generator = "Immutables")
  private final class InitShim {
    private byte columnSpecificationsBuildStage = STAGE_UNINITIALIZED;
    private List<ColumnSpecification> columnSpecifications;

    List<ColumnSpecification> getColumnSpecifications() {
      if (columnSpecificationsBuildStage == STAGE_INITIALIZING) throw new IllegalStateException(formatInitCycleMessage());
      if (columnSpecificationsBuildStage == STAGE_UNINITIALIZED) {
        columnSpecificationsBuildStage = STAGE_INITIALIZING;
        this.columnSpecifications = createUnmodifiableList(false, createSafeList(getColumnSpecificationsInitialize(), true, false));
        columnSpecificationsBuildStage = STAGE_INITIALIZED;
      }
      return this.columnSpecifications;
    }

    void columnSpecifications(List<ColumnSpecification> columnSpecifications) {
      this.columnSpecifications = columnSpecifications;
      columnSpecificationsBuildStage = STAGE_INITIALIZED;
    }

    private byte indexSpecificationsBuildStage = STAGE_UNINITIALIZED;
    private List<IndexSpecification> indexSpecifications;

    List<IndexSpecification> getIndexSpecifications() {
      if (indexSpecificationsBuildStage == STAGE_INITIALIZING) throw new IllegalStateException(formatInitCycleMessage());
      if (indexSpecificationsBuildStage == STAGE_UNINITIALIZED) {
        indexSpecificationsBuildStage = STAGE_INITIALIZING;
        this.indexSpecifications = createUnmodifiableList(false, createSafeList(getIndexSpecificationsInitialize(), true, false));
        indexSpecificationsBuildStage = STAGE_INITIALIZED;
      }
      return this.indexSpecifications;
    }

    void indexSpecifications(List<IndexSpecification> indexSpecifications) {
      this.indexSpecifications = indexSpecifications;
      indexSpecificationsBuildStage = STAGE_INITIALIZED;
    }

    private String formatInitCycleMessage() {
      List<String> attributes = new ArrayList<>();
      if (columnSpecificationsBuildStage == STAGE_INITIALIZING) attributes.add("columnSpecifications");
      if (indexSpecificationsBuildStage == STAGE_INITIALIZING) attributes.add("indexSpecifications");
      return "Cannot build TableSpecification, attribute initializers form cycle " + attributes;
    }
  }

  private List<ColumnSpecification> getColumnSpecificationsInitialize() {
    return TableSpecification.super.getColumnSpecifications();
  }

  private List<IndexSpecification> getIndexSpecificationsInitialize() {
    return TableSpecification.super.getIndexSpecifications();
  }

  /**
   * @return The value of the {@code name} attribute
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * @return The value of the {@code columnSpecifications} attribute
   */
  @Override
  public List<ColumnSpecification> getColumnSpecifications() {
    InitShim shim = this.initShim;
    return shim != null
        ? shim.getColumnSpecifications()
        : this.columnSpecifications;
  }

  /**
   * @return The value of the {@code indexSpecifications} attribute
   */
  @Override
  public List<IndexSpecification> getIndexSpecifications() {
    InitShim shim = this.initShim;
    return shim != null
        ? shim.getIndexSpecifications()
        : this.indexSpecifications;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link TableSpecification#getName() name} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for name
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableTableSpecification withName(String value) {
    String newValue = Objects.requireNonNull(value, "name");
    if (this.name.equals(newValue)) return this;
    return new ImmutableTableSpecification(newValue, this.columnSpecifications, this.indexSpecifications);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link TableSpecification#getColumnSpecifications() columnSpecifications}.
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableTableSpecification withColumnSpecifications(ColumnSpecification... elements) {
    List<ColumnSpecification> newValue = createUnmodifiableList(false, createSafeList(Arrays.asList(elements), true, false));
    return new ImmutableTableSpecification(this.name, newValue, this.indexSpecifications);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link TableSpecification#getColumnSpecifications() columnSpecifications}.
   * A shallow reference equality check is used to prevent copying of the same value by returning {@code this}.
   * @param elements An iterable of columnSpecifications elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableTableSpecification withColumnSpecifications(Iterable<? extends ColumnSpecification> elements) {
    if (this.columnSpecifications == elements) return this;
    List<ColumnSpecification> newValue = createUnmodifiableList(false, createSafeList(elements, true, false));
    return new ImmutableTableSpecification(this.name, newValue, this.indexSpecifications);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link TableSpecification#getIndexSpecifications() indexSpecifications}.
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableTableSpecification withIndexSpecifications(IndexSpecification... elements) {
    List<IndexSpecification> newValue = createUnmodifiableList(false, createSafeList(Arrays.asList(elements), true, false));
    return new ImmutableTableSpecification(this.name, this.columnSpecifications, newValue);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link TableSpecification#getIndexSpecifications() indexSpecifications}.
   * A shallow reference equality check is used to prevent copying of the same value by returning {@code this}.
   * @param elements An iterable of indexSpecifications elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableTableSpecification withIndexSpecifications(Iterable<? extends IndexSpecification> elements) {
    if (this.indexSpecifications == elements) return this;
    List<IndexSpecification> newValue = createUnmodifiableList(false, createSafeList(elements, true, false));
    return new ImmutableTableSpecification(this.name, this.columnSpecifications, newValue);
  }

  /**
   * This instance is equal to all instances of {@code ImmutableTableSpecification} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutableTableSpecification
        && equalTo((ImmutableTableSpecification) another);
  }

  private boolean equalTo(ImmutableTableSpecification another) {
    return name.equals(another.name)
        && columnSpecifications.equals(another.columnSpecifications)
        && indexSpecifications.equals(another.indexSpecifications);
  }

  /**
   * Computes a hash code from attributes: {@code name}, {@code columnSpecifications}, {@code indexSpecifications}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + name.hashCode();
    h += (h << 5) + columnSpecifications.hashCode();
    h += (h << 5) + indexSpecifications.hashCode();
    return h;
  }

  /**
   * Prints the immutable value {@code TableSpecification} with attribute values.
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "TableSpecification{"
        + "name=" + name
        + ", columnSpecifications=" + columnSpecifications
        + ", indexSpecifications=" + indexSpecifications
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link TableSpecification} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable TableSpecification instance
   */
  public static ImmutableTableSpecification copyOf(TableSpecification instance) {
    if (instance instanceof ImmutableTableSpecification) {
      return (ImmutableTableSpecification) instance;
    }
    return ImmutableTableSpecification.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutableTableSpecification ImmutableTableSpecification}.
   * <pre>
   * ImmutableTableSpecification.builder()
   *    .name(String) // required {@link TableSpecification#getName() name}
   *    .addColumnSpecifications|addAllColumnSpecifications(com.enterprisepasswordsafe.database.abstraction.ColumnSpecification) // {@link TableSpecification#getColumnSpecifications() columnSpecifications} elements
   *    .addIndexSpecifications|addAllIndexSpecifications(com.enterprisepasswordsafe.database.abstraction.IndexSpecification) // {@link TableSpecification#getIndexSpecifications() indexSpecifications} elements
   *    .build();
   * </pre>
   * @return A new ImmutableTableSpecification builder
   */
  public static ImmutableTableSpecification.Builder builder() {
    return new ImmutableTableSpecification.Builder();
  }

  /**
   * Builds instances of type {@link ImmutableTableSpecification ImmutableTableSpecification}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "TableSpecification", generator = "Immutables")
  public static final class Builder {
    private static final long INIT_BIT_NAME = 0x1L;
    private static final long OPT_BIT_COLUMN_SPECIFICATIONS = 0x1L;
    private static final long OPT_BIT_INDEX_SPECIFICATIONS = 0x2L;
    private long initBits = 0x1L;
    private long optBits;

    private String name;
    private List<ColumnSpecification> columnSpecifications = new ArrayList<ColumnSpecification>();
    private List<IndexSpecification> indexSpecifications = new ArrayList<IndexSpecification>();

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code TableSpecification} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * Collection elements and entries will be added, not replaced.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(TableSpecification instance) {
      Objects.requireNonNull(instance, "instance");
      name(instance.getName());
      addAllColumnSpecifications(instance.getColumnSpecifications());
      addAllIndexSpecifications(instance.getIndexSpecifications());
      return this;
    }

    /**
     * Initializes the value for the {@link TableSpecification#getName() name} attribute.
     * @param name The value for name 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder name(String name) {
      this.name = Objects.requireNonNull(name, "name");
      initBits &= ~INIT_BIT_NAME;
      return this;
    }

    /**
     * Adds one element to {@link TableSpecification#getColumnSpecifications() columnSpecifications} list.
     * @param element A columnSpecifications element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addColumnSpecifications(ColumnSpecification element) {
      this.columnSpecifications.add(Objects.requireNonNull(element, "columnSpecifications element"));
      optBits |= OPT_BIT_COLUMN_SPECIFICATIONS;
      return this;
    }

    /**
     * Adds elements to {@link TableSpecification#getColumnSpecifications() columnSpecifications} list.
     * @param elements An array of columnSpecifications elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addColumnSpecifications(ColumnSpecification... elements) {
      for (ColumnSpecification element : elements) {
        this.columnSpecifications.add(Objects.requireNonNull(element, "columnSpecifications element"));
      }
      optBits |= OPT_BIT_COLUMN_SPECIFICATIONS;
      return this;
    }


    /**
     * Sets or replaces all elements for {@link TableSpecification#getColumnSpecifications() columnSpecifications} list.
     * @param elements An iterable of columnSpecifications elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder columnSpecifications(Iterable<? extends ColumnSpecification> elements) {
      this.columnSpecifications.clear();
      return addAllColumnSpecifications(elements);
    }

    /**
     * Adds elements to {@link TableSpecification#getColumnSpecifications() columnSpecifications} list.
     * @param elements An iterable of columnSpecifications elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllColumnSpecifications(Iterable<? extends ColumnSpecification> elements) {
      for (ColumnSpecification element : elements) {
        this.columnSpecifications.add(Objects.requireNonNull(element, "columnSpecifications element"));
      }
      optBits |= OPT_BIT_COLUMN_SPECIFICATIONS;
      return this;
    }

    /**
     * Adds one element to {@link TableSpecification#getIndexSpecifications() indexSpecifications} list.
     * @param element A indexSpecifications element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addIndexSpecifications(IndexSpecification element) {
      this.indexSpecifications.add(Objects.requireNonNull(element, "indexSpecifications element"));
      optBits |= OPT_BIT_INDEX_SPECIFICATIONS;
      return this;
    }

    /**
     * Adds elements to {@link TableSpecification#getIndexSpecifications() indexSpecifications} list.
     * @param elements An array of indexSpecifications elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addIndexSpecifications(IndexSpecification... elements) {
      for (IndexSpecification element : elements) {
        this.indexSpecifications.add(Objects.requireNonNull(element, "indexSpecifications element"));
      }
      optBits |= OPT_BIT_INDEX_SPECIFICATIONS;
      return this;
    }


    /**
     * Sets or replaces all elements for {@link TableSpecification#getIndexSpecifications() indexSpecifications} list.
     * @param elements An iterable of indexSpecifications elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder indexSpecifications(Iterable<? extends IndexSpecification> elements) {
      this.indexSpecifications.clear();
      return addAllIndexSpecifications(elements);
    }

    /**
     * Adds elements to {@link TableSpecification#getIndexSpecifications() indexSpecifications} list.
     * @param elements An iterable of indexSpecifications elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllIndexSpecifications(Iterable<? extends IndexSpecification> elements) {
      for (IndexSpecification element : elements) {
        this.indexSpecifications.add(Objects.requireNonNull(element, "indexSpecifications element"));
      }
      optBits |= OPT_BIT_INDEX_SPECIFICATIONS;
      return this;
    }

    /**
     * Builds a new {@link ImmutableTableSpecification ImmutableTableSpecification}.
     * @return An immutable instance of TableSpecification
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutableTableSpecification build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new ImmutableTableSpecification(this);
    }

    private boolean columnSpecificationsIsSet() {
      return (optBits & OPT_BIT_COLUMN_SPECIFICATIONS) != 0;
    }

    private boolean indexSpecificationsIsSet() {
      return (optBits & OPT_BIT_INDEX_SPECIFICATIONS) != 0;
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_NAME) != 0) attributes.add("name");
      return "Cannot build TableSpecification, some of required attributes are not set " + attributes;
    }
  }

  private static <T> List<T> createSafeList(Iterable<? extends T> iterable, boolean checkNulls, boolean skipNulls) {
    ArrayList<T> list;
    if (iterable instanceof Collection<?>) {
      int size = ((Collection<?>) iterable).size();
      if (size == 0) return Collections.emptyList();
      list = new ArrayList<>();
    } else {
      list = new ArrayList<>();
    }
    for (T element : iterable) {
      if (skipNulls && element == null) continue;
      if (checkNulls) Objects.requireNonNull(element, "element");
      list.add(element);
    }
    return list;
  }

  private static <T> List<T> createUnmodifiableList(boolean clone, List<T> list) {
    switch(list.size()) {
    case 0: return Collections.emptyList();
    case 1: return Collections.singletonList(list.get(0));
    default:
      if (clone) {
        return Collections.unmodifiableList(new ArrayList<>(list));
      } else {
        if (list instanceof ArrayList<?>) {
          ((ArrayList<?>) list).trimToSize();
        }
        return Collections.unmodifiableList(list);
      }
    }
  }
}
