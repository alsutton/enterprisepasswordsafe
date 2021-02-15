package com.enterprisepasswordsafe.database.abstraction;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.immutables.value.Generated;

/**
 * Immutable implementation of {@link IndexSpecification}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutableIndexSpecification.builder()}.
 */
@Generated(from = "IndexSpecification", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutableIndexSpecification
    implements IndexSpecification {
  private final String indexName;
  private final String tableName;
  private final List<ColumnSpecification> columns;
  private final boolean isUnique;

  private ImmutableIndexSpecification(ImmutableIndexSpecification.Builder builder) {
    this.indexName = builder.indexName;
    this.tableName = builder.tableName;
    this.columns = createUnmodifiableList(true, builder.columns);
    this.isUnique = builder.isUniqueIsSet()
        ? builder.isUnique
        : IndexSpecification.super.isUnique();
  }

  private ImmutableIndexSpecification(
      String indexName,
      String tableName,
      List<ColumnSpecification> columns,
      boolean isUnique) {
    this.indexName = indexName;
    this.tableName = tableName;
    this.columns = columns;
    this.isUnique = isUnique;
  }

  /**
   * @return The value of the {@code indexName} attribute
   */
  @Override
  public String getIndexName() {
    return indexName;
  }

  /**
   * @return The value of the {@code tableName} attribute
   */
  @Override
  public String getTableName() {
    return tableName;
  }

  /**
   * @return The value of the {@code columns} attribute
   */
  @Override
  public List<ColumnSpecification> getColumns() {
    return columns;
  }

  /**
   * @return The value of the {@code isUnique} attribute
   */
  @Override
  public boolean isUnique() {
    return isUnique;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link IndexSpecification#getIndexName() indexName} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for indexName
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableIndexSpecification withIndexName(String value) {
    String newValue = Objects.requireNonNull(value, "indexName");
    if (this.indexName.equals(newValue)) return this;
    return new ImmutableIndexSpecification(newValue, this.tableName, this.columns, this.isUnique);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link IndexSpecification#getTableName() tableName} attribute.
   * An equals check used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for tableName
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableIndexSpecification withTableName(String value) {
    String newValue = Objects.requireNonNull(value, "tableName");
    if (this.tableName.equals(newValue)) return this;
    return new ImmutableIndexSpecification(this.indexName, newValue, this.columns, this.isUnique);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link IndexSpecification#getColumns() columns}.
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableIndexSpecification withColumns(ColumnSpecification... elements) {
    List<ColumnSpecification> newValue = createUnmodifiableList(false, createSafeList(Arrays.asList(elements), true, false));
    return new ImmutableIndexSpecification(this.indexName, this.tableName, newValue, this.isUnique);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link IndexSpecification#getColumns() columns}.
   * A shallow reference equality check is used to prevent copying of the same value by returning {@code this}.
   * @param elements An iterable of columns elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableIndexSpecification withColumns(Iterable<? extends ColumnSpecification> elements) {
    if (this.columns == elements) return this;
    List<ColumnSpecification> newValue = createUnmodifiableList(false, createSafeList(elements, true, false));
    return new ImmutableIndexSpecification(this.indexName, this.tableName, newValue, this.isUnique);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link IndexSpecification#isUnique() isUnique} attribute.
   * A value equality check is used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for isUnique
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableIndexSpecification withIsUnique(boolean value) {
    if (this.isUnique == value) return this;
    return new ImmutableIndexSpecification(this.indexName, this.tableName, this.columns, value);
  }

  /**
   * This instance is equal to all instances of {@code ImmutableIndexSpecification} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutableIndexSpecification
        && equalTo((ImmutableIndexSpecification) another);
  }

  private boolean equalTo(ImmutableIndexSpecification another) {
    return indexName.equals(another.indexName)
        && tableName.equals(another.tableName)
        && columns.equals(another.columns)
        && isUnique == another.isUnique;
  }

  /**
   * Computes a hash code from attributes: {@code indexName}, {@code tableName}, {@code columns}, {@code isUnique}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + indexName.hashCode();
    h += (h << 5) + tableName.hashCode();
    h += (h << 5) + columns.hashCode();
    h += (h << 5) + Boolean.hashCode(isUnique);
    return h;
  }

  /**
   * Prints the immutable value {@code IndexSpecification} with attribute values.
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "IndexSpecification{"
        + "indexName=" + indexName
        + ", tableName=" + tableName
        + ", columns=" + columns
        + ", isUnique=" + isUnique
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link IndexSpecification} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable IndexSpecification instance
   */
  public static ImmutableIndexSpecification copyOf(IndexSpecification instance) {
    if (instance instanceof ImmutableIndexSpecification) {
      return (ImmutableIndexSpecification) instance;
    }
    return ImmutableIndexSpecification.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutableIndexSpecification ImmutableIndexSpecification}.
   * <pre>
   * ImmutableIndexSpecification.builder()
   *    .indexName(String) // required {@link IndexSpecification#getIndexName() indexName}
   *    .tableName(String) // required {@link IndexSpecification#getTableName() tableName}
   *    .addColumns|addAllColumns(com.enterprisepasswordsafe.database.abstraction.ColumnSpecification) // {@link IndexSpecification#getColumns() columns} elements
   *    .isUnique(boolean) // optional {@link IndexSpecification#isUnique() isUnique}
   *    .build();
   * </pre>
   * @return A new ImmutableIndexSpecification builder
   */
  public static ImmutableIndexSpecification.Builder builder() {
    return new ImmutableIndexSpecification.Builder();
  }

  /**
   * Builds instances of type {@link ImmutableIndexSpecification ImmutableIndexSpecification}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "IndexSpecification", generator = "Immutables")
  public static final class Builder {
    private static final long INIT_BIT_INDEX_NAME = 0x1L;
    private static final long INIT_BIT_TABLE_NAME = 0x2L;
    private static final long OPT_BIT_IS_UNIQUE = 0x1L;
    private long initBits = 0x3L;
    private long optBits;

    private String indexName;
    private String tableName;
    private List<ColumnSpecification> columns = new ArrayList<ColumnSpecification>();
    private boolean isUnique;

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code IndexSpecification} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * Collection elements and entries will be added, not replaced.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(IndexSpecification instance) {
      Objects.requireNonNull(instance, "instance");
      indexName(instance.getIndexName());
      tableName(instance.getTableName());
      addAllColumns(instance.getColumns());
      isUnique(instance.isUnique());
      return this;
    }

    /**
     * Initializes the value for the {@link IndexSpecification#getIndexName() indexName} attribute.
     * @param indexName The value for indexName 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder indexName(String indexName) {
      this.indexName = Objects.requireNonNull(indexName, "indexName");
      initBits &= ~INIT_BIT_INDEX_NAME;
      return this;
    }

    /**
     * Initializes the value for the {@link IndexSpecification#getTableName() tableName} attribute.
     * @param tableName The value for tableName 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder tableName(String tableName) {
      this.tableName = Objects.requireNonNull(tableName, "tableName");
      initBits &= ~INIT_BIT_TABLE_NAME;
      return this;
    }

    /**
     * Adds one element to {@link IndexSpecification#getColumns() columns} list.
     * @param element A columns element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addColumns(ColumnSpecification element) {
      this.columns.add(Objects.requireNonNull(element, "columns element"));
      return this;
    }

    /**
     * Adds elements to {@link IndexSpecification#getColumns() columns} list.
     * @param elements An array of columns elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addColumns(ColumnSpecification... elements) {
      for (ColumnSpecification element : elements) {
        this.columns.add(Objects.requireNonNull(element, "columns element"));
      }
      return this;
    }


    /**
     * Sets or replaces all elements for {@link IndexSpecification#getColumns() columns} list.
     * @param elements An iterable of columns elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder columns(Iterable<? extends ColumnSpecification> elements) {
      this.columns.clear();
      return addAllColumns(elements);
    }

    /**
     * Adds elements to {@link IndexSpecification#getColumns() columns} list.
     * @param elements An iterable of columns elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllColumns(Iterable<? extends ColumnSpecification> elements) {
      for (ColumnSpecification element : elements) {
        this.columns.add(Objects.requireNonNull(element, "columns element"));
      }
      return this;
    }

    /**
     * Initializes the value for the {@link IndexSpecification#isUnique() isUnique} attribute.
     * <p><em>If not set, this attribute will have a default value as returned by the initializer of {@link IndexSpecification#isUnique() isUnique}.</em>
     * @param isUnique The value for isUnique 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder isUnique(boolean isUnique) {
      this.isUnique = isUnique;
      optBits |= OPT_BIT_IS_UNIQUE;
      return this;
    }

    /**
     * Builds a new {@link ImmutableIndexSpecification ImmutableIndexSpecification}.
     * @return An immutable instance of IndexSpecification
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutableIndexSpecification build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new ImmutableIndexSpecification(this);
    }

    private boolean isUniqueIsSet() {
      return (optBits & OPT_BIT_IS_UNIQUE) != 0;
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_INDEX_NAME) != 0) attributes.add("indexName");
      if ((initBits & INIT_BIT_TABLE_NAME) != 0) attributes.add("tableName");
      return "Cannot build IndexSpecification, some of required attributes are not set " + attributes;
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
