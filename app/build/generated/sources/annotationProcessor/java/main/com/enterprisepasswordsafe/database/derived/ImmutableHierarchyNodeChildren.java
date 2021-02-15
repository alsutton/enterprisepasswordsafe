package com.enterprisepasswordsafe.database.derived;

import com.enterprisepasswordsafe.database.HierarchyNode;
import com.enterprisepasswordsafe.database.Password;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.immutables.value.Generated;

/**
 * Immutable implementation of {@link HierarchyNodeChildren}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutableHierarchyNodeChildren.builder()}.
 */
@Generated(from = "HierarchyNodeChildren", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutableHierarchyNodeChildren
    implements HierarchyNodeChildren {
  private final Collection<HierarchyNode> nodes;
  private final Set<Password> objects;

  private ImmutableHierarchyNodeChildren(
      Collection<HierarchyNode> nodes,
      Set<Password> objects) {
    this.nodes = nodes;
    this.objects = objects;
  }

  /**
   * @return The value of the {@code nodes} attribute
   */
  @Override
  public Collection<HierarchyNode> getNodes() {
    return nodes;
  }

  /**
   * @return The value of the {@code objects} attribute
   */
  @Override
  public Set<Password> getObjects() {
    return objects;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link HierarchyNodeChildren#getNodes() nodes} attribute.
   * A shallow reference equality check is used to prevent copying of the same value by returning {@code this}.
   * @param value A new value for nodes
   * @return A modified copy of the {@code this} object
   */
  public final ImmutableHierarchyNodeChildren withNodes(Collection<HierarchyNode> value) {
    if (this.nodes == value) return this;
    Collection<HierarchyNode> newValue = Objects.requireNonNull(value, "nodes");
    return new ImmutableHierarchyNodeChildren(newValue, this.objects);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link HierarchyNodeChildren#getObjects() objects}.
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableHierarchyNodeChildren withObjects(Password... elements) {
    Set<Password> newValue = createUnmodifiableSet(createSafeList(Arrays.asList(elements), true, false));
    return new ImmutableHierarchyNodeChildren(this.nodes, newValue);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link HierarchyNodeChildren#getObjects() objects}.
   * A shallow reference equality check is used to prevent copying of the same value by returning {@code this}.
   * @param elements An iterable of objects elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableHierarchyNodeChildren withObjects(Iterable<? extends Password> elements) {
    if (this.objects == elements) return this;
    Set<Password> newValue = createUnmodifiableSet(createSafeList(elements, true, false));
    return new ImmutableHierarchyNodeChildren(this.nodes, newValue);
  }

  /**
   * This instance is equal to all instances of {@code ImmutableHierarchyNodeChildren} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutableHierarchyNodeChildren
        && equalTo((ImmutableHierarchyNodeChildren) another);
  }

  private boolean equalTo(ImmutableHierarchyNodeChildren another) {
    return nodes.equals(another.nodes)
        && objects.equals(another.objects);
  }

  /**
   * Computes a hash code from attributes: {@code nodes}, {@code objects}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + nodes.hashCode();
    h += (h << 5) + objects.hashCode();
    return h;
  }

  /**
   * Prints the immutable value {@code HierarchyNodeChildren} with attribute values.
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "HierarchyNodeChildren{"
        + "nodes=" + nodes
        + ", objects=" + objects
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link HierarchyNodeChildren} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable HierarchyNodeChildren instance
   */
  public static ImmutableHierarchyNodeChildren copyOf(HierarchyNodeChildren instance) {
    if (instance instanceof ImmutableHierarchyNodeChildren) {
      return (ImmutableHierarchyNodeChildren) instance;
    }
    return ImmutableHierarchyNodeChildren.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutableHierarchyNodeChildren ImmutableHierarchyNodeChildren}.
   * <pre>
   * ImmutableHierarchyNodeChildren.builder()
   *    .nodes(Collection&amp;lt;com.enterprisepasswordsafe.database.HierarchyNode&amp;gt;) // required {@link HierarchyNodeChildren#getNodes() nodes}
   *    .addObjects|addAllObjects(com.enterprisepasswordsafe.database.Password) // {@link HierarchyNodeChildren#getObjects() objects} elements
   *    .build();
   * </pre>
   * @return A new ImmutableHierarchyNodeChildren builder
   */
  public static ImmutableHierarchyNodeChildren.Builder builder() {
    return new ImmutableHierarchyNodeChildren.Builder();
  }

  /**
   * Builds instances of type {@link ImmutableHierarchyNodeChildren ImmutableHierarchyNodeChildren}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "HierarchyNodeChildren", generator = "Immutables")
  public static final class Builder {
    private static final long INIT_BIT_NODES = 0x1L;
    private long initBits = 0x1L;

    private Collection<HierarchyNode> nodes;
    private List<Password> objects = new ArrayList<Password>();

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code HierarchyNodeChildren} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * Collection elements and entries will be added, not replaced.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(HierarchyNodeChildren instance) {
      Objects.requireNonNull(instance, "instance");
      nodes(instance.getNodes());
      addAllObjects(instance.getObjects());
      return this;
    }

    /**
     * Initializes the value for the {@link HierarchyNodeChildren#getNodes() nodes} attribute.
     * @param nodes The value for nodes 
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder nodes(Collection<HierarchyNode> nodes) {
      this.nodes = Objects.requireNonNull(nodes, "nodes");
      initBits &= ~INIT_BIT_NODES;
      return this;
    }

    /**
     * Adds one element to {@link HierarchyNodeChildren#getObjects() objects} set.
     * @param element A objects element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addObjects(Password element) {
      this.objects.add(Objects.requireNonNull(element, "objects element"));
      return this;
    }

    /**
     * Adds elements to {@link HierarchyNodeChildren#getObjects() objects} set.
     * @param elements An array of objects elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addObjects(Password... elements) {
      for (Password element : elements) {
        this.objects.add(Objects.requireNonNull(element, "objects element"));
      }
      return this;
    }


    /**
     * Sets or replaces all elements for {@link HierarchyNodeChildren#getObjects() objects} set.
     * @param elements An iterable of objects elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder objects(Iterable<? extends Password> elements) {
      this.objects.clear();
      return addAllObjects(elements);
    }

    /**
     * Adds elements to {@link HierarchyNodeChildren#getObjects() objects} set.
     * @param elements An iterable of objects elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllObjects(Iterable<? extends Password> elements) {
      for (Password element : elements) {
        this.objects.add(Objects.requireNonNull(element, "objects element"));
      }
      return this;
    }

    /**
     * Builds a new {@link ImmutableHierarchyNodeChildren ImmutableHierarchyNodeChildren}.
     * @return An immutable instance of HierarchyNodeChildren
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutableHierarchyNodeChildren build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new ImmutableHierarchyNodeChildren(nodes, createUnmodifiableSet(objects));
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_NODES) != 0) attributes.add("nodes");
      return "Cannot build HierarchyNodeChildren, some of required attributes are not set " + attributes;
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

  /** Unmodifiable set constructed from list to avoid rehashing. */
  private static <T> Set<T> createUnmodifiableSet(List<T> list) {
    switch(list.size()) {
    case 0: return Collections.emptySet();
    case 1: return Collections.singleton(list.get(0));
    default:
      Set<T> set = new LinkedHashSet<>(list.size());
      set.addAll(list);
      return Collections.unmodifiableSet(set);
    }
  }
}
