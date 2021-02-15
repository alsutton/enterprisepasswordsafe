package com.enterprisepasswordsafe.database.derived;

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
 * Immutable implementation of {@link ExpiringAccessiblePasswords}.
 * <p>
 * Use the builder to create immutable instances:
 * {@code ImmutableExpiringAccessiblePasswords.builder()}.
 */
@Generated(from = "ExpiringAccessiblePasswords", generator = "Immutables")
@SuppressWarnings({"all"})
@javax.annotation.processing.Generated("org.immutables.processor.ProxyProcessor")
public final class ImmutableExpiringAccessiblePasswords
    implements ExpiringAccessiblePasswords {
  private final Set<Password> expiring;
  private final Set<Password> expired;

  private ImmutableExpiringAccessiblePasswords(ImmutableExpiringAccessiblePasswords.Builder builder) {
    if (builder.expiringIsSet()) {
      initShim.expiring(createUnmodifiableSet(builder.expiring));
    }
    if (builder.expiredIsSet()) {
      initShim.expired(createUnmodifiableSet(builder.expired));
    }
    this.expiring = initShim.getExpiring();
    this.expired = initShim.getExpired();
    this.initShim = null;
  }

  private ImmutableExpiringAccessiblePasswords(
      Set<Password> expiring,
      Set<Password> expired) {
    this.expiring = expiring;
    this.expired = expired;
    this.initShim = null;
  }

  private static final byte STAGE_INITIALIZING = -1;
  private static final byte STAGE_UNINITIALIZED = 0;
  private static final byte STAGE_INITIALIZED = 1;
  private transient volatile InitShim initShim = new InitShim();

  @Generated(from = "ExpiringAccessiblePasswords", generator = "Immutables")
  private final class InitShim {
    private byte expiringBuildStage = STAGE_UNINITIALIZED;
    private Set<Password> expiring;

    Set<Password> getExpiring() {
      if (expiringBuildStage == STAGE_INITIALIZING) throw new IllegalStateException(formatInitCycleMessage());
      if (expiringBuildStage == STAGE_UNINITIALIZED) {
        expiringBuildStage = STAGE_INITIALIZING;
        this.expiring = createUnmodifiableSet(createSafeList(getExpiringInitialize(), true, false));
        expiringBuildStage = STAGE_INITIALIZED;
      }
      return this.expiring;
    }

    void expiring(Set<Password> expiring) {
      this.expiring = expiring;
      expiringBuildStage = STAGE_INITIALIZED;
    }

    private byte expiredBuildStage = STAGE_UNINITIALIZED;
    private Set<Password> expired;

    Set<Password> getExpired() {
      if (expiredBuildStage == STAGE_INITIALIZING) throw new IllegalStateException(formatInitCycleMessage());
      if (expiredBuildStage == STAGE_UNINITIALIZED) {
        expiredBuildStage = STAGE_INITIALIZING;
        this.expired = createUnmodifiableSet(createSafeList(getExpiredInitialize(), true, false));
        expiredBuildStage = STAGE_INITIALIZED;
      }
      return this.expired;
    }

    void expired(Set<Password> expired) {
      this.expired = expired;
      expiredBuildStage = STAGE_INITIALIZED;
    }

    private String formatInitCycleMessage() {
      List<String> attributes = new ArrayList<>();
      if (expiringBuildStage == STAGE_INITIALIZING) attributes.add("expiring");
      if (expiredBuildStage == STAGE_INITIALIZING) attributes.add("expired");
      return "Cannot build ExpiringAccessiblePasswords, attribute initializers form cycle " + attributes;
    }
  }

  private Set<Password> getExpiringInitialize() {
    return ExpiringAccessiblePasswords.super.getExpiring();
  }

  private Set<Password> getExpiredInitialize() {
    return ExpiringAccessiblePasswords.super.getExpired();
  }

  /**
   * @return The value of the {@code expiring} attribute
   */
  @Override
  public Set<Password> getExpiring() {
    InitShim shim = this.initShim;
    return shim != null
        ? shim.getExpiring()
        : this.expiring;
  }

  /**
   * @return The value of the {@code expired} attribute
   */
  @Override
  public Set<Password> getExpired() {
    InitShim shim = this.initShim;
    return shim != null
        ? shim.getExpired()
        : this.expired;
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link ExpiringAccessiblePasswords#getExpiring() expiring}.
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableExpiringAccessiblePasswords withExpiring(Password... elements) {
    Set<Password> newValue = createUnmodifiableSet(createSafeList(Arrays.asList(elements), true, false));
    return new ImmutableExpiringAccessiblePasswords(newValue, this.expired);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link ExpiringAccessiblePasswords#getExpiring() expiring}.
   * A shallow reference equality check is used to prevent copying of the same value by returning {@code this}.
   * @param elements An iterable of expiring elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableExpiringAccessiblePasswords withExpiring(Iterable<? extends Password> elements) {
    if (this.expiring == elements) return this;
    Set<Password> newValue = createUnmodifiableSet(createSafeList(elements, true, false));
    return new ImmutableExpiringAccessiblePasswords(newValue, this.expired);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link ExpiringAccessiblePasswords#getExpired() expired}.
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableExpiringAccessiblePasswords withExpired(Password... elements) {
    Set<Password> newValue = createUnmodifiableSet(createSafeList(Arrays.asList(elements), true, false));
    return new ImmutableExpiringAccessiblePasswords(this.expiring, newValue);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link ExpiringAccessiblePasswords#getExpired() expired}.
   * A shallow reference equality check is used to prevent copying of the same value by returning {@code this}.
   * @param elements An iterable of expired elements to set
   * @return A modified copy of {@code this} object
   */
  public final ImmutableExpiringAccessiblePasswords withExpired(Iterable<? extends Password> elements) {
    if (this.expired == elements) return this;
    Set<Password> newValue = createUnmodifiableSet(createSafeList(elements, true, false));
    return new ImmutableExpiringAccessiblePasswords(this.expiring, newValue);
  }

  /**
   * This instance is equal to all instances of {@code ImmutableExpiringAccessiblePasswords} that have equal attribute values.
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof ImmutableExpiringAccessiblePasswords
        && equalTo((ImmutableExpiringAccessiblePasswords) another);
  }

  private boolean equalTo(ImmutableExpiringAccessiblePasswords another) {
    return expiring.equals(another.expiring)
        && expired.equals(another.expired);
  }

  /**
   * Computes a hash code from attributes: {@code expiring}, {@code expired}.
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + expiring.hashCode();
    h += (h << 5) + expired.hashCode();
    return h;
  }

  /**
   * Prints the immutable value {@code ExpiringAccessiblePasswords} with attribute values.
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "ExpiringAccessiblePasswords{"
        + "expiring=" + expiring
        + ", expired=" + expired
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link ExpiringAccessiblePasswords} value.
   * Uses accessors to get values to initialize the new immutable instance.
   * If an instance is already immutable, it is returned as is.
   * @param instance The instance to copy
   * @return A copied immutable ExpiringAccessiblePasswords instance
   */
  public static ImmutableExpiringAccessiblePasswords copyOf(ExpiringAccessiblePasswords instance) {
    if (instance instanceof ImmutableExpiringAccessiblePasswords) {
      return (ImmutableExpiringAccessiblePasswords) instance;
    }
    return ImmutableExpiringAccessiblePasswords.builder()
        .from(instance)
        .build();
  }

  /**
   * Creates a builder for {@link ImmutableExpiringAccessiblePasswords ImmutableExpiringAccessiblePasswords}.
   * <pre>
   * ImmutableExpiringAccessiblePasswords.builder()
   *    .addExpiring|addAllExpiring(com.enterprisepasswordsafe.database.Password) // {@link ExpiringAccessiblePasswords#getExpiring() expiring} elements
   *    .addExpired|addAllExpired(com.enterprisepasswordsafe.database.Password) // {@link ExpiringAccessiblePasswords#getExpired() expired} elements
   *    .build();
   * </pre>
   * @return A new ImmutableExpiringAccessiblePasswords builder
   */
  public static ImmutableExpiringAccessiblePasswords.Builder builder() {
    return new ImmutableExpiringAccessiblePasswords.Builder();
  }

  /**
   * Builds instances of type {@link ImmutableExpiringAccessiblePasswords ImmutableExpiringAccessiblePasswords}.
   * Initialize attributes and then invoke the {@link #build()} method to create an
   * immutable instance.
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or collection,
   * but instead used immediately to create instances.</em>
   */
  @Generated(from = "ExpiringAccessiblePasswords", generator = "Immutables")
  public static final class Builder {
    private static final long OPT_BIT_EXPIRING = 0x1L;
    private static final long OPT_BIT_EXPIRED = 0x2L;
    private long optBits;

    private List<Password> expiring = new ArrayList<Password>();
    private List<Password> expired = new ArrayList<Password>();

    private Builder() {
    }

    /**
     * Fill a builder with attribute values from the provided {@code ExpiringAccessiblePasswords} instance.
     * Regular attribute values will be replaced with those from the given instance.
     * Absent optional values will not replace present values.
     * Collection elements and entries will be added, not replaced.
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(ExpiringAccessiblePasswords instance) {
      Objects.requireNonNull(instance, "instance");
      addAllExpiring(instance.getExpiring());
      addAllExpired(instance.getExpired());
      return this;
    }

    /**
     * Adds one element to {@link ExpiringAccessiblePasswords#getExpiring() expiring} set.
     * @param element A expiring element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addExpiring(Password element) {
      this.expiring.add(Objects.requireNonNull(element, "expiring element"));
      optBits |= OPT_BIT_EXPIRING;
      return this;
    }

    /**
     * Adds elements to {@link ExpiringAccessiblePasswords#getExpiring() expiring} set.
     * @param elements An array of expiring elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addExpiring(Password... elements) {
      for (Password element : elements) {
        this.expiring.add(Objects.requireNonNull(element, "expiring element"));
      }
      optBits |= OPT_BIT_EXPIRING;
      return this;
    }


    /**
     * Sets or replaces all elements for {@link ExpiringAccessiblePasswords#getExpiring() expiring} set.
     * @param elements An iterable of expiring elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder expiring(Iterable<? extends Password> elements) {
      this.expiring.clear();
      return addAllExpiring(elements);
    }

    /**
     * Adds elements to {@link ExpiringAccessiblePasswords#getExpiring() expiring} set.
     * @param elements An iterable of expiring elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllExpiring(Iterable<? extends Password> elements) {
      for (Password element : elements) {
        this.expiring.add(Objects.requireNonNull(element, "expiring element"));
      }
      optBits |= OPT_BIT_EXPIRING;
      return this;
    }

    /**
     * Adds one element to {@link ExpiringAccessiblePasswords#getExpired() expired} set.
     * @param element A expired element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addExpired(Password element) {
      this.expired.add(Objects.requireNonNull(element, "expired element"));
      optBits |= OPT_BIT_EXPIRED;
      return this;
    }

    /**
     * Adds elements to {@link ExpiringAccessiblePasswords#getExpired() expired} set.
     * @param elements An array of expired elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addExpired(Password... elements) {
      for (Password element : elements) {
        this.expired.add(Objects.requireNonNull(element, "expired element"));
      }
      optBits |= OPT_BIT_EXPIRED;
      return this;
    }


    /**
     * Sets or replaces all elements for {@link ExpiringAccessiblePasswords#getExpired() expired} set.
     * @param elements An iterable of expired elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder expired(Iterable<? extends Password> elements) {
      this.expired.clear();
      return addAllExpired(elements);
    }

    /**
     * Adds elements to {@link ExpiringAccessiblePasswords#getExpired() expired} set.
     * @param elements An iterable of expired elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllExpired(Iterable<? extends Password> elements) {
      for (Password element : elements) {
        this.expired.add(Objects.requireNonNull(element, "expired element"));
      }
      optBits |= OPT_BIT_EXPIRED;
      return this;
    }

    /**
     * Builds a new {@link ImmutableExpiringAccessiblePasswords ImmutableExpiringAccessiblePasswords}.
     * @return An immutable instance of ExpiringAccessiblePasswords
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public ImmutableExpiringAccessiblePasswords build() {
      return new ImmutableExpiringAccessiblePasswords(this);
    }

    private boolean expiringIsSet() {
      return (optBits & OPT_BIT_EXPIRING) != 0;
    }

    private boolean expiredIsSet() {
      return (optBits & OPT_BIT_EXPIRED) != 0;
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
