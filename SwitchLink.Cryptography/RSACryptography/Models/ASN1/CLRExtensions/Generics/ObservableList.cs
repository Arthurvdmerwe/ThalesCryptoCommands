using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.CLRExtensions.Generics {
    /// <summary>
    /// Represents a dynamic data collection that provides notifications when items get added, removed, or when
    /// the whole list is refreshed.
    /// <para>
    /// This class replaces standard <see cref="ObservableCollection{T}"/> by extending its flexibility.
    /// </para>
    /// </summary>
    /// <typeparam name="T">The type of elements in the collection.</typeparam>
	public class ObservableList<T> : List<T>, IList<T>, INotifyCollectionChanged, INotifyPropertyChanged {
        /// <summary>
        /// Initializes a new instance of the ObservableList&lt;T&gt; class and specifies whether it provides
        /// observation features.
        /// </summary>
        /// <param name="observe">
        /// <strong>True</strong> if event subscribers are notified about collection changes,
        /// otherwise <strong>False</strong>.
        /// </param>
		public ObservableList(Boolean observe) {
			IsNotifying = observe;
			if (observe) {
				CollectionChanged += delegate { OnPropertyChanged("Count"); };
			}
		}

        /// <summary>
        /// Gets or sets the status of event subscriber notification. <strong>True</strong> if event subscribers
        /// are notified about collection changes, otherwise <strong>False</strong>.
        /// </summary>
		public Boolean IsNotifying { get; set; }

        /// <summary>
        /// Adds an object to the end of the Collection&lt;T&gt;.
        /// </summary>
        /// <param name="item">Item to add.</param>
		public new void Add(T item) {
			base.Add(item);
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, item);
			OnCollectionChanged(e);
		}
        /// <summary>
        /// Adds an object collection to the end of the Collection&lt;T&gt;. If enabled, this method notifies
        /// event subscribers only once, when all items are added.
        /// </summary>
        /// <param name="collection">Items to add</param>
		public new void AddRange(IEnumerable<T> collection) {
			base.AddRange(collection);
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, new List<T>(collection));
			OnCollectionChanged(e);
		}
        /// <summary>
        /// Adds an object collection to the end of the Collection&lt;T&gt;. This method do not notify
        /// event subscribers about collection change.
        /// </summary>
        /// <param name="collection"></param>
        public void AddRangeSlient(IEnumerable<T> collection) {
            base.AddRange(collection);
        }
        /// <summary>
        /// Removes all elements from the Collection&lt;T&gt;.
        /// </summary>
		public new void Clear() {
			base.Clear();
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset);
			OnCollectionChanged(e);
		}
        /// <summary>
        /// Inserts an element into the Collection&lt;T&gt; at the specified index.
        /// </summary>
        /// <param name="i">The zero-based index at which <i>item</i> should be inserted.</param>
        /// <param name="item">The object to insert. The value can be null for reference types.</param>
		public new void Insert(Int32 i, T item) {
			base.Insert(i, item);
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, item);
			OnCollectionChanged(e);
		}
        /// <summary>
        /// Inserts an element collection into the Collection&lt;T&gt; at the specified index.
        /// If enabled, this method notifies event subscribers only once, when all items are inserted.
        /// </summary>
        /// <param name="i">The zero-based index at which <i>items</i> should be inserted.</param>
        /// <param name="collection">A collection to insert.</param>
		public new void InsertRange(Int32 i, IEnumerable<T> collection) {
			base.InsertRange(i, collection);
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, collection);
			OnCollectionChanged(e);
		}
        /// <summary>
        /// Inserts an element collection into the Collection&lt;T&gt; at the specified index.
        /// This method do not notify event subscribers about collection change.
        /// </summary>
        /// <param name="i">The zero-based index at which <i>items</i> should be inserted.</param>
        /// <param name="collection">A collection to insert.</param>
        public void InsertRangeSilent(Int32 i, IEnumerable<T> collection) {
            base.InsertRange(i, collection);
        }
        /// <summary>
        /// Removes the first occurrence of a specific object from the Collection&lt;T&gt;.
        /// </summary>
        /// <param name="item">The object to remove.</param>
		public new void Remove(T item) {
			base.Remove(item);
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Remove, item);
			OnCollectionChanged(e);
        }
        /// <summary>
        /// Removes all the elements that match the conditions defined by the specified predicate.
        /// </summary>
        /// <param name="match">
        /// The <see cref="Predicate{T}"/> delegate that defines the conditions of the elements to remove.
        /// </param>
		public new void RemoveAll(Predicate<T> match) {
			List<T> backup = FindAll(match);
			base.RemoveAll(match);
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Remove, backup);
			OnCollectionChanged(e);
		}
        /// <summary>
        /// Removes the element at the specified index of the Collection&lt;T&gt;.
        /// </summary>
        /// <param name="i">The zero-based index at which <i>item</i> should be removed.</param>
		public new void RemoveAt(Int32 i) {
			T backup = this[i];
			base.RemoveAt(i);
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Remove, backup);
			OnCollectionChanged(e);
        }
        /// <summary>
        /// Removes a range of elements from the Collection&lt;T&gt;.
        /// If enabled, this method notifies event subscribers only once, when all items are inserted.
        /// </summary>
        /// <param name="index">The zero-based starting index of the range of elements to remove.</param>
        /// <param name="count">The number of elements to remove.</param>
		public new void RemoveRange(Int32 index, Int32 count) {
			List<T> backup = GetRange(index, count);
			base.RemoveRange(index, count);
			var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Remove, backup);
			OnCollectionChanged(e);
		}
        /// <summary>
        /// Removes a range of elements from the Collection&lt;T&gt;.
        /// This method do not notify event subscribers about collection change.
        /// </summary>
        /// <param name="index">The zero-based starting index of the range of elements to remove.</param>
        /// <param name="count">The number of elements to remove.</param>
        public void RemoveRangeSilent(Int32 index, Int32 count) {
            base.RemoveRange(index, count);
        }
        /// <summary>
        /// Gets or sets the element at the specified index.
        /// </summary>
        /// <param name="index">The zero-based index of the element to get or set.</param>
        /// <returns>The element at the specified index.</returns>
		public new T this[Int32 index] {
			get { return base[index]; }
			set {
				T oldValue = base[index];
				NotifyCollectionChangedEventArgs e =
					new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Replace, value, oldValue);
				OnCollectionChanged(e);
			}
		}

        /// <summary>
        /// Forces <see cref="NotifyCollectionChangedEventHandler"/> raise.
        /// </summary>
        public void ForceUpdate() {
            List<T> backup = this.ToList();
            var e = new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset, backup);
            OnCollectionChanged(e);
        }

        /// <summary>
        /// Occurs when an item is added, removed, changed, moved, or the entire list is refreshed.
        /// </summary>
        /// <param name="e">Event arguments.</param>
		protected void OnCollectionChanged(NotifyCollectionChangedEventArgs e) {
			if (IsNotifying && CollectionChanged != null) {
				try {
					CollectionChanged(this, e);
				} catch (NotSupportedException) {
					NotifyCollectionChangedEventArgs alternativeEventArgs =
						new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset);
					OnCollectionChanged(alternativeEventArgs);
				}
			}
		}
        /// <summary>
        /// Called when a property value changes.
        /// </summary>
        /// <param name="propertyName">Property name which value is changed.</param>
		protected void OnPropertyChanged(String propertyName) {
			PropertyChangedEventHandler handler = PropertyChanged;
			if (handler != null) {
				handler(this, new PropertyChangedEventArgs(propertyName));
			}
		}
        /// <summary>
        /// Occurs when a property value changes.
        /// </summary>
		public event PropertyChangedEventHandler PropertyChanged;
        /// <summary>
        /// Occurs when an item is added, removed, changed, moved, or the entire list is refreshed.
        /// </summary>
		public event NotifyCollectionChangedEventHandler CollectionChanged;
	}

}
