using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Tree {
    public class GenericAsn1Tree<T> : INotifyPropertyChanged where T : GenericAsn1Tree<T>, IAsn1NodeValue {
		// List of children
		readonly ObservableCollection<T> _children = new ObservableCollection<T>();

		static GenericAsn1Tree() {
			PathDelimeter = '/';
		}

		protected GenericAsn1Tree(IAsn1TreeSource source) {
			Source = source;
		}

		protected IAsn1TreeSource Source { get; private set; }

		/// <summary>
		/// Gets the parent node.
		/// </summary>
		public GenericAsn1Tree<T> Parent { get; private set; }
		/// <summary>
		/// Gets the children for this tree.
		/// </summary>
		public ReadOnlyObservableCollection<T> Children {
			get { return new ReadOnlyObservableCollection<T>(_children); }
		}
		/// <summary>
		/// Gets a child at the specified index.
		/// </summary>
		/// <param name="index"></param>
		/// <returns></returns>
		public T this[Int32 index] {
			get { return _children[index]; }
		}

		/// <summary>
		/// Add a child node to the tree.
		/// </summary>
		/// <param name="node">Node to add.</param>
		/// <remarks>
		/// This method shall be used only during initial tree building. This method do not update
		/// binary copy and relevant node data. Use <see cref="AddSafe"/> method to add new node to
		/// existing binary source.
		/// </remarks>
		public void AddUnsafe(T node) {
			// TODO do something with checks. They seems good, but needs an Equals method.
			// check to see if node is self
			//if (node == this) {
			//	throw new Exception("Cannot add self to children.");
			//}
			//// check to see if node is in children
			//if (this == node.Parent) {
			//	throw new Exception("Node already exists in children.");
			//}
			//// check to see if the node is an ancestor
			//T parent = (T)Parent;
			//while (parent != null) {
			//	if (parent == node) {
			//		throw new Exception("Node is an ancestor to this node.");
			//	}
			//	parent = (T)parent.Parent;
			//}
			//if (node.Parent != null) {
			//	node.Parent.RemoveChild(node);
			//}
			node.Parent = this;
			_children.Add(node);
			Int32 newIndex = _children.Count - 1;
			node.MyIndex = newIndex;
		}
		public Int32 AddSafe(T node) {
            Insert(Children.Count, node);
            return Children.Count - 1;
		}
		/// <summary>
		/// Removes child node from tree.  Sets the parent of the node to null.
		/// </summary>
		/// <param name="node">Node to remove</param>
		/// <returns>True if removed. False if not.</returns>
		public void Remove(T node) {
            Int32 difference = node.TagLength;
            Source.RawData.RemoveRange(node.Offset, difference);
            _children.RemoveAt(node.MyIndex);
            notifyLengthChanged(-difference);
        }
        public void Insert(Int32 indexToInsert, T node) {
            if (indexToInsert < 0) {
                throw new IndexOutOfRangeException();
            }
            T me = (T)this;
            if (Parent != null && Asn1Reader.GetRestrictedTags().Contains(me.Tag)) {
                throw new InvalidOperationException();
            }
            node.Parent = this;
            // if indexToInsert is greater than Children length, append node to the end.
            Int32 newOffset;
            Boolean insert;
            if (indexToInsert >= _children.Count) {
                newOffset = me.Offset + me.TagLength;
                insert = false;
            }  else {
                newOffset = _children[indexToInsert].Offset;
                insert = true;
            }
            Int32 offsetDifference = node.Offset - newOffset;
            // update offsets for inserted node
            updateOffsetByCaller(node, offsetDifference);
            // update offset for all nodes below inserted node
            updateOffsetByIndex(indexToInsert, node.TagLength);
            if (insert) {
                _children.Insert(indexToInsert, node);
            } else {
                _children.Add(node);
            }
            // update binary copy.
            Source.RawData.InsertRange(newOffset, node.GetRawData());
            //
            notifyLengthChanged(node.TagLength);
            Source.RawData.ForceUpdate();
        }
		/// <summary>
		/// Traverses all of the tree nodes executing the specified action. Visitor pattern.
		/// </summary>
		/// <param name="action">Action to execute.</param>
		public void Traverse(Action<T> action) {
			action((T)this);
			foreach (var c in _children) {
				c.Traverse(action);
			}
		}
		/// <summary>
		/// Expands entire tree to a flat array.
		/// </summary>
		/// <returns></returns>
		public IEnumerable<T> Flatten() {
			return (IEnumerable<T>) new[] { this }.Union(_children.SelectMany(x => x.Flatten()));
		}
		/// <summary>
		/// Finds a node using the specified predicate.
		/// </summary>
		/// <param name="predicate">Predictate</param>
		/// <returns>First node where predicate is true.</returns>
		public T Find(Predicate<T> predicate) {
			if (predicate((T)this)) {
				return (T)this;
			}
			foreach (T child in _children) {
				var found = child.Find(predicate);
				if (found != null) {
					return found;
				}
			}
			return null;
		}
		/// <summary>
		/// Finds the specified node in the descendants.
		/// </summary>
		/// <param name="tree">Node to search for.</param>
		/// <returns>Found node.  Null if not found in descendants.</returns>
		public T Find(T tree) {
			if (tree == this) {
				return (T)this;
			}
			foreach (var c in _children) {
				var found = c.Find(tree);
				if (found != null) {
					return found;
				}
			}
			return null;
		}

		/// <summary>
		/// Gets or sets the path delimeter. Default value is '/'.
		/// </summary>
		public static Char PathDelimeter { get; set; }

		/// <summary>
		/// Gets the node's index in the parent collection.
		/// </summary>
		public Int32 MyIndex { get; private set; }
		/// <summary>
		/// Gets the path of the current node in the tree.
		/// </summary>
		public String Path {
			get {
				return Parent == null
					? String.Empty
					: Parent.Path + PathDelimeter + MyIndex;
			}
		}
		/// <summary>
		/// Gets the depth of the current node in the tree.
		/// </summary>
		public Int32 Deepness {
			get { return (Path.Split(PathDelimeter)).Length / 2; }
		}

		// updates offset at tree part down below the caller's node.
        // Verified: true
		void updateOffsetByIndex(Int32 callerIndex, Int32 difference) {
			T caller = Children[callerIndex];
			for (Int32 index = callerIndex + 1; index < Children.Count; index++) {
				Children[index].updateOffsetByCaller(caller, difference);
			}
			notifyLengthChanged(difference);
		    Parent?.updateOffsetByIndex(MyIndex, difference);
		}
        // updates new offset down the specified node only.
        // This method is used when node is added or inserted.
        // Verified: true
        void updateOffsetByCaller(T startNode, Int32 difference) {
            startNode.Offset += difference;
            foreach (T child in Children) {
                child.updateOffsetByCaller(child, difference);
            }
        }
        // updates binary source (header).
        // If header length (in bytes) is changed, all child nodes receives new offset
        // Verified: true
        void notifyLengthChanged(Int32 difference) {
            T me = (T)this;
            Int32 oldHeaderLength = me.HeaderLength;
			Byte[] newLenBytes = Asn1Utils.GetLengthBytes(me.PayloadLength + difference);
            me.PayloadLength += difference;
			// 1 means tag byte.
			Source.RawData.RemoveRangeSilent(me.Offset + 1, oldHeaderLength - 1);
			Source.RawData.InsertRangeSilent(me.Offset + 1, newLenBytes);
			Int32 lenDiff = newLenBytes.Length - (oldHeaderLength - 1);
            // 
			if (lenDiff != 0 && Parent != null) {
				Parent.updateOffsetByCaller(me, lenDiff);
                Parent.notifyLengthChanged(lenDiff);
			}
		}

		protected void NotifyChangeLength(Int32 difference) {
			if (difference == 0 || Parent == null) { return; }
			Parent.updateOffsetByIndex(MyIndex, difference);
		}
		protected void OnPropertyChanged(String propertyName) {
			PropertyChangedEventHandler handler = PropertyChanged;
		    handler?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}
		public event PropertyChangedEventHandler PropertyChanged;
	}
}
