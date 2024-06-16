#include "tree.h"

/* Caller allocated RB_TREE */
NTSTATUS
RtlRbTreeCreate(_In_ RB_COMPARE Compare,
                _In_ UINT32     ObjectSize,
                _Out_ PRB_TREE  Tree)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!ARGUMENT_PRESENT(Compare))
        return STATUS_INVALID_PARAMETER;

    status = ExInitializeLookasideListEx(&Tree->pool,
                                         NULL,
                                         NULL,
                                         NonPagedPoolNx,
                                         0,
                                         ObjectSize + sizeof(RB_TREE_NODE),
                                         POOL_TAG_RB_TREE,
                                         0);

    if (!NT_SUCCESS(status))
        return status;

    Tree->compare = Compare;
    KeInitializeGuardedMutex(&Tree->lock);

    return STATUS_SUCCESS;
}

/* This function is used to maintain the balance of a red-black tree by
 * performing a left rotation around a given node. A left rotation moves the
 * given node down to the left and its right child up to take its place.
 *
 * The structure of the tree before and after the rotation is as follows:
 *
 *     Before Rotation:           After Rotation:
 *        (Node)                    (Right_Child)
 *        /   \                      /          \
 *    (A)     (Right_Child)  ->   (Node)        (C)
 *                /   \            /  \
 *               (B)  (C)        (A)  (B)
 */
STATIC
VOID
RtlpRbTreeRotateLeft(_In_ PRB_TREE Tree, _In_ PRB_TREE_NODE Node)
{
    PRB_TREE_NODE right_child = Node->right;
    Node->right               = right_child->left;

    if (right_child->left)
        right_child->left->parent = Node;

    right_child->parent = Node->parent;

    if (!Node->parent)
        Tree->root = right_child;
    else if (Node == Node->parent->left)
        Node->parent->left = right_child;
    else
        Node->parent->right = right_child;

    right_child->left = Node;
    Node->parent      = right_child;
}

/*
 * This function is used to maintain the balance of a red-black tree by
 * performing a right rotation around a given node. A right rotation moves the
 * given node down to the right and its left child up to take its place.
 *
 * The structure of the tree before and after the rotation is as follows:
 *
 *     Before Rotation:         After Rotation:
 *         (Node)                  (Left_Child)
 *         /   \                    /         \
 *  (Left_Child)  (C)  ->        (A)       (Node)
 *      /   \                               /   \
 *   (A)    (B)                           (B)    (C)
 *
 */
STATIC
VOID
RtlpRbTreeRotateRight(_In_ PRB_TREE Tree, _In_ PRB_TREE_NODE Node)
{
    PRB_TREE_NODE left_child = Node->left;
    Node->left               = left_child->right;

    if (left_child->right)
        left_child->right->parent = Node;

    left_child->parent = Node->parent;

    if (!Node->parent)
        Tree->root = left_child;
    else if (Node == Node->parent->right)
        Node->parent->right = left_child;
    else
        Node->parent->left = left_child;

    left_child->right = Node;
    Node->parent      = left_child;
}

/*
 * This function ensures the red-black tree properties are maintained after a
 * new node is inserted. It adjusts the colors and performs rotations as
 * necessary.
 *
 * Example scenario:
 *
 * Inserted Node causing a fixup:
 *         (Grandparent)                (Parent)
 *        /            \                /      \
 *   (Parent)        (Uncle)     -> (Node)   (Grandparent)
 *      /                                    /       \
 *   (Node)                              (Left)     (Uncle)
 */
STATIC
VOID
RtlpRbTreeFixupInsert(_In_ PRB_TREE Tree, _In_ PRB_TREE_NODE Node)
{
    PRB_TREE_NODE uncle       = NULL;
    PRB_TREE_NODE parent      = NULL;
    PRB_TREE_NODE grandparent = NULL;

    while ((parent = Node->parent) && parent->colour == red) {
        grandparent = parent->parent;

        if (parent == grandparent->left) {
            uncle = grandparent->right;

            if (uncle && uncle->colour == red) {
                parent->colour      = black;
                uncle->colour       = black;
                grandparent->colour = red;
                Node                = grandparent;
            }
            else {
                if (Node == parent->right) {
                    RtlpRbTreeRotateLeft(Tree, parent);
                    Node   = parent;
                    parent = Node->parent;
                }

                parent->colour      = black;
                grandparent->colour = red;
                RtlpRbTreeRotateRight(Tree, grandparent);
            }
        }
        else {
            uncle = grandparent->left;

            if (uncle && uncle->colour == red) {
                parent->colour      = black;
                uncle->colour       = black;
                grandparent->colour = red;
                Node                = grandparent;
            }
            else {
                if (Node == parent->left) {
                    RtlpRbTreeRotateRight(Tree, parent);
                    Node   = parent;
                    parent = Node->parent;
                }

                parent->colour      = black;
                grandparent->colour = red;
                RtlpRbTreeRotateLeft(Tree, grandparent);
            }
        }
    }

    Tree->root->colour = black;
}

/*
 * ASSUMES LOCK IS HELD!
 *
 * This function inserts a new node into the red-black tree, and then calls a
 * fix-up routine to ensure the tree properties are maintained.
 *
 * Example insertion process:
 *
 * Before insertion:
 *           (Root)
 *          /     \
 *     (Left)     (Right)
 *
 * After insertion:
 *           (Root)
 *          /     \
 *     (Left)    (Right)
 *              /
 *           (Node)
 *
 * After fix-up:
 *          (Root)
 *         /     \
 *    (Left)   (Node)
 *                 \
 *                (Right)
 */
PVOID
RtlRbTreeInsertNode(_In_ PRB_TREE Tree, _In_ PVOID Key)
{
    UINT32        result  = 0;
    PRB_TREE_NODE node    = NULL;
    PRB_TREE_NODE parent  = NULL;
    PRB_TREE_NODE current = NULL;

    node = ExAllocateFromLookasideListEx(&Tree->pool);

    if (!node)
        return NULL;

    node->parent = NULL;
    node->left   = NULL;
    node->right  = NULL;
    node->colour = red;

    current = Tree->root;

    while (current) {
        parent = current;
        result = Tree->compare(Key, current->object);

        if (result == RB_TREE_LESS_THAN) {
            current = current->left;
        }
        else if (result == RB_TREE_GREATER_THAN) {
            current = current->right;
        }
        else {
            ExFreeToLookasideListEx(&Tree->pool, node);
            return current->object;
        }
    }

    node->parent = parent;

    if (!parent)
        Tree->root = node;
    else if (result == RB_TREE_LESS_THAN)
        parent->left = node;
    else
        parent->right = node;

    RtlpRbTreeFixupInsert(Tree, node);

    return node->object;
}

/*
 * ASSUMES LOCK IS HELD!
 *
 * This function traverses the left children of the given node to find and
 * return the node with the minimum key in the subtree.
 *
 * Example traversal to find minimum:
 *
 *        (Root)
 *        /    \
 *  (Left)     (Right)
 *  /
 * (Node)
 *
 * After finding minimum:
 *        (Root)
 *        /    \
 *     (Node)  (Right)
 *
 * Returns the left-most node.
 */
STATIC
PRB_TREE_NODE
RtlpRbTreeMinimum(_In_ PRB_TREE_NODE Node)
{
    while (Node->left != NULL)
        Node = Node->left;

    return Node;
}

/*
 * ASSUMES LOCK IS HELD!
 *
 * This function is called after a node is deleted from the Red-Black Tree.
 * It ensures that the tree remains balanced and the Red-Black properties are
 * maintained. It performs the necessary rotations and recoloring.
 *
 * Example fixup scenarios:
 *
 *       Before Fixup:              After Fixup:
 *       (Parent)                   (Parent)
 *       /    \                     /    \
 *  (Node)  (Sibling)          (Node)  (Sibling)
 *              /  \                      /  \
 *         (Left) (Right)            (Left) (Right)
 *
 *  The fixup process ensures that the tree remains balanced.
 */
STATIC
VOID
RtlpRbTreeFixupDelete(_In_ PRB_TREE Tree, _In_ PRB_TREE_NODE Node)
{
    PRB_TREE_NODE sibling = NULL;

    while (Node != Tree->root && Node->colour == black) {
        if (Node == Node->parent->left) {
            sibling = Node->parent->right;

            if (sibling && sibling->colour == red) {
                sibling->colour      = black;
                Node->parent->colour = red;
                RtlpRbTreeRotateLeft(Tree, Node->parent);
                sibling = Node->parent->right;
            }

            if (sibling && (!sibling->left || sibling->left->colour == black) &&
                (!sibling->right || sibling->right->colour == black)) {
                sibling->colour = red;
                Node            = Node->parent;
            }
            else {
                if (sibling &&
                    (!sibling->right || sibling->right->colour == black)) {
                    if (sibling->left) {
                        sibling->left->colour = black;
                    }
                    sibling->colour = red;
                    RtlpRbTreeRotateRight(Tree, sibling);
                    sibling = Node->parent->right;
                }

                if (sibling) {
                    sibling->colour      = Node->parent->colour;
                    Node->parent->colour = black;
                    if (sibling->right) {
                        sibling->right->colour = black;
                    }
                    RtlpRbTreeRotateLeft(Tree, Node->parent);
                }
                Node = Tree->root;
            }
        }
        else {
            sibling = Node->parent->left;

            if (sibling && sibling->colour == red) {
                sibling->colour      = black;
                Node->parent->colour = red;
                RtlpRbTreeRotateRight(Tree, Node->parent);
                sibling = Node->parent->left;
            }

            if (sibling &&
                (!sibling->right || sibling->right->colour == black) &&
                (!sibling->left || sibling->left->colour == black)) {
                sibling->colour = red;
                Node            = Node->parent;
            }
            else {
                if (sibling &&
                    (!sibling->left || sibling->left->colour == black)) {
                    if (sibling->right) {
                        sibling->right->colour = black;
                    }
                    sibling->colour = red;
                    RtlpRbTreeRotateLeft(Tree, sibling);
                    sibling = Node->parent->left;
                }

                if (sibling) {
                    sibling->colour      = Node->parent->colour;
                    Node->parent->colour = black;
                    if (sibling->left) {
                        sibling->left->colour = black;
                    }
                    RtlpRbTreeRotateRight(Tree, Node->parent);
                }
                Node = Tree->root;
            }
        }
    }

    Node->colour = black;
}

/*
 * ASSUMES LOCK IS HELD!
 *
 * This function replaces the subtree rooted at the node `toBeReplacedNode` with
 * the subtree rooted at the node `replacementNode`. It adjusts the parent
 * pointers accordingly.
 *
 * Example scenario:
 *
 *       Before Transplant:           After Transplant:
 *       (ParentNode)                 (ParentNode)
 *       /        \                   /        \
 * (toBeReplaced)  Sibling       (Replacement)  Sibling
 *     /  \                            /  \
 *  Left  Right                    Left  Right
 *
 *  The transplant process ensures that the subtree rooted at `replacementNode`
 *  takes the place of the subtree rooted at `toBeReplacedNode`.
 */
STATIC
VOID
RtlpRbTreeTransplant(_In_ PRB_TREE      Tree,
                     _In_ PRB_TREE_NODE Target,
                     _In_ PRB_TREE_NODE Replacement)
{
    if (!Target->parent)
        Tree->root = Replacement;
    else if (Target == Target->parent->left)
        Target->parent->left = Replacement;
    else
        Target->parent->right = Replacement;

    if (Replacement)
        Replacement->parent = Target->parent;
}

STATIC
PVOID
RtlpRbTreeFindNode(_In_ PRB_TREE Tree, _In_ PVOID Key)
{
    INT32         result  = 0;
    PRB_TREE_NODE current = Tree->root;

    while (current) {
        result = Tree->compare(Key, current->object);

        if (result == RB_TREE_EQUAL)
            return current;
        else if (result == RB_TREE_LESS_THAN)
            current = current->left;
        else
            current = current->right;
    }

    return NULL;
}

/*
 * ASSUMES LOCK IS HELD!
 *
 * This function removes a node with the specified key from the Red-Black Tree
 * and ensures the tree remains balanced by performing necessary rotations and
 * recoloring.
 *
 * Example scenario:
 *
 *         Before Deletion:                       After Deletion:
 *             (ParentNode)                         (ParentNode)
 *             /        \                           /        \
 *       (TargetNode)   Sibling               (Replacement)  Sibling
 *          /   \                               /       \
 *    LeftChild RightChild                LeftChild  RightChild
 *
 *  The deletion process involves finding the target node, replacing it with a
 * suitable successor or child, and ensuring the Red-Black Tree properties are
 * maintained.
 */
VOID
RtlRbTreeDeleteNode(_In_ PRB_TREE Tree, _In_ PVOID Key)
{
    PRB_TREE_NODE target    = NULL;
    PRB_TREE_NODE child     = NULL;
    PRB_TREE_NODE successor = NULL;
    COLOUR        colour    = {0};

    /* We want the node not the object */
    target = RtlpRbTreeFindNode(Tree, Key);

    if (!target)
        return;

    colour = target->colour;

    if (!target->left) {
        child = target->right;
        RtlpRbTreeTransplant(Tree, target, target->right);
    }
    else if (!target->right) {
        child = target->left;
        RtlpRbTreeTransplant(Tree, target, target->left);
    }
    else {
        successor = RtlpRbTreeMinimum(target->right);
        colour    = successor->colour;
        child     = successor->right;

        if (successor->parent == target) {
            if (child)
                child->parent = successor;
        }
        else {
            RtlpRbTreeTransplant(Tree, successor, successor->right);
            successor->right         = target->right;
            successor->right->parent = successor;
        }

        RtlpRbTreeTransplant(Tree, target, successor);
        successor->left         = target->left;
        successor->left->parent = successor;
        successor->colour       = target->colour;
    }

    if (colour == black && child)
        RtlpRbTreeFixupDelete(Tree, child);

    ExFreeToLookasideListEx(&Tree->pool, target);
}

/* Public API that is used to find the node object for an associated key. Should
 * be used externally when wanting to find an object with a key value. If you
 * are wanting to get the node itself, use the RtlpRbTreeFindNode routine. */
PVOID
RtlRbTreeFindNodeObject(_In_ PRB_TREE Tree, _In_ PVOID Key)
{
    INT32         result  = 0;
    PRB_TREE_NODE current = Tree->root;

    while (current) {
        result = Tree->compare(Key, current->object);

        if (result == RB_TREE_EQUAL)
            return current->object;
        else if (result == RB_TREE_LESS_THAN)
            current = current->left;
        else
            current = current->right;
    }

    return NULL;
}

STATIC
VOID
RtlpRbTreeEnumerate(_In_ PRB_TREE_NODE    Node,
                    _In_ RB_ENUM_CALLBACK Callback,
                    _In_opt_ PVOID        Context)
{
    if (Node == NULL)
        return;

    RtlpRbTreeEnumerate(Node->left, Callback, Context);
    Callback(Node->object, Context);
    RtlpRbTreeEnumerate(Node->right, Callback, Context);
}

VOID
RtlRbTreeEnumerate(_In_ PRB_TREE         Tree,
                   _In_ RB_ENUM_CALLBACK Callback,
                   _In_opt_ PVOID        Context)
{
    if (Tree->root == NULL)
        return;

    RtlRbTreeAcquireLock(Tree);
    RtlpRbTreeEnumerate(Tree->root, Callback, Context);
    RtlRbTreeReleaselock(Tree);
}

STATIC
VOID
RtlpPrintInOrder(PRB_TREE_NODE Node)
{
    if (Node == NULL)
        return;

    RtlpPrintInOrder(Node->left);

    const char* color = (Node->colour == red) ? "Red" : "Black";
    DbgPrintEx(DPFLTR_DEFAULT_ID,
               DPFLTR_INFO_LEVEL,
               "Node: Key=%p, Color=%s\n",
               *((PHANDLE)Node->object),
               color);

    RtlpPrintInOrder(Node->right);
}

/* assumes lock is held */
VOID
RtlRbTreeInOrderPrint(_In_ PRB_TREE Tree)
{
    DEBUG_ERROR("*************************************************");
    DEBUG_ERROR("<><><><>STARTING IN ORDER PRINT <><><><><><");
    RtlpPrintInOrder(Tree->root);
    DEBUG_ERROR("<><><><>ENDING IN ORDER PRINT <><><><><><");
    DEBUG_ERROR("*************************************************");
}

STATIC
VOID
RtlpRbTreeDeleteSubtree(_In_ PRB_TREE Tree, _In_ PRB_TREE_NODE Node)
{
    if (Node == NULL)
        return;

    RtlpRbTreeDeleteSubtree(Tree, Node->left);
    RtlpRbTreeDeleteSubtree(Tree, Node->right);

    ExFreeToLookasideListEx(&Tree->pool, Node);
}

VOID
RtlRbTreeDeleteTree(_In_ PRB_TREE Tree)
{
    Tree->active = FALSE;

    RtlRbTreeAcquireLock(Tree);
    RtlpRbTreeDeleteSubtree(Tree, Tree->root);
    ExDeleteLookasideListEx(&Tree->pool);
    RtlRbTreeReleaselock(Tree);
}