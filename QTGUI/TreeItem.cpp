#include <QStringList>

#include "treeitem.h"

TreeItem::TreeItem(const QString &name, const QList<QVariant> &data, TreeItem *parent)
{
	parentItem = parent;
	if (name == "")
		itemName = "Unnamed";
	else
		itemName = name;	
	itemData = data;
}

TreeItem::TreeItem(const QList<QVariant> &data, TreeItem *parent)
{
	parentItem = parent;
	itemData = data;
	itemName = "";
}

TreeItem::~TreeItem()
{
	qDeleteAll(childItems);
}

void TreeItem::appendChild(TreeItem *item)
{
	childItems.append(item);
}

TreeItem *TreeItem::child(int row)
{
	return childItems.value(row);
}

int TreeItem::childCount() const
{
	return childItems.count();
}

int TreeItem::columnCount() const
{
	return itemData.count();
}

QList<QVariant> TreeItem::getItemData() const
{
	return itemData;
}

QVariant TreeItem::data(int column) const
{
	if (itemName != "")
		return itemName;
	return itemData.value(column);
}

TreeItem *TreeItem::parent()
{
	return parentItem;
}

int TreeItem::row() const
{
	if (parentItem)
		return parentItem->childItems.indexOf(const_cast<TreeItem*>(this));

	return 0;
}