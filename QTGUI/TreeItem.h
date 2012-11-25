#ifndef TREEITEM_H
#define TREEITEM_H

#include <QList>
#include <QVariant>

class TreeItem
{
public:
	TreeItem(const QList<QVariant> &data, TreeItem *parent = 0);
	TreeItem(const QString &name, const QList<QVariant> &data, 
		TreeItem *parent = 0);
	~TreeItem();

	void appendChild(TreeItem *child);
	QList<QVariant> getItemData() const;

	TreeItem *child(int row);
	int childCount() const;
	int columnCount() const;
	QVariant data(int column) const;
	int row() const;
	TreeItem *parent();

private:
	QList<TreeItem*> childItems;
	QString itemName;
	QList<QVariant> itemData;
	TreeItem *parentItem;
};

#endif