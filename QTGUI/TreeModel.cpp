#include <QtGui>

#include "treeitem.h"
#include "treemodel.h"

TreeModel::TreeModel(const QHash<QString, QStringList> &data, QObject *parent)
	: QAbstractItemModel(parent)
{
	QList<QVariant> rootData;
	rootData << "Packets";
	rootItem = new TreeItem(rootData);
	setupModelData(data, rootItem);
}

TreeModel::~TreeModel()
{
	delete rootItem;
}

int TreeModel::columnCount(const QModelIndex &parent) const
{
	if (parent.isValid())
		return static_cast<TreeItem*>(parent.internalPointer())->columnCount();
	else
		return rootItem->columnCount();
}

QVariant TreeModel::data(const QModelIndex &index, int role) const
{
	if (!index.isValid())
		return QVariant();

	if (role != Qt::DisplayRole)
		return QVariant();

	TreeItem *item = static_cast<TreeItem*>(index.internalPointer());

	return item->data(index.column());
}

Qt::ItemFlags TreeModel::flags(const QModelIndex &index) const
{
	if (!index.isValid())
		return 0;

	return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}
/*
QVariant TreeModel::headerData(int section, Qt::Orientation orientation,
	int role) const
{
	if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
		return rootItem->data(section);

	return QVariant();
}
*/

QModelIndex TreeModel::index(int row, int column, const QModelIndex &parent)
	const
{
	if (!hasIndex(row, column, parent))
		return QModelIndex();

	TreeItem *parentItem;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<TreeItem*>(parent.internalPointer());

	TreeItem *childItem = parentItem->child(row);
	if (childItem)
		return createIndex(row, column, childItem);
	else
		return QModelIndex();
}

QModelIndex TreeModel::parent(const QModelIndex &index) const
{
	if (!index.isValid())
		return QModelIndex();

	TreeItem *childItem = static_cast<TreeItem*>(index.internalPointer());
	TreeItem *parentItem = childItem->parent();

	if (parentItem == rootItem)
		return QModelIndex();

	return createIndex(parentItem->row(), 0, parentItem);
}

int TreeModel::rowCount(const QModelIndex &parent) const
{
	TreeItem *parentItem;
	if (parent.column() > 0)
		return 0;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<TreeItem*>(parent.internalPointer());

	return parentItem->childCount();
}

void TreeModel::setupModelData(const QHash<QString, QStringList> &lines, TreeItem *parent)
{
	QList<TreeItem*> parents;
	parents << parent;	
	QHash<QString, QStringList>::const_iterator i = lines.constBegin();
	while (i != lines.constEnd()) {
		//TODO: save all data to the top 'packet' node and add fancy output
		//of packet header into children nodes
		// Append a new item to the current parent's list of children.
		//TreeItem* node = new TreeItem(i.key(), QList<QVariant>(), parents.last());	
		QList<QVariant> columnData;
		columnData << i.value();
		TreeItem* node = new TreeItem(i.key(), columnData, parents.last());	
		
		for (int column = 0; column < i.value().count(); ++column) {			
			QStringList strs = i.value()[column].split(":");
			if (strs.size() == 2) {
				columnData.clear();	
				columnData << i.value()[column];
				TreeItem* hdrNode = new TreeItem(strs[0], columnData, node);
				node->appendChild(hdrNode);
				QStringList data = strs[1].split(";");
				for (int i = 0; i < data.size() - 1; ++i) {
					columnData.clear();	
					columnData << data[i];
					TreeItem* dataNode = new TreeItem(columnData, hdrNode);
					hdrNode->appendChild(dataNode);
				}
			}
		}
		
		parents.last()->appendChild(node);
		++i;
	}
	
	
	/*
	QList<int> indentations;
	indentations << 0;
	int number = 0;	
	while (number < lines.count()) {
		
		int position = 0;
		while (position < lines[number].length()) {
			if (lines[number].mid(position, 1) != " ")
				break;
			position++;
		}		
		QString lineData = lines[number].mid(position).trimmed();
		
		if (!lineData.isEmpty()) {
			// Read the column data from the rest of the line.
			QStringList columnStrings = lineData.split("\t", QString::SkipEmptyParts);
			QList<QVariant> columnData;
			for (int column = 0; column < columnStrings.count(); ++column)
				columnData << columnStrings[column];

			if (position > indentations.last()) {
				// The last child of the current parent is now the new parent
				// unless the current parent has no children.

				if (parents.last()->childCount() > 0) {
					parents << parents.last()->child(parents.last()->childCount()-1);
					indentations << position;
				}
			} else {
				while (position < indentations.last() && parents.count() > 0) {
					parents.pop_back();
					indentations.pop_back();
				}
			}

			// Append a new item to the current parent's list of children.
			parents.last()->appendChild(new TreeItem(columnData, parents.last()));
		}

		number++;
	}
	*/
}