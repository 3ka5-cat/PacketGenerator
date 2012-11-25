#include "FieldsModel.h"

FieldsModel::FieldsModel(QObject *parent)
	: QAbstractTableModel(parent)
{
}

FieldsModel::FieldsModel(const QList<QPair<QString, QString>> pairs, QObject *parent)
	: QAbstractTableModel(parent)
{
	listOfPairs=pairs;
	/*
	QString selectedPacket = child.data().toString();			
	std::string format = selectedPacket.toUtf8().constData();			
	//std::string current_locale_text = selectedPacket.toLocal8Bit().constData();
	fmts.push_back(format);
	*/
}

QVariant FieldsModel::data(const QModelIndex &index, int role) const
{
	if (!index.isValid())
		return QVariant();

	if (index.row() >= listOfPairs.size() || index.row() < 0)
		return QVariant();

	if (role == Qt::DisplayRole) {
		QPair<QString, QString> pair = listOfPairs.at(index.row());

		if (index.column() == 0)
			return pair.first;
		else if (index.column() == 1)
			return pair.second;
	}
	return QVariant();
}

bool FieldsModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
	if (index.isValid() && role == Qt::EditRole) {
		int row = index.row();

		QPair<QString, QString> p = listOfPairs.value(row);

		if (index.column() == 0)
			p.first = value.toString();
		else if (index.column() == 1)
			p.second = value.toString();
		else
			return false;

		listOfPairs.replace(row, p);
		emit(dataChanged(index, index));

		return true;
	}

	return false;
}

Qt::ItemFlags FieldsModel::flags(const QModelIndex &index) const
{
	if (!index.isValid())
		return Qt::ItemIsEnabled;

	return QAbstractTableModel::flags(index) | Qt::ItemIsEditable;
}

QList<QPair<QString, QString>> FieldsModel::getList()
{
	return listOfPairs;
}