#ifndef FIELDSMODEL_H
#define FIELDSMODEL_H

#include <QAbstractTableModel>
#include "Utilities.h"

class FieldsModel : public QAbstractTableModel
{
	Q_OBJECT

public:
	FieldsModel(QObject *parent=0);
	FieldsModel(const QList<QPair<QString, QString>> pairs, QObject *parent=0);

	QVariant data(const QModelIndex &index, int role) const;
	Qt::ItemFlags flags(const QModelIndex &index) const;
	bool setData(const QModelIndex &index, const QVariant &value, int role=Qt::EditRole);	
	QList<QPair<QString, QString>> getList();
private:
	QList<QPair<QString, QString>> listOfPairs;
	Tokens formats;
};


#endif