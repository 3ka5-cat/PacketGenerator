#ifndef FORMATS_H
#define FORMATS_H

#include <QObject>
#include "Utilities.h"

class Formats : public QObject
{
	Q_OBJECT

public:
	Formats() {}
	Tokens getValue() const { return formats; }

signals:
	void valueChanged();
public slots:
	void setValue(Tokens& value) { 
		formats = value; 
		emit valueChanged();
	}

private:
	Tokens formats;
};


#endif