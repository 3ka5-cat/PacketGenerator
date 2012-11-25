#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtGui/QMainWindow>
#include "ui_mainwindow.h"
#include <QStringListModel>
#include <qtconcurrentrun.h>
#include <QMessageBox>
#include <QFileDialog>
#include "PktGen.h"
#include "Device.h"
#include "TreeModel.h"
#include "Formats.h"

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	MainWindow(QWidget *parent = 0, Qt::WFlags flags = 0);
	~MainWindow();

private slots:
		void selectDevice(int selected);
		void sendPacket(void);
		void selectPacket(void);
		void savePacket(void);
		void loadPacketFile(void);
		void setFields(void);
		void getFormats(void);
		void oneAllTrigger(int state);

private:	
	void getDevices(void);
	void send(void);
	bool validateBuild(Tokens format, Token name = "");
	Token getEth(void);
	Token getIp4(void);

	Ui::MainWindowClass ui;	
	QStringListModel* devsModel;	
	TreeModel* packetsModel;
	Formats* formats;
	
	PktGen* generator;
	Device* selectedDev;
};

#endif // MAINWINDOW_H
