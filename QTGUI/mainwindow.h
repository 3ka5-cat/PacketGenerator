#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtGui/QMainWindow>
#include "ui_mainwindow.h"
#include <QStringListModel>
#include <QInputDialog>
 #include <QRegExpValidator>
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
		int selectPacket(QModelIndex& index = QModelIndex());
		void savePacket(void);
		void loadPacketFile(void);
		void setFields(void);		
		void oneAllTrigger(int state);

private:	
	void _sendPacket(void);
	void getDevices(void);
	void send(void);
	bool validateBuild(Tokens format, Token name = "");
	Token getEth(void);
	bool setEth(Token str);
	Token getIp4(void);
	bool setIp4(Token str);
	Token getUdp(void);
	bool setUdp(Token str);
	Token getTcp(void);
	bool setTcp(Token str);	
	Token getIcmp(void);
	bool setIcmp(Token str);
	bool getFormats(void);

	//TODO: remove to the utils
	void getDottedIp(unsigned long ip, QString& str);

	Ui::MainWindowClass ui;	
	QStringListModel* devsModel;	
	TreeModel* packetsModel;
	Formats* formats;
	
	PktGen* generator;
	Device* selectedDev;
};

#endif // MAINWINDOW_H
