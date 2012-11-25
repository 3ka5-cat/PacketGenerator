#include "mainwindow.h"

MainWindow::MainWindow(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);	
	ui.sendBtn->setDisabled(true);	
	ui.loadPacketFileBtn->setDisabled(true);	
	ui.selectPacketBtn->setDisabled(true);
	ui.savePacketBtn->setDisabled(true);
	ui.packetsView->header()->hide();		
	QObject::connect(ui.loadPacketFileBtn, SIGNAL(clicked()), 
		this, SLOT(loadPacketFile()));	
	QObject::connect(ui.deviceBox, SIGNAL(currentIndexChanged(int)), 
		this, SLOT(selectDevice(int)));
	QObject::connect(ui.sendBtn, SIGNAL(clicked()), 
		this, SLOT(sendPacket()));	
	QObject::connect(ui.selectPacketBtn, SIGNAL(clicked()), 
		this, SLOT(selectPacket()));	
	QObject::connect(ui.savePacketBtn, SIGNAL(clicked()), 
		this, SLOT(savePacket()));
	QObject::connect(ui.sendAll, SIGNAL(stateChanged(int)), 
		this, SLOT(oneAllTrigger(int)));
	ui.deviceDescription->setText("Device is not selected");
	//TODO: change formats to model for fields
	formats = new Formats();
	QObject::connect(formats, SIGNAL(valueChanged()), 
		this, SLOT(setFields()));	
	generator = new PktGen();
	selectedDev = NULL;	
	packetsModel = NULL;
	devsModel = NULL;
	getDevices();
}

MainWindow::~MainWindow()
{
	delete generator;
	delete packetsModel;
	delete selectedDev;
	delete devsModel;
	delete formats;
}
void MainWindow::oneAllTrigger(int state)
{
	if (state == Qt::Unchecked && packetsModel)
		ui.selectPacketBtn->setDisabled(false);
	else if (state == Qt::Checked && packetsModel)
		ui.selectPacketBtn->setDisabled(true);		
}

//TODO: remove this to the library
bool MainWindow::validateBuild(Tokens format, Token name)
{
	if (selectedDev->buildPackets(format,true))
		return true;
	else {		
		QMessageBox::critical(0, "Error", QString("Packet \"").append(name.data()).
			append("\": ").append(getGlobalError().data()));
		return false;
	}
}
//TODO: remove this to the library
void MainWindow::savePacket(void)
{
	Tokens formats;	
	formats.push_back(getEth());
	if (validateBuild(formats)) {
		if (!FileWorker::savePacket("pp", formats, "test.xml"))
			QMessageBox::critical(0, "Error", 
			QString("Can't save packet to file\n").append(getGlobalError().data()));
	}

}
//TODO: remove this to the library
void MainWindow::loadPacketFile(void)
{
	QString filename = QFileDialog::getOpenFileName( 
		this, 
		tr("Gimme a file with packets, supa h4x0r"), 
		QDir::currentPath(), 
		tr("XML files (*.xml);;All files (*.*)"));
	if(!filename.isNull())
	{
		std::vector<std::pair<Token,Tokens>> packetsSTL;
		QHash<QString, QStringList> packets;
		if (FileWorker::loadPacket(packetsSTL, filename.toStdString())) {
			for (unsigned int i = 0; i < packetsSTL.size(); ++i) {
				if (validateBuild(packetsSTL[i].second, packetsSTL[i].first)) {
					QStringList tokens;
					for (unsigned int j = 0; j < packetsSTL[i].second.size(); ++j)
						tokens << QString::fromUtf8(packetsSTL[i].second[j].data(), 
							packetsSTL[i].second[j].size());
					packets.insert(QString::fromUtf8(packetsSTL[i].first.data(), 
						packetsSTL[i].first.size()), tokens);
				}
			}
			packetsModel = new TreeModel(packets);		
			ui.packetsView->setModel(packetsModel);
			QItemSelectionModel *selectionModel= ui.packetsView->selectionModel();			
			if (ui.sendAll->checkState() == Qt::Unchecked)
				ui.selectPacketBtn->setDisabled(false);
		}
		else
			QMessageBox::critical(0, "Error", 
				QString("Can't load packets from file\n").append(getGlobalError().data()));
	}
}
void MainWindow::selectPacket(void)
{	
	const QModelIndex index = ui.packetsView->selectionModel()->currentIndex();	
	if (selectedDev && index.isValid()) {		
		//find out the root	
		QModelIndex seekRoot = index;
		while(seekRoot.parent() != QModelIndex())
			seekRoot = seekRoot.parent();
		//QString selectedPacket = seekRoot.data(Qt::UserRole).toString();
		//TODO: get whole itemData from selected root parent		
		QModelIndex child;
		Tokens fmts;
		for (unsigned int i = 0; child = seekRoot.child(i,0), child.isValid(); ++i) {	
			//QString selectedPacket = child.data().toString();			
			std::string format = child.data().toString().toUtf8().constData();			
			//std::string current_locale_text = selectedPacket.toLocal8Bit().constData();
			fmts.push_back(format);			
		}
		formats->setValue(fmts);
	}
}


//TODO: dirty conversations..
void MainWindow::setFields(void)
{	
	Tokens frmts = formats->getValue();
	for (unsigned int i = 0; i < frmts.size(); ++i) {
		if (Utilities::startsWith(frmts[i], ETH2PROTO)) {
			TokenAndRadix src,dst,type;
			if (!Utilities::parseEthFormat(frmts[i], src, dst, type)) {
				QMessageBox::critical(0, "Error", "Can't parse ETH2 format");							
			}	
			else {				
				QString str = QString::fromUtf8(dst.token.data(), dst.token.size()).append(",");
				str.append(QString::number(dst.radix));
				ui.ethDst->setText(str);
				str = QString::fromUtf8(src.token.data(), src.token.size()).append(",");
				str.append(QString::number(src.radix));
				ui.ethSrc->setText(str);
				str = QString::fromUtf8(type.token.data(), type.token.size()).append(",");
				str.append(QString::number(type.radix));
				ui.ethType->setText(str);
			}
		}		
		else if (Utilities::startsWith(frmts[i], IPV4PROTO)) {			
			TokenAndRadix version, ihl, tos, pktLen, id, 
				flags, offset, ttl, protocol, hdrChecksum, 
				src, dst;
			if (!Utilities::parseIPv4Format(frmts[i], version, 
				ihl, tos, pktLen, id, flags, offset, ttl, 
				protocol, hdrChecksum, src, dst)) {
					QMessageBox::critical(0, "Error", "Can't parse IPv4 format");
			}
			else {				
				QString str = QString::fromUtf8(version.token.data(), version.token.size()).append(",");
				str.append(QString::number(version.radix));
				ui.ip4ver->setText(str);
				str = QString::fromUtf8(ihl.token.data(), ihl.token.size()).append(",");
				str.append(QString::number(ihl.radix));
				ui.ip4ihl->setText(str);
				str = QString::fromUtf8(tos.token.data(), tos.token.size()).append(",");
				str.append(QString::number(tos.radix));
				ui.ip4tos->setText(str);
				str = QString::fromUtf8(pktLen.token.data(), pktLen.token.size()).append(",");
				str.append(QString::number(pktLen.radix));
				ui.ip4len->setText(str);
				str = QString::fromUtf8(id.token.data(), id.token.size()).append(",");
				str.append(QString::number(id.radix));
				ui.ip4id->setText(str);

				str = QString::fromUtf8(flags.token.data(), flags.token.size());
				unsigned int fl = str.toUInt(0, flags.radix) << 5;
				fl & IPv4::RESERVEDFLAG ? 
					ui.ip4res->setCheckState(Qt::Checked) : ui.ip4res->setCheckState(Qt::Unchecked);
				fl & IPv4::DFFLAG ? 
					ui.ip4df->setCheckState(Qt::Checked) : ui.ip4df->setCheckState(Qt::Unchecked);
				fl & IPv4::MFFLAG ? 
					ui.ip4mf->setCheckState(Qt::Checked) : ui.ip4mf->setCheckState(Qt::Unchecked);

				str = QString::fromUtf8(offset.token.data(), offset.token.size()).append(",");
				str.append(QString::number(offset.radix));
				ui.ip4offset->setText(str);

				str = QString::fromUtf8(ttl.token.data(), ttl.token.size());
				ui.ip4ttl->setValue(str.toUInt(0, ttl.radix));

				str = QString::fromUtf8(protocol.token.data(), protocol.token.size()).append(",");
				str.append(QString::number(protocol.radix));
				ui.ip4proto->setText(str);
				str = QString::fromUtf8(hdrChecksum.token.data(), hdrChecksum.token.size()).append(",");
				str.append(QString::number(hdrChecksum.radix));
				ui.ip4checksum->setText(str);
				str = QString::fromUtf8(src.token.data(), src.token.size()).append(",");
				str.append(QString::number(src.radix));
				ui.ip4src->setText(str);
				str = QString::fromUtf8(dst.token.data(), dst.token.size()).append(",");
				str.append(QString::number(dst.radix));
				ui.ip4dest->setText(str);
			}
		}
		
		else if (Utilities::startsWith(frmts[i], UDPPROTO)) {
			TokenAndRadix src, dst, checksum, pktLen;
			if (!Utilities::parseUDPFormat(frmts[i], src, 
				dst, checksum, pktLen)) {
				QMessageBox::critical(0, "Error", "Can't parse UDP format");	
			}	
			else {
				QString str = QString::fromUtf8(src.token.data(), src.token.size()).append(",");
				str.append(QString::number(src.radix));
				ui.udpSrc->setText(str);
				str = QString::fromUtf8(dst.token.data(), dst.token.size()).append(",");
				str.append(QString::number(dst.radix));
				ui.udpDst->setText(str);
				str = QString::fromUtf8(checksum.token.data(), checksum.token.size()).append(",");
				str.append(QString::number(checksum.radix));
				ui.udpChecksum->setText(str);
				str = QString::fromUtf8(pktLen.token.data(), pktLen.token.size()).append(",");
				str.append(QString::number(pktLen.radix));
				ui.udpLen->setText(str);
			}
		}			
		/*
		else if (Utilities::startsWith(formats[i], TCPPROTO)) {	
			tcp = createTCP(formats[i]);				
		}
		else if (Utilities::startsWith(formats[i], ICMPPROTO)) {			
				icmp = createICMP(formats[i]);				
		}
		*/
	}	
}


Token MainWindow::getEth(void)
{
	Token result = "";
	if (!ui.ethSrc->text().isEmpty() && !ui.ethDst->text().isEmpty()
		&& !ui.ethType->text().isEmpty()) {
			Token src = ui.ethSrc->text().toUtf8().constData();
			Token dst = ui.ethDst->text().toUtf8().constData();
			Token type = ui.ethType->text().toUtf8().constData();
			Utilities::createEthFormat(src, dst, type, result);
	}
	return result;	
}

Token MainWindow::getIp4(void)
{
	Token result = "";
	if (!ui.ip4ver->text().isEmpty() && !ui.ip4checksum->text().isEmpty()
		&& !ui.ip4dest->text().isEmpty() && !ui.ip4id->text().isEmpty()
		&& !ui.ip4ihl->text().isEmpty() && !ui.ip4len->text().isEmpty()
		&& !ui.ip4offset->text().isEmpty() && !ui.ip4proto->text().isEmpty()
		&& !ui.ip4src->text().isEmpty() && !ui.ip4tos->text().isEmpty()) {
			Token src = ui.ip4src->text().toUtf8().constData();
			Token dst = ui.ip4dest->text().toUtf8().constData();
			Token ver = ui.ip4ver->text().toUtf8().constData();
			Token checksum = ui.ip4checksum->text().toUtf8().constData();
			Token id = ui.ip4id->text().toUtf8().constData();
			Token ihl = ui.ip4ihl->text().toUtf8().constData();
			//TODO flags and ttl
			Token flags = "";
			Token ttl = "";

			Token len = ui.ip4len->text().toUtf8().constData();
			Token offset = ui.ip4offset->text().toUtf8().constData();
			Token proto = ui.ip4proto->text().toUtf8().constData();
			Token tos = ui.ip4tos->text().toUtf8().constData();
			return Utilities::createIPv4Format(ver, ihl, tos, len, id, 
				flags, offset, ttl, proto, checksum, src, dst);
	}
	return result;	
}

void MainWindow::getFormats(void)
{
	Tokens fmts;	
	fmts.push_back(getEth());
	//fmts.push_back(getIp4());
	//fmts.push_back(getUdp());
	formats->setValue(fmts);
}

void MainWindow::sendPacket(void)
{
	if (selectedDev) {
		getFormats();
		//Note that the function may not run immediately;
		//the function will only be run when a thread is available.
		if (selectedDev->buildPackets(formats->getValue())) {
			QFuture<void> sender = QtConcurrent::run(this, &MainWindow::send);
			//sender.waitForFinished();	
		}
		else
			QMessageBox::critical(0, "Error", 
			QString("Can't send packet\n").append(getGlobalError().data()));	
	}
}

void MainWindow::send(void)
{	
	//while (true)
	selectedDev->sendPacket(formats->getValue());	
}

void MainWindow::getDevices(void)
{
	QStringList allDevs;
	Devices devices = generator->devices();			
	for (size_t i = 0; i < devices.size(); ++i) {
		allDevs << devices[i]->name().c_str();		
	}
	devsModel = new QStringListModel(allDevs);
	ui.deviceBox->setModel(devsModel);
}

void MainWindow::selectDevice(int selected)
{	
	selectedDev = generator->device(selected);
	if (selectedDev) {
		ui.savePacketBtn->setDisabled(false);
		ui.sendBtn->setDisabled(false);
		ui.loadPacketFileBtn->setDisabled(false);	
		ui.deviceDescription->clear();
		std::string descrChunk;
		InterfaceAddresses addresses = selectedDev->addresses();
		for (int i = 0; i < addresses.size(); ++i) {
			descrChunk.append("Family " + addresses[i].family + " :: " 
				+ addresses[i].address + "\tMask :: " + addresses[i].netmask + "\n");			
		}
		ui.deviceDescription->append("Loopback");
		selectedDev->loopback() ? ui.deviceDescription->append("Yes") : 
			ui.deviceDescription->append("No");

		ui.deviceDescription->append(QString::fromUtf8(descrChunk.data(), descrChunk.size()));
		descrChunk = selectedDev->description();
		ui.deviceDescription->append(QString::fromUtf8(descrChunk.data(), descrChunk.size()));
	}
}