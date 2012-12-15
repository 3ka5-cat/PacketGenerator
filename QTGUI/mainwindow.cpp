#include "mainwindow.h"

MainWindow::MainWindow(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);	
	ui.sendBtn->setDisabled(true);	
	ui.loadPacketFileBtn->setDisabled(true);	
	ui.selectPacketBtn->setDisabled(true);
	ui.savePacketBtn->setDisabled(true);
	ui.packetsView->header()->setResizeMode(QHeaderView::ResizeToContents);		
	QRegExp ipRegExp("((1{0,1}[0-9]{0,2}|2[0-4]{1,1}[0-9]{1,1}|25[0-5]{1,1})\\.){3,3}(1{0,1}[0-9]{0,2}|2[0-4]{1,1}[0-9]{1,1}|25[0-5]{1,1})");
	QValidator* ipValidator = new QRegExpValidator(ipRegExp, this);
	ui.ip4src->setValidator(ipValidator);
	ui.ip4dest->setValidator(ipValidator);
	//TODO: add correct validator for MAC addresses
	ui.ethDst->setInputMask("HH:HH:HH:HH:HH:HH,99");
	ui.ethSrc->setInputMask("HH:HH:HH:HH:HH:HH,99");
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
	formats.push_back(getIp4());
	formats.push_back(getUdp());
	formats.push_back(getTcp());	
	formats.push_back(getIcmp());	
	if (validateBuild(formats)) {
		QString filename = QFileDialog::getOpenFileName( 
		this, tr("Select file to save the packet..."), 
		QDir::currentPath(), 
		tr("XML files (*.xml);;All files (*.*)"));
		if(!filename.isNull()) {
			bool ok;
			QString name = QInputDialog::getText(this, tr("Save packet"),
												  tr("Packet name:"), QLineEdit::Normal,
												  QDir::home().dirName(), &ok);
			if (ok && !name.isEmpty()) {				
				if (!FileWorker::savePacket(name.toStdString(), formats, filename.toStdString()))
					QMessageBox::critical(0, "Error", 
					QString("Can't save packet to file\n").append(getGlobalError().data()));
			}
		}
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
			ui.packetsView->setCurrentIndex(packetsModel->index(0, 0));
		}
		else
			QMessageBox::critical(0, "Error", 
				QString("Can't load packets from file\n").append(getGlobalError().data()));
	}
}

void MainWindow::setFields(void)
{	
	Tokens frmts = formats->getValue();
	for (unsigned int i = 0; i < frmts.size(); ++i) {
		if (Utilities::startsWith(frmts[i], ETH2PROTO)) {
			if (!setEth(frmts[i]))
				return;
		}		
		else if (Utilities::startsWith(frmts[i], IPV4PROTO)) {			
			if (!setIp4(frmts[i]))
				return;
		}
		
		else if (Utilities::startsWith(frmts[i], UDPPROTO)) {
			if (!setUdp(frmts[i]))
				return;
		}			
		
		else if (Utilities::startsWith(frmts[i], TCPPROTO)) {	
			if (!setTcp(frmts[i]))
				return;
		}		
		else if (Utilities::startsWith(frmts[i], ICMPPROTO)) {			
			if (!setIcmp(frmts[i]))
				return;
		}		
	}	
}


Token MainWindow::getEth(void)
{
	if (!ui.ethSrc->text().isEmpty() && !ui.ethDst->text().isEmpty()
		&& !ui.ethType->text().isEmpty()) {
			Token result = "";
			Token src = ui.ethSrc->text().toUtf8().constData();
			Token dst = ui.ethDst->text().toUtf8().constData();
			Token type = ui.ethType->text().toUtf8().constData();
			if (Utilities::createEthFormat(src, dst, type, result))
				return result;
	}
	return "";	
}

bool MainWindow::setEth(Token str)
{
	TokenAndRadix src,dst,type;
	if (!Utilities::parseEthFormat(str, src, dst, type)) {
		QMessageBox::critical(0, "Error", "Can't parse ETH2 format");	
		return false;
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
		return true;
	}
}

Token MainWindow::getIp4(void)
{	
	if (!ui.ip4ver->text().isEmpty() && !ui.ip4checksum->text().isEmpty()
		&& !ui.ip4dest->text().isEmpty() && !ui.ip4id->text().isEmpty()
		&& !ui.ip4ihl->text().isEmpty() && !ui.ip4len->text().isEmpty()
		&& !ui.ip4offset->text().isEmpty() && !ui.ip4proto->text().isEmpty()
		&& !ui.ip4src->text().isEmpty() && !ui.ip4tos->text().isEmpty()) {
			Token result = "";			
			std::stringstream stream;
			QStringList octets = ui.ip4src->text().split(".");
			if (octets.size() == 4)
				stream << octets[3].toUInt()+octets[2].toUInt()*256+octets[1].toUInt()*256*256+octets[0].toUInt()*256*256*256;							
			else
				return "";
			//Token src = ui.ip4src->text().toUtf8().constData();
			Token src = stream.str().append(",10");			
			stream.str("");
			octets = ui.ip4dest->text().split(".");
			if (octets.size() == 4)
				stream << octets[3].toUInt()+octets[2].toUInt()*256+octets[1].toUInt()*256*256+octets[0].toUInt()*256*256*256;							
			else
				return "";
			//Token dst = ui.ip4dest->text().toUtf8().constData();
			Token dst = stream.str().append(",10");
			Token ver = ui.ip4ver->text().toUtf8().constData();
			Token checksum = ui.ip4checksum->text().toUtf8().constData();
			Token id = ui.ip4id->text().toUtf8().constData();
			Token ihl = ui.ip4ihl->text().toUtf8().constData();
			unsigned int fl = 0;
			if (ui.ip4res->checkState() == Qt::Checked)
				fl |= IPv4::RESERVEDFLAG;
			if (ui.ip4df->checkState() == Qt::Checked)
				fl |= IPv4::DFFLAG;
			if (ui.ip4mf->checkState() == Qt::Checked)
				fl |= IPv4::MFFLAG;			
			stream.str("");
			stream << (fl >> 5);			
			Token flags = stream.str().append(",10");
			stream.str("");
			stream << ui.ip4ttl->value();	
			Token ttl = stream.str().append(",10");

			Token len = ui.ip4len->text().toUtf8().constData();
			Token offset = ui.ip4offset->text().toUtf8().constData();
			Token proto = ui.ip4proto->text().toUtf8().constData();
			Token tos = ui.ip4tos->text().toUtf8().constData();
			if (Utilities::createIPv4Format(ver, ihl, tos, len, id, 
				flags, offset, ttl, proto, checksum, src, dst, result))
				return result;
	}
	return "";	
}

void MainWindow::getDottedIp(unsigned long ip, QString& str)
{
	str = QString::number((ip >> 24) & 0xFF).append(".");	
	str.append(QString::number((ip >> 16) & 0xFF)).append(".");
	str.append(QString::number((ip >> 8) & 0xFF)).append(".");
	str.append(QString::number(ip & 0xFF));
}

bool MainWindow::setIp4(Token str)
{
	TokenAndRadix version, ihl, tos, pktLen, id, 
		flags, offset, ttl, protocol, hdrChecksum, 
		src, dst;
	if (!Utilities::parseIPv4Format(str, version, 
		ihl, tos, pktLen, id, flags, offset, ttl, 
		protocol, hdrChecksum, src, dst)) {
			QMessageBox::critical(0, "Error", "Can't parse IPv4 format");
			return false;
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

		getDottedIp(QString::fromUtf8(src.token.data(), src.token.size()).toUInt(), str);
		ui.ip4src->setText(str);
		getDottedIp(QString::fromUtf8(dst.token.data(), dst.token.size()).toUInt(), str);
		ui.ip4dest->setText(str);

		return true;
	}
}

Token MainWindow::getUdp(void)
{	
	if (!ui.udpSrc->text().isEmpty() && !ui.udpDst->text().isEmpty()
		&& !ui.udpLen->text().isEmpty() && !ui.udpChecksum->text().isEmpty()) {
			Token result = "";
			Token src = ui.udpSrc->text().toUtf8().constData();
			Token dst = ui.udpDst->text().toUtf8().constData();
			Token len = ui.udpLen->text().toUtf8().constData();
			Token cs = ui.udpChecksum->text().toUtf8().constData();
			if (Utilities::createUDPFormat(src, dst, cs, len, result))
				return result;
	}
	return "";
}

bool MainWindow::setUdp(Token str)
{
	TokenAndRadix src, dst, checksum, pktLen;
	if (!Utilities::parseUDPFormat(str, src, 
		dst, checksum, pktLen)) {
			QMessageBox::critical(0, "Error", "Can't parse UDP format");	
			return false;
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
		return true;
	}
}

Token MainWindow::getTcp(void)
{
	if (!ui.tcpSrc->text().isEmpty() && !ui.tcpDst->text().isEmpty()
		&& !ui.tcpSeqNum->text().isEmpty() && !ui.tcpAckNum->text().isEmpty()
		&& !ui.tcpOffset->text().isEmpty() && !ui.tcpWs->text().isEmpty()
		&& !ui.tcpChecksum->text().isEmpty() && !ui.tcpUrgPointer->text().isEmpty()
		) {
			Token result = "";
			Token src = ui.tcpSrc->text().toUtf8().constData();
			Token dst = ui.tcpDst->text().toUtf8().constData();
			Token seq = ui.tcpSeqNum->text().toUtf8().constData();
			Token ack = ui.tcpAckNum->text().toUtf8().constData();

			unsigned int fl = 0;
			unsigned int res = 0;
			if (ui.tcpFin->checkState() == Qt::Checked)
				fl |= TCP::FINFLAG;
			if (ui.tcpSyn->checkState() == Qt::Checked)
				fl |= TCP::SYNFLAG;
			if (ui.tcpRst->checkState() == Qt::Checked)
				fl |= TCP::RSTFLAG;
			if (ui.tcpPsh->checkState() == Qt::Checked)
				fl |= TCP::PSHFLAG;
			if (ui.tcpAck->checkState() == Qt::Checked)
				fl |= TCP::ACKFLAG;
			if (ui.tcpUrg->checkState() == Qt::Checked)
				fl |= TCP::URGFLAG;			
			if (ui.tcpEce->checkState() == Qt::Checked)
				fl |= TCP::ECEFLAG;
			if (ui.tcpCwr->checkState() == Qt::Checked)
				fl |= TCP::CWRFLAG;
			if (ui.tcpNs->checkState() == Qt::Checked)
				res |= TCP::NSFLAG;
			if (ui.tcpRes0->checkState() == Qt::Checked)
				res |= TCP::RES0;
			if (ui.tcpRes1->checkState() == Qt::Checked)
				res |= TCP::RES1;
			if (ui.tcpRes2->checkState() == Qt::Checked)
				res |= TCP::RES2;

			std::stringstream stream;
			stream << fl;			
			Token flags = stream.str().append(",10");		
			stream.str("");
			stream << res;			
			Token reserved = stream.str().append(",10");			

			Token offset = ui.tcpOffset->text().toUtf8().constData();
			Token windowSize = ui.tcpWs->text().toUtf8().constData();
			Token cs = ui.tcpChecksum->text().toUtf8().constData();
			Token urgPointer = ui.tcpUrgPointer->text().toUtf8().constData();
			if (Utilities::createTCPFormat(src, dst, seq, ack, offset, reserved, flags, windowSize, cs, urgPointer, result))
				return result;
	}
	return "";
}

bool MainWindow::setTcp(Token str)
{
	TokenAndRadix src, dst, seq, ack, offset, 
		reserved, flags, windowSize, checksum,
		urgentPointer;
	if (!Utilities::parseTCPFormat(str, src, 
		dst, seq, ack, offset, reserved, flags, 
		windowSize, checksum, urgentPointer)) {
			QMessageBox::critical(0, "Error", "Can't parse TCP format");	
			return false;
	}	
	else {
		QString str = QString::fromUtf8(src.token.data(), src.token.size()).append(",");
		str.append(QString::number(src.radix));
		ui.tcpSrc->setText(str);
		str = QString::fromUtf8(dst.token.data(), dst.token.size()).append(",");
		str.append(QString::number(dst.radix));
		ui.tcpDst->setText(str);
		str = QString::fromUtf8(seq.token.data(), seq.token.size()).append(",");
		str.append(QString::number(seq.radix));
		ui.tcpSeqNum->setText(str);
		str = QString::fromUtf8(ack.token.data(), ack.token.size()).append(",");
		str.append(QString::number(ack.radix));
		ui.tcpAckNum->setText(str);
		str = QString::fromUtf8(flags.token.data(), flags.token.size());
		unsigned int fl = str.toUInt(0, flags.radix);
		fl & TCP::FINFLAG ? 
			ui.tcpFin->setCheckState(Qt::Checked) : ui.tcpFin->setCheckState(Qt::Unchecked);
		fl & TCP::SYNFLAG ? 
			ui.tcpSyn->setCheckState(Qt::Checked) : ui.tcpSyn->setCheckState(Qt::Unchecked);
		fl & TCP::RSTFLAG ? 
			ui.tcpRst->setCheckState(Qt::Checked) : ui.tcpRst->setCheckState(Qt::Unchecked);
		fl & TCP::PSHFLAG ? 
			ui.tcpPsh->setCheckState(Qt::Checked) : ui.tcpPsh->setCheckState(Qt::Unchecked);
		fl & TCP::ACKFLAG ? 
			ui.tcpAck->setCheckState(Qt::Checked) : ui.tcpAck->setCheckState(Qt::Unchecked);
		fl & TCP::URGFLAG ? 
			ui.tcpUrg->setCheckState(Qt::Checked) : ui.tcpUrg->setCheckState(Qt::Unchecked);
		fl & TCP::ECEFLAG ? 
			ui.tcpEce->setCheckState(Qt::Checked) : ui.tcpEce->setCheckState(Qt::Unchecked);
		fl & TCP::CWRFLAG ? 
			ui.tcpCwr->setCheckState(Qt::Checked) : ui.tcpCwr->setCheckState(Qt::Unchecked);
		
		str = QString::fromUtf8(reserved.token.data(), reserved.token.size());
		unsigned int res = str.toUInt(0, reserved.radix);
		res & TCP::RES0 ? 
			ui.tcpRes0->setCheckState(Qt::Checked) : ui.tcpRes0->setCheckState(Qt::Unchecked);
		res & TCP::RES1 ? 
			ui.tcpRes1->setCheckState(Qt::Checked) : ui.tcpRes1->setCheckState(Qt::Unchecked);
		res & TCP::RES2 ? 
			ui.tcpRes2->setCheckState(Qt::Checked) : ui.tcpRes2->setCheckState(Qt::Unchecked);
		res & TCP::NSFLAG ? 
			ui.tcpNs->setCheckState(Qt::Checked) : ui.tcpNs->setCheckState(Qt::Unchecked);

		str = QString::fromUtf8(offset.token.data(), offset.token.size()).append(",");
		str.append(QString::number(offset.radix));
		ui.tcpOffset->setText(str);
		str = QString::fromUtf8(windowSize.token.data(), windowSize.token.size()).append(",");
		str.append(QString::number(windowSize.radix));
		ui.tcpWs->setText(str);
		str = QString::fromUtf8(checksum.token.data(), checksum.token.size()).append(",");
		str.append(QString::number(checksum.radix));
		ui.tcpChecksum->setText(str);
		str = QString::fromUtf8(urgentPointer.token.data(), urgentPointer.token.size()).append(",");
		str.append(QString::number(urgentPointer.radix));
		ui.tcpUrgPointer->setText(str);
		return true;
	}
}

Token MainWindow::getIcmp(void)
{	
	if (!ui.icmpType->text().isEmpty() && !ui.icmpCode->text().isEmpty()
		&& !ui.icmpChecksum->text().isEmpty() && !ui.icmpId->text().isEmpty()
		&& !ui.icmpSeq->text().isEmpty() && !ui.icmpData->text().isEmpty()) {
			Token result = "";
			Token type = ui.icmpType->text().toUtf8().constData();
			Token code = ui.icmpCode->text().toUtf8().constData();
			Token id = ui.icmpId->text().toUtf8().constData();
			Token seq = ui.icmpSeq->text().toUtf8().constData();
			Token cs = ui.icmpChecksum->text().toUtf8().constData();
			if (Utilities::createICMPFormat(type, code, cs, id, seq, result))
				return result;
	}
	return "";
}

bool MainWindow::setIcmp(Token str)
{
	TokenAndRadix type, code, id, seq, checksum;
	if (!Utilities::parseICMPFormat(str, type, 
		code, checksum, id, seq)) {
			QMessageBox::critical(0, "Error", "Can't parse ICMP format");	
			return false;
	}	
	else {
		QString str = QString::fromUtf8(type.token.data(), type.token.size()).append(",");
		str.append(QString::number(type.radix));
		ui.icmpType->setText(str);
		str = QString::fromUtf8(code.token.data(), code.token.size()).append(",");
		str.append(QString::number(code.radix));
		ui.icmpCode->setText(str);
		str = QString::fromUtf8(id.token.data(), id.token.size()).append(",");
		str.append(QString::number(id.radix));
		ui.icmpId->setText(str);
		str = QString::fromUtf8(seq.token.data(), seq.token.size()).append(",");
		str.append(QString::number(seq.radix));
		ui.icmpSeq->setText(str);
		str = QString::fromUtf8(checksum.token.data(), checksum.token.size()).append(",");
		str.append(QString::number(checksum.radix));
		ui.icmpChecksum->setText(str);		
		return true;
	}
}

bool MainWindow::getFormats(void)
{
	bool prevLayer = false;
	Tokens fmts;
	Token tmp = getEth();
	if (tmp.empty()) {
		QMessageBox::critical(0, "Error", QString("Incorrect data at Ethernet fields\n"));
		return false;
	}
	else {
		fmts.push_back(getEth());	
		prevLayer = true;
	}
	tmp = getIp4();
	if (!tmp.empty() && prevLayer) {
		fmts.push_back(tmp);
	}
	else
		prevLayer = false;
		
	if (ui.transportTabs->currentWidget()->objectName() == QString("tcpTab")) {	
		tmp = getTcp();
		if (!tmp.empty() && prevLayer) {
				fmts.push_back(tmp);				
		}		
	}
	if (ui.transportTabs->currentWidget()->objectName() == QString("udpTab")) {	
		tmp = getUdp();
		if (!tmp.empty() && prevLayer) {
			fmts.push_back(tmp);
		}		
	}
	if (ui.transportTabs->currentWidget()->objectName() == QString("icmpTab")) {
		tmp = getIcmp();
		if (!tmp.empty() && prevLayer) {
			fmts.push_back(tmp);
		}		
	}
	formats->setValue(fmts);
	return true;
}

int MainWindow::selectPacket(QModelIndex& index)
{	
	if (!index.isValid())
		index = ui.packetsView->selectionModel()->currentIndex();
	else
		ui.packetsView->setCurrentIndex(index);
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
		return seekRoot.row();
	}
	return -1;
}

void MainWindow::sendPacket(void)
{
	if (selectedDev) {
		if (ui.sendAll->checkState() == Qt::Checked) {
			int currentRow = selectPacket();	
			int nextRow = currentRow;
			while (nextRow < currentRow + 1) {				
				_sendPacket();		
				nextRow = currentRow + 1;				 
				currentRow = selectPacket(packetsModel->index(nextRow,0));
			}			
		}
		else
			_sendPacket();		
	}
}

void MainWindow::_sendPacket(void)
{
	if (getFormats()) {
		//TODO: add stop feature
		//Note that the function may not run immediately;
		//the function will only be run when a thread is available.
		if (selectedDev->buildPackets(formats->getValue())) {
			QFuture<void> sender = QtConcurrent::run(this, &MainWindow::send);
			sender.waitForFinished();	
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