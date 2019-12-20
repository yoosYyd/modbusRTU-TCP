#pragma once
#include <memory.h>
#include <stdlib.h> 
#include <Windows.h>
#include <string>
#include "logger.h"

#pragma comment( lib, "Ws2_32.lib" )
/*********************************HEADERS_SECTION****************************************/
unsigned short swapWORD(unsigned short in)
{
	unsigned short ret = 0;
	unsigned char swap[3] = { 0 };
	memcpy(swap, &in, 2);
	swap[2] = swap[0];
	swap[0] = swap[1];
	swap[1] = swap[2];
	memcpy(&ret, swap, 2);
	return ret;
}

void ReverseBytesByWORDS(void *start, int size/*in words*/)
{
	unsigned short *words = (unsigned short *)start;
	for (int i = 0; i < size; i++)
	{
		words[i] = swapWORD(words[i]);
	}
}

#pragma pack(push)
#pragma pack(1)
struct MBAP
{
	unsigned short transID;
	unsigned short protID = 0;
	unsigned short len = 1;
	unsigned char unitIDp1 = 0;
	MBAP(int PDUlen)
	{
		len = len + PDUlen;
		len = swapWORD(len);
		transID = (rand() % (0xFFFF - 1)) + 1;
		unitIDp1 = (rand() % (0xFF - 1)) + 1;
	}
};
struct func01PDU
{
	unsigned char funcode = 1;
	unsigned short fcoilAdr;
	unsigned short coilCount;
	func01PDU(unsigned short startCoil, unsigned short coilCount)
	{
		this->fcoilAdr = swapWORD(startCoil);
		this->coilCount = swapWORD(coilCount);
	}
};
struct func01PDUresp
{
	unsigned char funcode = 1;
	unsigned short coilCount;
	unsigned char *bitMap = NULL;
	func01PDUresp(void *pduPTR)
	{
		funcode = *((unsigned char*)pduPTR);
		unsigned char *countPtr = ((unsigned char*)pduPTR) + 1;
		coilCount = *countPtr;
		unsigned char *dataPtr = countPtr + 1;
		if (coilCount > 0)
		{
			bitMap = new unsigned char[coilCount];
			memcpy(bitMap, dataPtr, coilCount);
		}
	}
};
struct func02PDU
{
	unsigned char funcode = 2;
	unsigned short fdiscAdr;
	unsigned short discCount;
	func02PDU(unsigned short startDisc, unsigned short discCount)
	{
		this->fdiscAdr = swapWORD(startDisc);
		this->discCount = swapWORD(discCount);
	}
};
struct func02PDUanswer : func01PDUresp
{
	func02PDUanswer(void *pduPTR) :func01PDUresp(pduPTR) {};
};
struct func03PDU
{
	unsigned char funcode = 3;
	unsigned short fregAdr;
	unsigned short regsCount;
	func03PDU(unsigned short fregAdr, unsigned short regsCount)
	{
		this->fregAdr = swapWORD(fregAdr);
		this->regsCount = swapWORD(regsCount);
	}
};
struct func03PDUresp
{
	unsigned char funcode;
	unsigned char regCount;
	unsigned short integers[255] = {0};
	func03PDUresp(void *pduPTR)
	{
		funcode = *((unsigned char*)pduPTR);
		unsigned char *countPtr = ((unsigned char*)pduPTR) + 1;
		regCount = *countPtr;
		unsigned char *dataPtr = countPtr + 1;
		if (regCount >0 && regCount < 256)
		{
			memcpy(integers, dataPtr, regCount);
			ReverseBytesByWORDS(integers, regCount / 2);
		}
	}
};
struct func04PDU
{
	unsigned char funcode = 4;
	unsigned short inputAdr;
	unsigned short inputCount;
	func04PDU(unsigned short inputAdr, unsigned short inputCount)
	{
		this->inputAdr = swapWORD(inputAdr);
		this->inputCount = swapWORD(inputCount);
	}
};
struct func04PDUanswer : func03PDUresp
{
	func04PDUanswer(void *pduPTR) :func03PDUresp(pduPTR)
	{}
};
struct func05PDU
{
	unsigned char funcode = 5;
	unsigned short coilAdr;
	unsigned char force1 = 0;
	unsigned char force2 = 0;
	func05PDU(unsigned short coilAdr, bool forceTo)
	{
		this->coilAdr = swapWORD(coilAdr);
		if (forceTo)
		{
			force1 = 0xFF;
		}
	}
};
struct func06PDU
{
	unsigned char funcode = 6;
	unsigned short inputAdr;
	unsigned short val;
	func06PDU(unsigned short inputAdr, unsigned short val)
	{
		this->inputAdr = swapWORD(inputAdr);
		this->val = swapWORD(val);
	}
};
struct func15PDU
{
	unsigned char funcode = 15;
	unsigned short startADR;
	unsigned short coilsCount;
	unsigned char dataLen;//bytes
	func15PDU(unsigned short adr, unsigned short count, unsigned char dataLen)
	{
		this->startADR = swapWORD(adr);
		this->coilsCount = swapWORD(coilsCount);
		this->dataLen = dataLen;
	}
};
struct func15PDUresp
{
	unsigned char funcode;
	unsigned short startADR;
	unsigned short coilsCount;
	func15PDUresp(unsigned char *data)
	{
		funcode = data[0];
		memcpy(&startADR, data + 1, 2);
		startADR = swapWORD(startADR);
		memcpy(&coilsCount, data + 3, 2);
		coilsCount = swapWORD(coilsCount);
	}
};
struct func16PDU
{
	unsigned char funcode = 16;
	unsigned short startAdr;
	unsigned short regsCount;
	unsigned char dataBytesCount;
	func16PDU(unsigned short startAdr, unsigned short regsCount)
	{
		this->dataBytesCount = regsCount * 2;
		this->startAdr = swapWORD(startAdr);
		this->regsCount = swapWORD(regsCount);
	}
};
struct func16PDUresp
{
	unsigned char funcode = 16;
	unsigned short startAdr;
	unsigned short regsCount;
	func16PDUresp(unsigned char* data)
	{
		funcode = data[0];
		memcpy(&startAdr, data + 1, 2);
		startAdr = swapWORD(startAdr);
		memcpy(&regsCount, data + 3, 2);
		regsCount = swapWORD(regsCount);
	}
};
#pragma pack(pop)
/*****************************************COMMUNICATION_SECTION***********************************************/
struct connDescriptor//settings for serial port
{
	int comId;
	int baudRate;
	unsigned char parity;
	unsigned char stopbit;
	unsigned char byteSize;
	unsigned short timeout;
	connDescriptor(int comId, int baudRate, unsigned char parity,
		unsigned char stopbit, unsigned char byteSizeof, unsigned short timeout)
	{
		this->comId = comId;
		this->baudRate = baudRate;
		this->parity = parity;
		this->stopbit = stopbit;
		this->byteSize = byteSizeof;
		this->timeout = timeout;
	}
};
class SerialExchangeInterface
{
private:
	bool isConnOpened = false;
	HANDLE COMdescriptor = INVALID_HANDLE_VALUE;
	Logger *log;

	bool SetUPSerial(connDescriptor* setts)
	{
		char comid[128] = "";
		wsprintfA(comid, "\\\\.\\COM%d", setts->comId);
		COMdescriptor = CreateFileA(comid, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 0, NULL);
		if (COMdescriptor == INVALID_HANDLE_VALUE)
		{
			log->Log(log->format("SetUPSerial::open com %d error %d", setts->comId, GetLastError()));
			return false;
		}
		DCB dcb = { 0 };
		dcb.DCBlength = sizeof(dcb);
		if (GetCommState(COMdescriptor, &dcb) == 0)
		{
			log->Log(log->format("SetUPSerial::GetCommState fail %d",GetLastError()));
			return false;
		}
		dcb.BaudRate = setts->baudRate;
		dcb.Parity = setts->parity;
		dcb.ByteSize = setts->byteSize;
		dcb.StopBits = setts->stopbit;
		dcb.fBinary = 1;
		if (SetCommState(COMdescriptor, &dcb) == 0)
		{
			log->Log(log->format("SetUPSerial::SetCommState fail %d", GetLastError()));
			return false;
		}
		COMMTIMEOUTS ct = { 0 };
		if (GetCommTimeouts(COMdescriptor, &ct) == 0)
		{
			log->Log(log->format("SetUPSerial::GetCommTimeouts failed %d", GetLastError()));
			return false;
		}
		ct.ReadIntervalTimeout = setts->timeout;
		ct.ReadTotalTimeoutConstant = 300;
		ct.ReadTotalTimeoutMultiplier = 25;
		ct.WriteTotalTimeoutMultiplier = 2;
		ct.WriteTotalTimeoutConstant = 100;
		if (SetCommTimeouts(COMdescriptor, &ct) == 0)
		{
			printf("SetCommTimeouts failed %d\n", GetLastError());
			log->Log(log->format("SetUPSerial::SetCommTimeouts failed %d", GetLastError()));
			return false;
		}
		SetCommMask(COMdescriptor, EV_RXCHAR);
		return true;
	}
protected:
	bool WriteDataSer(char *data, int dataLen, DWORD *dataWrited)
	{
		if (WriteFile(COMdescriptor, data, dataLen, dataWrited, 0) == 0)
		{
			log->Log(log->format("WriteDataSer::WriteFile failed %d", GetLastError()));
			return false;
		}
		return true;
	}
	bool ReadDataSer(char *data, int dataLen, DWORD *dataReaded)
	{
		char *buff = new char[dataLen];
		if (ReadFile(COMdescriptor, buff, dataLen, dataReaded, 0) == 0)
		{
			delete[]buff;
			log->Log(log->format("ReadDataSer::ReadFile failed %d", GetLastError()));
			return false;
		}
		memcpy(data, buff, *dataReaded);
		return true;
	}
	bool IsConnectedSer()
	{
		return isConnOpened;
	}
public:
	SerialExchangeInterface() 
	{
		log = Logger::getInstance();
	}
	SerialExchangeInterface(connDescriptor* connSetts)
	{
		log = Logger::getInstance();
		isConnOpened = SetUPSerial(connSetts);
	}
	~SerialExchangeInterface()
	{
		if (COMdescriptor != INVALID_HANDLE_VALUE)
		{
			CloseHandle(COMdescriptor);
		}
	}
};

class TCPexchangeInterface
{
private:
	std::string remoteAdr;
	int remotePort;
	int timeOut;
	SOCKET sock = INVALID_SOCKET;
	int connStatus;
	Logger *log;

	void ShootSock()
	{
		if (sock == INVALID_SOCKET)
			return;
		if (shutdown(sock, 1) == SOCKET_ERROR)
		{
			log->Log(log->format("ShootSock::shutdown error: %d", WSAGetLastError()));
		}
		if (closesocket(sock) == SOCKET_ERROR)
		{
			log->Log(log->format("ShootSock::closesocket error: %d", WSAGetLastError()));
		}
		sock = INVALID_SOCKET;
	}
	void TryConn()
	{
		wchar_t errbuf[512];
		struct sockaddr_in remote;
		ShootSock();
		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock == INVALID_SOCKET)
		{
			log->Log(log->format("TryConn::connect error: %d", WSAGetLastError()));
		}
		ZeroMemory(&remote, sizeof(remote));
		remote.sin_addr.s_addr = inet_addr(this->remoteAdr.c_str());
		remote.sin_family = AF_INET;
		remote.sin_port = htons(this->remotePort);
		DWORD to = this->timeOut;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, 4);
		this->connStatus = connect(sock, (struct sockaddr *)&remote, sizeof(remote));
		if (this->connStatus != 0)
		{
			log->Log(log->format("TryConn::connect error: %d", WSAGetLastError()));
		}
	}
	int ReadFromSocket(unsigned char *read_buffer, int buffLen)
	{
		unsigned char *buff = new unsigned char[buffLen];
		wchar_t errbuf[512];
		int counter = 0, result = 0;
		while (counter < (result = recv(sock, (char*)buff, buffLen, 0)) > 0)
		{
			memcpy(read_buffer, buff + counter, result);
			counter += result;
		}
		delete[] buff;
		if (result == SOCKET_ERROR && counter<1)
		{
			log->Log(log->format("TCPReadFromSocket::receiving error: %d", WSAGetLastError()));
			this->TryConn();
		}
		return counter;
	}
	int WriteToSocket(char *data, int dataLen)
	{
		return send(sock, data, dataLen, 0);
	}
protected:
	bool WriteDataSock(char *data, int dataLen)
	{
		int status = WriteToSocket(data, dataLen);
		if (status == SOCKET_ERROR)
		{
			log->Log(log->format("TCPWriteData::send error: %d", WSAGetLastError()));
		}
		return status != SOCKET_ERROR;
	}
	int WaitData(char *data, DWORD buffLen)
	{
		return ReadFromSocket((unsigned char*)data, buffLen);
	}
	bool IsConnectedSock()
	{
		return sock != INVALID_SOCKET;
	}
public:
	TCPexchangeInterface() {}
	TCPexchangeInterface(char *remoteAdr, int port, int connTimeOut)
	{
		log = Logger::getInstance();
		this->remoteAdr = std::string(remoteAdr);
		remotePort = port;
		timeOut = connTimeOut;
		WSADATA wsd = { 0 };
		WSAStartup(MAKEWORD(2, 2), &wsd);
		this->TryConn();
	}
	~TCPexchangeInterface()
	{
		ShootSock();
	}
};

class UniDataExInterface :public TCPexchangeInterface, SerialExchangeInterface
{
private:
public:
	UniDataExInterface(connDescriptor *cd) :SerialExchangeInterface(cd)
	{}
	UniDataExInterface(char *remoteAdr, int port, int connTimeOut) :
		TCPexchangeInterface(remoteAdr, port, connTimeOut)
	{}
	~UniDataExInterface()
	{}
	bool WriteData(unsigned char* data, DWORD dataLen)
	{
		bool ret = false;
		if (this->IsConnectedSock())
		{
			ret = this->WriteDataSock((char*)data, dataLen);
		}
		if (this->IsConnectedSer())
		{
			DWORD wd = 0;
			ret = this->WriteDataSer((char*)data, dataLen, &wd);
		}
		return ret;
	}
	bool ReadData(unsigned char* data, int buffLen, DWORD &dataRead)
	{
		bool ret = false;
		if (this->IsConnectedSock())
		{
			dataRead = this->WaitData((char*)data, buffLen);
			ret = dataRead > 0;
		}
		if (this->IsConnectedSer())
		{
			ret = this->ReadDataSer((char*)data, buffLen, &dataRead);
		}
		return ret;
	}
	bool IsConnected()
	{
		return this->IsConnectedSock() | this->IsConnectedSer();
	}
};
/*************************************************MODBUS_SECTION*******************************************************/
class ModUNI :public UniDataExInterface
{
private:
	int delay = 50;
	unsigned char *buffer = NULL;
	int buffSize = 4096;
	bool tcp2rtu = false;
	Logger *log;
	/************************************************************/
	unsigned short GEN_CRC16(unsigned char *buf, int len)
	{
		unsigned short crc = 0xFFFF;
		for (int pos = 0; pos < len; pos++)
		{
			crc ^= (unsigned short)buf[pos];
			for (int i = 8; i != 0; i--) {
				if ((crc & 0x0001) != 0) {
					crc >>= 1;
					crc ^= 0xA001;
				}
				else
					crc >>= 1;
			}
		}
		return crc;
	}
	bool IsRTUpacketGOOD(unsigned char *packet, int len)
	{
		unsigned short crc = this->GEN_CRC16(packet, len - 2);
		unsigned char *packetCRCptr = packet + (len - 2);
		unsigned char *calcCRCptr = (unsigned char *)&crc;
		return packetCRCptr[1] == calcCRCptr[1] && packetCRCptr[0] == calcCRCptr[0];
	}
	bool IsResError(unsigned char *data)
	{
		return data[0] > 129 && data[0] < 145;
	}
	func01PDUresp* ReadCoilRTU(unsigned char dev, unsigned short coilAdr, unsigned short coilCount)
	{
		buffer[0] = dev;
		unsigned char *PDUptr = buffer + 1;
		memcpy(PDUptr, &func01PDU(coilAdr - 1, coilCount), sizeof(func01PDU));
		unsigned short crc = this->GEN_CRC16(buffer, sizeof(func01PDU) + 1);
		unsigned char *crcptr = PDUptr + sizeof(func01PDU);
		memcpy(crcptr, &crc, 2);
		WriteData(buffer, 3 + sizeof(func01PDU));
		DWORD readed = 0;
		Sleep(delay);
		ReadData(buffer, buffSize, readed);
		func01PDUresp *ret = NULL;
		if (readed > 0 && *buffer == dev)
		{
			if (IsRTUpacketGOOD(buffer, readed))
			{
				ret = new func01PDUresp(buffer + 1);
			}
		}
		if (IsResError(buffer + 1))
		{
			log->Log(log->format("ReadCoilRTU::modbus error: %X", buffer[2]));
		}
		return ret;
	}
	func02PDUanswer* ReadDInputRTU(unsigned char dev, unsigned short coilAdr, unsigned short coilCount)
	{
		buffer[0] = dev;
		unsigned char *PDUptr = buffer + 1;
		memcpy(PDUptr, &func02PDU(coilAdr - 1, coilCount), sizeof(func02PDU));
		unsigned short crc = this->GEN_CRC16(buffer, sizeof(func02PDU) + 1);
		unsigned char *crcptr = PDUptr + sizeof(func02PDU);
		memcpy(crcptr, &crc, 2);
		WriteData(buffer, 3 + sizeof(func02PDU));
		DWORD readed = 0;
		Sleep(delay);
		this->ReadData(buffer, buffSize, readed);
		func02PDUanswer* ret = NULL;
		if (readed > 0 && *buffer == dev)
		{
			if (IsRTUpacketGOOD(buffer, readed))
			{
				ret = new func02PDUanswer(buffer + 1);
			}
		}
		if (IsResError(buffer + 1))
		{
			log->Log(log->format("ReadDInputRTU::modbus error: %X", buffer[2]));
		}
		return ret;
	}
	func03PDUresp* ReadHoldRegRTU(unsigned char dev, unsigned short adr, unsigned char regCount)
	{
		buffer[0] = dev;
		unsigned char *pduPtr = buffer + 1;
		memcpy(pduPtr, &func03PDU(adr - 1, regCount), sizeof(func03PDU));
		unsigned char *crcPtr = pduPtr + sizeof(func03PDU);
		unsigned short crc = this->GEN_CRC16(buffer, sizeof(func03PDU) + 1);
		memcpy(crcPtr, &crc, 2);
		WriteData(buffer, 3 + sizeof(func03PDU));
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		Sleep(delay);
		unsigned short ret = 0;
		func03PDUresp *answer = NULL;
		if (readed > 0 && *buffer == dev)
		{
			if (IsRTUpacketGOOD(buffer, readed))
			{
				answer = new func03PDUresp(buffer + 1);
			}
		}
		if (IsResError(buffer + 1))
		{
			log->Log(log->format("ReadHoldRegRTU::modbus error: %X", buffer[2]));
		}
		return answer;
	}
	func04PDUanswer* ReadAInputRTU(unsigned char dev, unsigned short adr, unsigned short count)
	{
		buffer[0] = dev;
		unsigned char *pduPtr = buffer + 1;
		memcpy(pduPtr, &func04PDU(adr - 1, count), sizeof(func04PDU));
		unsigned char *crcPtr = pduPtr + sizeof(func04PDU);
		unsigned short crc = this->GEN_CRC16(buffer, sizeof(func04PDU) + 1);
		memcpy(crcPtr, &crc, 2);
		WriteData(buffer, 3 + sizeof(func04PDU));
		DWORD readed = 0;
		Sleep(delay);
		this->ReadData(buffer, buffSize, readed);
		func04PDUanswer* ret = NULL;
		if (readed > 0 && *buffer == dev)
		{
			if (IsRTUpacketGOOD(buffer, readed))
			{
				ret = new func04PDUanswer(buffer + 1);
			}
		}
		if (IsResError(buffer + 1))
		{
			log->Log(log->format("ReadAInputRTU::modbus error: %X", buffer[2]));
		}
		return ret;
	}
	bool ForceCoilRTU(unsigned char dev, unsigned short adr, bool to)
	{
		buffer[0] = dev;
		unsigned char *PDUptr = buffer + 1;
		memcpy(PDUptr, &func05PDU(adr - 1, to), sizeof(func05PDU));
		unsigned short crc = this->GEN_CRC16(buffer, sizeof(func05PDU) + 1);
		unsigned char *crcptr = PDUptr + sizeof(func05PDU);
		memcpy(crcptr, &crc, 2);
		WriteData(buffer, 3 + sizeof(func05PDU));
		DWORD readed = 0;
		Sleep(delay);
		this->ReadData(buffer, buffSize, readed);
		if (dev != buffer[0] || readed == 0) { return false; }
		if (!IsRTUpacketGOOD(buffer, readed)) { return false; }
		bool ret = (buffer[readed - 4] == 0xFF) | (buffer[readed - 3] == 0);
		if (IsResError(buffer + 1))
		{
			log->Log(log->format("ForceCoilRTU::modbus error: %X", buffer[2]));
		}
		return ret;
	}
	bool SetHoldingRegRTU(unsigned char dev, unsigned short adr, unsigned short val)
	{
		buffer[0] = dev;
		unsigned char *PDUptr = buffer + 1;
		func06PDU pdu = func06PDU(adr - 1, val);
		memcpy(PDUptr, &pdu, sizeof(func06PDU));
		unsigned short crc = this->GEN_CRC16(buffer, sizeof(func06PDU) + 1);
		unsigned char *crcptr = PDUptr + sizeof(func06PDU);
		memcpy(crcptr, &crc, 2);
		WriteData(buffer, 3 + sizeof(func06PDU));
		DWORD readed = 0;
		Sleep(delay);
		ReadData(buffer, buffSize, readed);
		if (IsResError(buffer + 1))
		{
			log->Log(log->format("SetHoldingRegRTU::modbus error: %X", buffer[2]));
		}
		if (dev != buffer[0] || readed == 0) { return false; }
		return (((unsigned short*)(buffer))[2] == pdu.val) &&
			(((unsigned short*)(buffer))[1] == pdu.inputAdr);
	}
	bool ForceCoilsRTU(unsigned char dev, unsigned short startCoil, unsigned short coilsCount, unsigned char dataLen,
		unsigned char* data)
	{
		buffer[0] = dev;
		unsigned char *PDUptr = buffer + 1;
		memcpy(PDUptr, &func15PDU(startCoil - 1, coilsCount, dataLen), sizeof(func15PDU));
		unsigned char *dataPTR = PDUptr + sizeof(func15PDU);
		memcpy(dataPTR, data, dataLen);
		unsigned short crc = this->GEN_CRC16(buffer, sizeof(func15PDU) + 1 + dataLen);
		unsigned char *CRCptr = dataPTR + dataLen;
		memcpy(CRCptr, &crc, 2);
		WriteData(buffer, 3 + sizeof(func15PDU) + dataLen);
		DWORD readed = 0;
		Sleep(delay);
		ReadData(buffer, buffSize, readed);
		if (dev != buffer[0] || readed == 0) { return false; }
		func15PDUresp answer = func15PDUresp(buffer + 1);
		if (IsResError(buffer + 1))
		{
			log->Log(log->format("ForceCoilsRTU::modbus error: %X", buffer[2]));
		}
		return (startCoil == answer.startADR + 1) && (coilsCount == answer.coilsCount);
	}
	bool ForceCoilsTCP(unsigned short startCoil, unsigned short coilsCount, unsigned char dataLen
		, unsigned char* data)
	{
		unsigned char *MBAPptr = buffer;
		unsigned char *PDUptr = buffer + sizeof(MBAP);
		memcpy(MBAPptr, &MBAP(sizeof(func15PDU)), sizeof(MBAP));
		memcpy(PDUptr, &func15PDU(startCoil - 1, coilsCount, dataLen), sizeof(func15PDU));
		unsigned char *dataPTR = PDUptr + sizeof(func15PDU);
		memcpy(dataPTR, data, dataLen);
		WriteData(buffer, sizeof(MBAP) + sizeof(func15PDU) + dataLen);
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		if (readed == 0)
		{
			return false;
		}
		func15PDUresp resp = func15PDUresp(buffer + sizeof(MBAP));
		if (IsResError(buffer + sizeof(MBAP)))
		{
			unsigned char *errCptr = buffer + sizeof(MBAP);
			log->Log(log->format("ForceCoilsTCP::modbus error: %X", errCptr[1]));
		}
		return (resp.startADR + 1 == startCoil) && (resp.coilsCount == coilsCount);
	}
	bool ForceRegsRTU(unsigned char dev, unsigned short startReg, unsigned short regsCount, unsigned short* data)
	{
		buffer[0] = dev;
		unsigned char *PDUptr = buffer + 1;
		memcpy(PDUptr, &func16PDU(startReg - 1, regsCount), sizeof(func16PDU));
		unsigned char *dataPTR = PDUptr + sizeof(func16PDU);
		for (int i = 0; i < regsCount; i++)
		{
			data[i] = swapWORD(data[i]);
		}
		memcpy(dataPTR, data, regsCount * 2);
		unsigned short crc = this->GEN_CRC16(buffer, 1 + sizeof(func16PDU) + regsCount * 2);
		unsigned char *CRCptr = dataPTR + regsCount * 2;
		memcpy(CRCptr, &crc, 2);
		WriteData(buffer, 3 + sizeof(func16PDU) + regsCount * 2);
		DWORD readed = 0;
		Sleep(delay);
		ReadData(buffer, buffSize, readed);
		if (dev != buffer[0] || readed == 0) { return false; }
		func16PDUresp ans = func16PDUresp(buffer + 1);
		if (IsResError(buffer + sizeof(MBAP)))
		{
			log->Log(log->format("ForceRegsRTU::modbus error: %X", buffer[2]));
		}
		return (ans.regsCount == regsCount) && (startReg == ans.startAdr + 1);
	}
	bool ForceRegsTCP(unsigned short startReg, unsigned short regsCount, unsigned short* data)
	{
		unsigned char *MBAPptr = buffer;
		unsigned char *PDUptr = buffer + sizeof(MBAP);
		memcpy(MBAPptr, &MBAP(sizeof(func16PDU)), sizeof(MBAP));
		memcpy(PDUptr, &func16PDU(startReg - 1, regsCount), sizeof(func16PDU));
		unsigned char *dataPTR = PDUptr + sizeof(func16PDU);
		ReverseBytesByWORDS(data, regsCount);
		memcpy(dataPTR, data, regsCount * 2);
		WriteData(buffer, sizeof(MBAP) + sizeof(func16PDU) + regsCount * 2);
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		if (readed == 0) { return false; }
		func16PDUresp ans = func16PDUresp(buffer + 1);
		if (IsResError(buffer + sizeof(MBAP)))
		{
			unsigned char *errCptr = buffer + sizeof(MBAP);
			log->Log(log->format("ForceRegsTCP::modbus error: %X", errCptr[1]));
		}
		return (ans.regsCount == regsCount) && (startReg == ans.startAdr + 1);
	}
	func01PDUresp* ReadCoilTCP(unsigned short coilAdr, unsigned short coilCount)
	{
		unsigned char *MBAPptr = buffer;
		unsigned char *PDUptr = buffer + sizeof(MBAP);
		memcpy(MBAPptr, &MBAP(sizeof(func01PDU)), sizeof(MBAP));
		memcpy(PDUptr, &func01PDU(coilAdr - 1, coilCount), sizeof(func01PDU));
		WriteData(buffer, sizeof(MBAP) + sizeof(func01PDU));
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		func01PDUresp* ret = NULL;
		if (readed > 0)
		{
			ret = new func01PDUresp(buffer + sizeof(MBAP));
		}
		if (IsResError(buffer + sizeof(MBAP)))
		{
			unsigned char *errCptr = buffer + sizeof(MBAP);
			log->Log(log->format("ReadCoilTCP::modbus error: %X", errCptr[1]));
		}
		return ret;
	}
	func02PDUanswer* ReadDInputTCP(unsigned short coilAdr, unsigned short coilCount)
	{
		unsigned char *MBAPptr = buffer;
		unsigned char *PDUptr = buffer + sizeof(MBAP);
		memcpy(MBAPptr, &MBAP(sizeof(func02PDU)), sizeof(MBAP));
		memcpy(PDUptr, &func02PDU(coilAdr - 1, coilCount), sizeof(func02PDU));
		WriteData(buffer, sizeof(MBAP) + sizeof(func02PDU));
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		func02PDUanswer *ret = NULL;
		if (readed>0)
		{
			ret = new func02PDUanswer(buffer + sizeof(MBAP));
		}
		if (IsResError(buffer + sizeof(MBAP)))
		{
			unsigned char *errCptr = buffer + sizeof(MBAP);
			log->Log(log->format("ReadDInputTCP::modbus error: %X", errCptr[1]));
		}
		return ret;
	}
	func04PDUanswer* ReadAInputTCP(unsigned short adr, unsigned short count)
	{
		unsigned char *MBAPptr = buffer;
		unsigned char *PDUptr = buffer + sizeof(MBAP);
		memcpy(MBAPptr, &MBAP(sizeof(func04PDU)), sizeof(MBAP));
		memcpy(PDUptr, &func04PDU(adr - 1, count), sizeof(func04PDU));
		WriteData(buffer, sizeof(MBAP) + sizeof(func04PDU));
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		func04PDUanswer *ret = NULL;
		if (readed > 0)
		{
			ret = new func04PDUanswer(buffer + sizeof(MBAP));
		}
		if (IsResError(buffer + sizeof(MBAP)))
		{
			unsigned char *errCptr = buffer + sizeof(MBAP);
			log->Log(log->format("ReadAInputTCP::modbus error: %X", errCptr[1]));
		}
		return ret;
	}
	func03PDUresp* ReadHoldRegTCP(unsigned short adr, unsigned short count)
	{
		unsigned char *MBAPptr = buffer;
		unsigned char *PDUptr = buffer + sizeof(MBAP);
		memcpy(MBAPptr, &MBAP(sizeof(func03PDU)), sizeof(MBAP));
		memcpy(PDUptr, &func03PDU(adr - 1, count), sizeof(func03PDU));
		WriteData(buffer, sizeof(MBAP) + sizeof(func03PDU));
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		func03PDUresp *ret = NULL;
		if (readed > 0)
		{
			ret = new func03PDUresp(buffer + sizeof(MBAP));
		}
		if (IsResError(buffer + sizeof(MBAP)))
		{
			unsigned char *errCptr = buffer + sizeof(MBAP);
			log->Log(log->format("ReadHoldRegTCP::modbus error: %X", errCptr[1]));
		}
		return ret;
	}
	bool ForceCoilTCP(unsigned short adr, bool to)
	{
		unsigned char *MBAPptr = buffer;
		unsigned char *PDUptr = buffer + sizeof(MBAP);
		memcpy(MBAPptr, &MBAP(sizeof(func05PDU)), sizeof(MBAP));
		memcpy(PDUptr, &func05PDU(adr - 1, to), sizeof(func05PDU));
		WriteData(buffer, sizeof(MBAP) + sizeof(func05PDU));
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		bool ret = (buffer[readed - 2] == 0xFF) | (buffer[readed - 2] == 0);
		if (IsResError(buffer + sizeof(MBAP)))
		{
			unsigned char *errCptr = buffer + sizeof(MBAP);
			log->Log(log->format("ForceCoilTCP::modbus error: %X", errCptr[1]));
		}
		return ret;
	}
	bool SetHoldingRegTCP(unsigned short adr, unsigned short val)
	{
		unsigned char *MBAPptr = buffer;
		unsigned char *PDUptr = buffer + sizeof(MBAP);
		memcpy(MBAPptr, &MBAP(sizeof(func06PDU)), sizeof(MBAP));
		func06PDU pdu = func06PDU(adr - 1, val);
		memcpy(PDUptr, &pdu, sizeof(func06PDU));
		WriteData(buffer, sizeof(MBAP) + sizeof(func06PDU));
		DWORD readed = 0;
		ReadData(buffer, buffSize, readed);
		bool ret = (((unsigned short*)(buffer))[5] == pdu.val) &&
			(((unsigned short*)(buffer))[4] == pdu.inputAdr);
		if (IsResError(buffer + sizeof(MBAP)))
		{
			unsigned char *errCptr = buffer + sizeof(MBAP);
			log->Log(log->format("SetHoldingRegTCP::modbus error: %X", errCptr[1]));
		}
		return ret;
	}
public:
	ModUNI(connDescriptor *cd, int buffSize = 4096) :UniDataExInterface(cd)
	{
		this->log = Logger::getInstance();
		delay = cd->timeout;
		this->buffer = new unsigned char[buffSize];
		this->buffSize = 4096;
	}
	ModUNI(char *remoteAdr, int port, int connTimeOut, int buffSize = 4096, bool tcp2rtu = false) :
		UniDataExInterface(remoteAdr, port, connTimeOut)
	{
		srand(time(NULL));
		this->log = Logger::getInstance();
		this->buffer = new unsigned char[buffSize];
		this->buffSize = 4096;
		this->tcp2rtu = tcp2rtu;
	}
	~ModUNI()
	{
		delete[]buffer;
	}
	/****************************************GET_SECTION************************************/
	bool GetINT16(unsigned short adr, short &out, unsigned char dev = 1)
	{
		bool ret = false;
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, 1);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, 1);
		}
		if (data == NULL) { return ret; }
		out = data->integers[0];
		delete data;
		return true;
	}
	bool GetUINT16(unsigned short adr, unsigned short &out, unsigned char dev = 1)
	{
		bool ret = false;
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, 1);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, 1);
		}
		if (data == NULL) { return ret; }
		out = data->integers[0];
		delete data;
		return true;
	}
	bool GetINT32(unsigned short adr, int &out, unsigned char dev = 1)
	{
		bool ret = false;
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, 2);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, 2);
		}
		if (data == NULL) { return ret; }
		out = *((int*)&data->integers[0]);
		delete data;
		return true;
	}
	bool GetUINT32(unsigned short adr, unsigned int &out, unsigned char dev = 1)
	{
		bool ret = false;
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, 2);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, 2);
		}
		if (data == NULL) { return ret; }
		out = *((int*)&data->integers[0]);
		delete data;
		return true;
	}
	bool GetINT64(unsigned short adr, __int64 &out, unsigned char dev = 1)
	{
		bool ret = false;
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, 4);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, 4);
		}
		if (data == NULL) { return ret; }
		out = *((__int64*)&data->integers[0]);
		delete data;
		return true;
	}
	bool GetUINT64(unsigned short adr, unsigned __int64 &out, unsigned char dev = 1)
	{
		bool ret = false;
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, 4);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, 4);
		}
		if (data == NULL)
		{

			return ret;
		}
		out = *((__int64*)&data->integers[0]);
		delete data;
		return true;
	}
	bool GetDOUBLE(unsigned short adr, double &out, unsigned char dev = 1)
	{
		bool ret = false;
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, 4);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, 4);
		}
		if (data == NULL) { return ret; }
		out = *((double*)&data->integers[0]);
		delete data;
		return true;
	}
	bool GetFLOAT(unsigned short adr, float &out, unsigned char dev = 1)
	{
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, 2);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, 2);
		}
		if (data == NULL) { return false; }
		out = *((float*)&data->integers[0]);
		delete data;
		return true;
	}
	bool GetDInputs(unsigned short firstInp, unsigned short inpCount, unsigned char *map, unsigned char dev = 1)
	{
		bool ret = false;
		if (map != NULL)
		{
			func02PDUanswer *dis = NULL;
			if (this->IsConnectedSock() && !tcp2rtu)
			{
				dis = this->ReadDInputTCP(firstInp, inpCount);
			}
			else
			{
				dis = this->ReadDInputRTU(dev, firstInp, inpCount);
			}
			if (dis != NULL)
			{
				int sz = dis->coilCount /*/ 8 + 1*/;
				memcpy(map, dis->bitMap, sz);
				delete dis;
				ret = true;
			}
		}
		return ret;
	}
	bool GetDI(unsigned short firstInp, bool &val, unsigned char dev = 1)
	{
		bool ret = false;
		func02PDUanswer *dis = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			dis = this->ReadDInputTCP(firstInp, 1);
		}
		else
		{
			dis = this->ReadDInputRTU(dev, firstInp, 1);
		}
		if (dis != NULL)
		{
			val = dis->bitMap[0];
			delete dis;
			ret = true;
		}
		return ret;
	}
	bool GetCoil(unsigned short firstInp, bool &val, unsigned char dev = 1)
	{
		bool ret = false;
		func01PDUresp *cis = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			cis = this->ReadCoilTCP(firstInp, 1);
		}
		else
		{
			cis = this->ReadCoilRTU(dev, firstInp, 1);
		}
		if (cis != NULL)
		{
			val = cis->bitMap[0];
			delete cis;
			ret = true;
		}
		return ret;
	}
	bool GetAIReg(unsigned short adr, unsigned short &val, unsigned char dev = 1)
	{
		bool ret = false;
		func04PDUanswer *ai = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			ai = this->ReadAInputTCP(adr, 1);
		}
		else
		{
			ai = this->ReadAInputRTU(dev, adr, 1);
		}
		if (ai != NULL)
		{
			ret = true;
			val = ai->integers[0];
			delete ai;
		}
		return ret;
	}
	bool GetString(unsigned short adr, char *out, unsigned short len/*bytes*/, unsigned char dev = 1)
	{
		if (len == 0) { return false; }
		int buffLen;
		if (len % 2 != 0)
		{
			buffLen = len + 1;
		}
		else
		{
			buffLen = len;
		}
		func03PDUresp *data = NULL;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			data = this->ReadHoldRegTCP(adr, buffLen/2);
		}
		else
		{
			data = this->ReadHoldRegRTU(dev, adr, buffLen/2);
		}
		if (data == NULL) { return false; }
		memcpy(out,data->integers ,len);
		delete data;
		return true;
	}
	/*************************************SET_SECTION******************************************/
	bool SetUINT16(unsigned short adr, unsigned short val, unsigned char dev = 1)
	{
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->SetHoldingRegTCP(adr, val);
		}
		else
		{
			return this->SetHoldingRegRTU(dev, adr, val);
		}
		return false;
	}
	bool SetINT16(unsigned short adr, short val, unsigned char dev = 1)
	{
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->SetHoldingRegTCP(adr, val);
		}
		else
		{
			return this->SetHoldingRegRTU(dev, adr, val);
		}
		return false;
	}
	bool SetINT32(unsigned short adr, int val, unsigned char dev = 1)
	{
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->ForceRegsTCP(adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		else
		{
			return this->ForceRegsRTU(dev, adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		return false;
	}
	bool SetUINT32(unsigned short adr, int val, unsigned char dev = 1)
	{
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->ForceRegsTCP(adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		else
		{
			return this->ForceRegsRTU(dev, adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		return false;
	}
	bool SetFloat(unsigned short adr, float val, unsigned char dev = 1)
	{
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->ForceRegsTCP(adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		else
		{
			return this->ForceRegsRTU(dev, adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		return false;
	}
	bool SetINT64(unsigned short adr, __int64 val, unsigned char dev = 1)
	{
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->ForceRegsTCP(adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		else
		{
			return this->ForceRegsRTU(dev, adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		return false;
	}
	bool SetUINT64(unsigned short adr, unsigned __int64 val, unsigned char dev = 1)
	{
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->ForceRegsTCP(adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		else
		{
			return this->ForceRegsRTU(dev, adr, sizeof(float) / 2, (unsigned short*)&val);
		}
		return false;
	}
	bool SetDOUBLE(unsigned short adr, double val, unsigned char dev = 1)
	{
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->ForceRegsTCP(adr, sizeof(double) / 2, (unsigned short*)&val);
		}
		else
		{
			return this->ForceRegsRTU(dev, adr, sizeof(double) / 2, (unsigned short*)&val);
		}
		return false;
	}
	bool SetCoil(unsigned short coil, bool val, unsigned char dev = 1)
	{
		bool ret = false;
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			ret = this->ForceCoilTCP(coil, val);
		}
		else
		{
			ret = this->ForceCoilRTU(dev, coil, val);
		}
		return ret;
	}
	bool SetString(unsigned short adr,char *str, unsigned char dev = 1)
	{
		int strLen = strlen(str);
		if (strLen % 2 != 0)
		{
			strLen = strLen + 1;
		}
		char *strBuff = new char[strLen];
		memset(strBuff, 0, strLen);
		memcpy(strBuff, str, strLen);
		if (this->IsConnectedSock() && !tcp2rtu)
		{
			return this->ForceRegsTCP(adr, strLen/2, (unsigned short*)strBuff);
		}
		else
		{
			return this->ForceRegsRTU(dev, adr, strLen/2, (unsigned short*)strBuff);
		}
		return false;
	}
};
/***********************************************************************************************/

